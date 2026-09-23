# Kubernetes Development Guide

Learnings, setup steps, and workflow recommendations from bringing Lattice-ID up on a local Kind cluster with the wasmCloud v2 operator.

## Learnings

### NATS JetStream KV key constraints

NATS KV keys only accept: `A-Za-z0-9`, `_`, `-`, `/`, `=`, `.` (dot valid in middle only).
Characters like `:`, `@`, `~`, `+`, `#`, and spaces are all **invalid** and produce a confusing error:

```
JetStream error: key cannot be empty or start/end with '.'
```

The error message is misleading — it fires for *any* invalid character, not just dots. We resolve this with `sanitize_key()` in `oidc-gateway/src/store.rs`:

- `:` → `/`
- `@` → `_at_`

This means `email:admin@test.local` becomes `email/admin_at_test.local`.

Any code that iterates keys via `kv_list_keys` and matches with `starts_with` must use the *sanitized* prefix (e.g. `"user/"` not `"user:"`).

### OCI cache on wasmCloud host pods

Host pods cache pulled images at `/oci-cache/` and use `IfNotPresent` policy. Pushing a new binary with the same `:dev` tag does **not** automatically invalidate the cache. You must manually clear it:

```bash
for pod in $(kubectl get pods -l wasmcloud.com/hostgroup=default -o name); do
  kubectl exec $pod -- sh -c 'rm -rf /oci-cache/kind-registry_5000_*'
done
```

### Binary filenames: hyphens vs underscores

Cargo produces binary names that **match the package name** from `Cargo.toml`, using hyphens:

- Package `oidc-gateway` → `oidc_gateway.wasm` (cdylib, Cargo converts hyphens to underscores for libs)
- Package `password-hasher` → `password_hasher.wasm` (cdylib)

Pushing the wrong filename (e.g. a stale 13KB artifact) produces a cryptic "Service must export a single interface with the 'run' function" error.

### Data layer: lattice-db

All persistent state is stored via [lattice-db](https://github.com/Taika-3D-Oy/lattice-db), which runs as a co-located service inside the same WorkloadDeployment. Components talk to lattice-db over localhost TCP (`127.0.0.1:4080`). lattice-db persists data to NATS JetStream KV.

### KV bucket naming

Buckets are created by lattice-db on first access. Table names correspond to KV bucket names: `lid-users`, `lid-user-idx`, `lid-sessions`, `lid-clients`, `lid-tenants`, `lid-memberships`, `lid-audit`, `lid-keys`, `lid-abuse-rate-limits`, `lid-vault`. The `lid-` prefix comes from `LDB_INSTANCE=lid` set on the storage-service deployment.

### Service components and wasi:cli/run

Components compile for `wasm32-wasip2` using `wasip3` and `wit-bindgen`. You do **not** need to declare `export wasi:cli/run` in `world.wit` — doing so causes conflicts.

---

## Local K8s Setup (from scratch)

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | stable (≥ 1.85) | `rustup target add wasm32-wasip2` |
| wash | stock upstream | `cargo install wash-cli` |
| Kind | 0.31+ | `brew install kind` |
| kubectl | 1.30+ | `brew install kubectl` |
| Helm | 3.x | `brew install helm` |

### 1. Create Kind cluster with local OCI registry

```bash
# Create registry container
docker run -d --restart=always -p 5001:5000 --network bridge --name kind-registry registry:2

# Create cluster
kind create cluster --name wasmcloud --config deploy/kind-config.yaml

# Connect registry to kind network
docker network connect kind kind-registry 2>/dev/null || true

# Create in-cluster DNS for the registry
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: kind-registry
spec:
  type: ClusterIP
  ports:
    - port: 5000
      targetPort: 5000
---
apiVersion: v1
kind: Endpoints
metadata:
  name: kind-registry
subsets:
  - addresses:
      - ip: $(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' kind-registry)
    ports:
      - port: 5000
EOF
```

### 2. Install wasmCloud operator

The deploy script handles this automatically. For manual setup:

```bash
helm install wasmcloud oci://ghcr.io/wasmcloud/charts/runtime-operator \
  --version 2.0.1 \
  --set 'hostConfig.allowInsecureRegistries=true'
```

Wait for all pods:

```bash
kubectl get pods -w
```

### 3. Build, deploy, and test

Use the deploy script for the remaining steps (NATS data-plane, lattice-db,
lattice-id, host patching):

```bash
bash deploy/deploy-local.sh
```

Or for a rebuild cycle after code changes:

```bash
bash deploy/deploy-local.sh rebuild
```

### Redeploy after code changes

```bash
bash deploy/deploy-local.sh rebuild
```

This rebuilds all wasm components, pushes them to the local registry, clears
the OCI cache on host pods, and redeploys the workload.

For manual redeployment (e.g. single component), the steps are:

```bash
# 1. Build
cargo build --workspace --target wasm32-wasip2 --release

# 2. Push changed component(s)
wash oci push --insecure localhost:5001/lattice-id/oidc-gateway:dev \
  target/wasm32-wasip2/release/oidc_gateway.wasm

# 3. Clear OCI cache on host pods
for pod in $(kubectl get pods -l wasmcloud.com/hostgroup=default -o name); do
  kubectl exec $pod -- sh -c 'rm -rf /oci-cache/kind-registry_5000_lattice-id_*'
done

# 4. Bounce the workload
kubectl delete workloaddeployment lattice-id
kubectl apply -f deploy/workloaddeployment-local.yaml
```

---

## Development Workflows

### Automated setup (recommended)

The `deploy/deploy-local.sh` script handles the full setup from scratch:

```bash
bash deploy/deploy-local.sh            # full setup
bash deploy/deploy-local.sh rebuild    # rebuild + redeploy components
bash deploy/deploy-local.sh teardown   # destroy everything
bash deploy/deploy-local.sh status     # show cluster status
```

This creates a Kind cluster, installs the wasmCloud operator, builds all
components, deploys lattice-db and lattice-id, and exposes the HTTP gateway
on `http://localhost:8000`.

### Running integration tests

After the cluster is up:

```bash
bash tests/run_cluster_tests.sh              # reset + run all
bash tests/run_cluster_tests.sh authority    # run only matching test(s)
bash tests/run_cluster_tests.sh --no-reset   # skip reset, use existing state
```

The test runner resets the cluster before each test (bounces nats-data +
lattice-db + host, reapplies workloads) so each test gets a clean slate
with a fresh bootstrap.

### Rebuild loop

After code changes:

```bash
bash deploy/deploy-local.sh rebuild
```

This rebuilds all wasm components, pushes to the local registry, clears the
OCI cache on host pods, and redeploys the workload.

---

## Email Delivery Configuration

The `email-worker` component is invoked directly by the gateway via the
`lattice-id:notify/email` WIT interface.  It delivers emails via one of two
providers configured by `email_provider`:

| Provider | Config key | Description |
|----------|-----------|-------------|
| `log` (default) | `email_provider: "log"` | Logs emails to stderr — for local dev |
| `ses` | `email_provider: "ses"` | Sends via AWS SES v2 API with SigV4 signing |

### AWS SES Setup

1. **Verify your sender address** in the AWS SES console:
   - Go to SES → Verified identities → Create identity
   - Verify a domain (recommended) or individual email address
   - If still in SES sandbox, also verify recipient addresses

2. **Create an IAM user** for email sending:
   ```bash
   aws iam create-user --user-name lattice-id-ses
   aws iam put-user-policy --user-name lattice-id-ses \
     --policy-name ses-send \
     --policy-document '{
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Allow",
         "Action": ["ses:SendEmail"],
         "Resource": "*"
       }]
     }'
   aws iam create-access-key --user-name lattice-id-ses
   ```
   Save the `AccessKeyId` and `SecretAccessKey` from the output.

3. **Configure the WorkloadDeployment** manifest — set these in the
   `wasi:config:store` host interface:

   ```yaml
   email_provider: "ses"
   ses_region: "eu-north-1"              # your SES region
   ses_access_key_id: "AKIA..."          # from step 2
   ses_secret_access_key: "..."          # from step 2
   ses_from_address: "noreply@yourdomain.com"  # must be SES-verified
   ```

   For production, store credentials in K8s Secrets and reference via `secretFrom`.

4. **Move out of SES sandbox** (for production):
   - SES Console → Account dashboard → Request production access
   - Until then, you can only send to verified recipient addresses

### Registration & Email Verification Defaults

| Config Key | Default | Effect |
|-----------|---------|--------|
| `require_email_verification` | `"true"` | Users start as "pending", must verify email before login |
| `allow_registration` | not set | Registration closed by default; open during bootstrap (no superadmin exists) |

After bootstrap, the superadmin can open registration via:
```bash
TOKEN="..."  # superadmin access token
curl -X PUT http://localhost:8000/api/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"allow_registration": true}'
```

For local dev (`deploy/workloaddeployment-local.yaml`), both are relaxed:
`require_email_verification: "false"` and `allow_registration: "true"`.
