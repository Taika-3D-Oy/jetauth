# JetAuth

JetAuth (formerly Lattice-ID) is a WebAssembly-native, NATS-powered OpenID Connect (OIDC) & OAuth 2.0 Identity Provider built for wasmCloud and modern cloud-native environments.

Runs as a single wasmCloud WorkloadDeployment with [jetcache](https://github.com/Taika-3D-Oy/jetcache) (formerly lattice-db) co-located as a service — no extra database, no external daemon dependencies. Components communicate with jetcache over localhost TCP (`127.0.0.1:4080`), and jetcache persists and replicates all state directly into NATS JetStream KV.

## Status

**v2.0.0-rc.1** (Rebranded from `lattice-id` v1.13.0)

- **Storage Layer & `jetcache` 2.0 Integration**:
  - High-performance native prefix scan operations (`kv_prefix` and `kv_prefix_keys`), eliminating N+1 round-trip latency on user listings, client listings, tenant memberships, consents, hooks, and audit logs.
  - Cascading instance and TCP port discovery (`JETAUTH_*` -> `JETCACHE_*` -> `CACHE_*` -> `LDB_*`).
  - Seamless backward compatibility with legacy `lattice-db` backends via automatic protocol fallbacks.
- **Component Model & Architecture**:
  - Aligned with the **`nats-wasip3` 1.0.0** and **`jetcache` 2.0** ecosystem.
  - Fully cleaned up WIT interfaces and manifests, removing unused messaging interfaces while maintaining 100% ABI stability for `lattice-id:*` component bindings.
- **Full OIDC Core 1.0 & OAuth 2.0 Conformance**:
  - Strict scope-based PII gating (`email`, `profile`), open-redirect prevention, and session ID (`sid`) backchannel logout tracking.
- **Advanced OAuth 2.0 Security Profiles**:
  - **RFC 9126 Pushed Authorization Requests (PAR)** (`/connect/par`, `/oauth/par`, `/as/par`) with 90s single-use `request_uri` and client enforcement policy
  - **RFC 9449 Demonstrating Proof-of-Possession (DPoP)** sender-constrained access tokens (`cnf: { jkt }`) and proof validation on token and resource (`/userinfo`) endpoints
  - **RFC 7523 `private_key_jwt`** asymmetric client authentication (RS256, ES256) across all token, PAR, revocation, and introspection endpoints
  - **RFC 7638 JWK Thumbprint** computation for public key binding
  - **RFC 7591 / RFC 7592 Dynamic Client Registration & Management** with configurable policy (`disabled`, `protected`, `open`) and Registration Access Tokens
  - **RFC 9207 Issuer Identifier in Authorization Response** (`iss`)
  - **RFC 8414 OAuth 2.0 Authorization Server Metadata** (`/.well-known/oauth-authorization-server`)
  - **RFC 7009 Token Revocation** with authenticated client ownership verification
- **Security & Access**:
  - Passkeys (WebAuthn / FIDO2) for passwordless authentication
  - TOTP MFA with recovery codes, brute-force protection, account lockout
  - SSR Maud + HTMX Admin Panel embedded directly at `/admin`
  - Dynamic theming engine with 6 built-in presets: [THEMING.md](THEMING.md)
  - GDPR export (`GET /api/users/:id/export`) and erasure (`DELETE /api/users/:id`)
  - Multi-region routing and replication: [MULTI_REGION.md](MULTI_REGION.md)

## Workspace Layout

- `oidc-gateway`: HTTP OIDC surface, management API, rate limiting, key management, region routing, and server-side rendered (SSR) Maud + HTMX admin panel
- `password-hasher`: Argon2id worker (SIMD-accelerated, imported via WIT)
- `email-worker`: email delivery (log for dev, AWS SES for production, imported via WIT)

## Prerequisites

- Rust stable (≥ 1.85) with `wasm32-wasip2` target
- Runtime: [wasmCloud](https://wasmcloud.com) ≥ 2.7.0, or [Wasmtime](https://wasmtime.dev) ≥ 47
- `wash` (stock upstream wasmCloud CLI)
- `kind`, `kubectl`, `helm` for local Kubernetes clusters
- `docker` for the local OCI registry
- `curl` and `python3` for integration tests
- Access to [jetcache](https://github.com/Taika-3D-Oy/jetcache) OCI images on GHCR (default: `ghcr.io/taika-3d-oy/jetcache/storage-service:v2.0.0-rc.1`)

```bash
rustup target add wasm32-wasip2
```

## Deployment

JetAuth runs as a single wasmCloud `WorkloadDeployment` with `jetcache` co-located as a sidecar service.

Declarative deployment manifests are provided in [`deploy/`](deploy/README.md):

```bash
# Substitute configuration and apply to your wasmCloud cluster
sed -e 's|__ISSUER_URL__|http://localhost:8000|' \
    -e 's|__HOST__|localhost|' \
    -e 's|__NATS_DATA_URL__|nats:4222|' \
    -e 's|__EMAIL_PROVIDER__|log|' \
    deploy/workloaddeployment-ghcr.yaml | kubectl apply -f -
```

See [deploy/README.md](deploy/README.md) for details on multi-region, staging, and local development configurations.

## Bootstrap Behavior

The `deploy/workloaddeployment-local.yaml` manifest includes a `bootstrap_hook`
that promotes the first registered user to superadmin automatically.

When the bootstrap hook promotes a superadmin (`set_superadmin(true)`), the
gateway also creates the built-in `lid-admin` OAuth client so the admin UI is
immediately usable without any manual client registration.

To restrict bootstrap to a specific email, edit the inline Rhai hook:

```yaml
bootstrap_hook: |
  if user.email == "you@example.com" {
    set_superadmin(true);
    log("Bootstrap: promoted " + user.email);
  }
```

## Build And Check

```bash
cargo build --workspace --target wasm32-wasip2
cargo test --workspace
```

## Integration Tests

Integration tests run against a live Kind cluster. The test runner resets the
cluster state (NATS data + lattice-db) before each test to ensure a clean slate.

### Run all tests

```bash
bash tests/run_cluster_tests.sh
```

### Run a single test

```bash
bash tests/run_cluster_tests.sh authority    # filter by name
```

### Skip reset (use existing state)

```bash
bash tests/run_cluster_tests.sh --no-reset
```

### Test coverage

| Script | Coverage |
|--------|----------|
| `integration_authority` | auth code flow, refresh, introspection, claims, replay detection |
| `integration_protocol` | invalid tokens, malformed JWTs, missing PKCE, unregistered redirect_uri, wrong code_verifier |
| `integration_hooks` | Rhai hook CRUD, dry-run, set_superadmin, set_claim |
| `integration_mfa` | TOTP setup, verification, recovery codes |
| `integration_isolation` | tenant isolation and role boundaries |
| `integration_rate_limit` | brute-force protection and lockout |
| `integration_hardening` | error handling, refresh token rotation, absolute lifetime cap |
| `integration_restart` | workload restart resilience and state recovery |
| `integration_new_features` | client_credentials, device flow, ES256 signing, `/version` |
| `integration_account` | CSRF protection, consent screen (allow/deny/state), first_party flag, GDPR export+delete |
| `integration_logout` | RP-initiated logout, open-redirect protection, prompt=none/login/consent, /healthz, /readyz |
| `integration_backchannel` | backchannel logout_token delivery and validation (RFC 8613) |
| `integration_social_mock` | Google OIDC social login with mock IdP |
| `integration_two_region` | cross-region user lookup, redirect, tenant/client replication |

## Features

**OIDC / OAuth2**
- Authorization Code flow with PKCE (S256)
- Client Credentials grant (confidential clients)
- Device Authorization grant (RFC 8628)
- Refresh token rotation with replay detection and 90-day absolute lifetime cap
- Backchannel Logout (RFC 8613) with signed `logout_token`
- RP-Initiated Logout (OIDC RP-Initiated Logout 1.0) with open-redirect protection
- `prompt=none/login/consent`, `max_age`, `id_token_hint`, `login_hint`, `claims` parameter
- RS256 and per-client ES256 ID token signing
- Token introspection (RFC 7662)

**Security**
- CSRF tokens on all account self-service mutations
- Consent screen for third-party clients (`first_party` flag to opt out)
- Account lockout after configurable failure threshold
- IP-based rate limiting via abuse-protection component
- Refresh token absolute lifetime cap (configurable, default 90 days)
- PKCE enforced for all public clients

**Identity & Access**
- Passkeys (WebAuthn) for passwordless authentication
- TOTP-based MFA with recovery codes
- Google OIDC social login (generic OIDC federation supported)
- Self-service account management (password change, email update, passkey enrollment)
- Email verification and invitation flows
- Multi-tenant with per-membership roles (`tenant_id`, `role` claims)

**Operations**
- GDPR: data export (`GET /api/users/:id/export`) and erasure (`DELETE /api/users/:id`)
- Audit log entries in a dedicated KV bucket
- Rhai scripting hooks for custom authorization logic and claim injection
- `/healthz` (liveness) and `/readyz` (readiness with KV + key checks)
- Prometheus-format metrics at `/metrics`
- Embedded admin UI served at `/admin`
- Multi-region deployment with cross-region user routing
- Configurable lattice-db instance isolation (`ldb_instance` config, matches `LDB_INSTANCE` on the storage-service)
- Session consistency tokens (lattice-db 1.6.0) — read-your-write guarantees across replicas via `x-lid-consistency` header and `__lid_cr` HttpOnly cookie
- AWS SES email delivery for production, log provider for development

## Important Docs

- [INTEGRATION.md](INTEGRATION.md): integrating an application with Lattice-ID
- [K8S_DEV.md](K8S_DEV.md): Kubernetes-based development flow, email delivery configuration
- [MULTI_REGION.md](MULTI_REGION.md): two-region architecture and deployment notes

## License

Apache-2.0
