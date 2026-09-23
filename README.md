# Lattice-ID

Lattice-ID is a NATS-native OIDC provider for wasmCloud, backed by JetStream KV.

Runs as a single wasmCloud WorkloadDeployment with [lattice-db](https://github.com/Taika-3D-Oy/lattice-db) co-located as a service — no extra database, no separate infrastructure. Components communicate with lattice-db over localhost TCP (`127.0.0.1:4080`), and lattice-db persists all state to NATS JetStream KV.

## Status

**v1.13.0**

- Full OIDC Core 1.0 & OAuth 2.0 conformance and compliance hardening (scope-based PII gating, strict open-redirect & PAR validation, session ID `sid` tracking for back-channel logout)
- Advanced OAuth 2.0 Security Profiles:
  - **RFC 9126 Pushed Authorization Requests (PAR)** (`/connect/par`, `/oauth/par`, `/as/par`) with 90s single-use `request_uri` and client enforcement policy
  - **RFC 9449 Demonstrating Proof-of-Possession (DPoP)** sender-constrained access tokens (`cnf: { jkt }`) and proof validation on token and resource (`/userinfo`) endpoints
  - **RFC 7523 `private_key_jwt`** asymmetric client authentication (RS256, ES256) across all token, PAR, revocation, and introspection endpoints
  - **RFC 7638 JWK Thumbprint** computation for public key binding
  - **RFC 7591 / RFC 7592 Dynamic Client Registration & Management** with configurable policy (`disabled`, `protected`, `open`) and Registration Access Tokens
  - **RFC 9207 Issuer Identifier in Authorization Response** (`iss`)
  - **RFC 8414 OAuth 2.0 Authorization Server Metadata** (`/.well-known/oauth-authorization-server`)
  - **RFC 7009 Token Revocation** with authenticated client ownership verification
- Security hardening: CSRF protection, refresh token absolute lifetime cap, account lockout, rate limiting, consent screen
- Dedicated RP-initiated logout (`post_logout_redirect_uris`) and Backchannel logout (RFC 8613)
- Built-in Server-Side Rendered (SSR) Maud + HTMX Admin Panel embedded directly in `oidc-gateway` at `/admin`
- Dynamic theming engine with 6 trendy built-in presets (`taika-dark`, `taika-light`, `glassmorphic`, `cyberpunk`, `minimal-noir`, `neo-brutalist`) and complete white-labeling: [THEMING.md](THEMING.md)
- GDPR: user data export (`GET /api/users/:id/export`) and erasure (`DELETE /api/users/:id`)
- Multi-region design: [MULTI_REGION.md](MULTI_REGION.md)
- WASI 0.3 / wasmCloud ≥ 2.7.0 Component Model async I/O compatibility (`wasip3 0.7`, `wit-bindgen 0.57`)

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
- Access to [lattice-db](https://github.com/Taika-3D-Oy/lattice-db) OCI images on GHCR (default: `ghcr.io/taika-3d-oy/lattice-db/storage-service:latest`)

```bash
rustup target add wasm32-wasip2
```

## Local Development

Lattice-ID requires lattice-db for persistent storage, which means it runs on
a Kind cluster with the wasmCloud operator — not standalone via `wash dev`.

### Deploy a local cluster

```bash
bash deploy/deploy-local.sh
```

This script:

- Creates a Kind cluster with a local OCI registry
- Installs the wasmCloud operator via Helm
- Deploys a standalone NATS JetStream data-plane (`nats-data`)
- Builds and pushes lattice-id wasm components (mirrors lattice-db from GHCR)
- Deploys a single WorkloadDeployment with lattice-db co-located as a service
- Exposes the HTTP gateway on `http://localhost`

Other commands:

```bash
bash deploy/deploy-local.sh rebuild   # rebuild + redeploy components
bash deploy/deploy-local.sh teardown  # destroy the cluster
bash deploy/deploy-local.sh status    # show cluster status
```

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
