# Multi-Region Architecture

## Overview

Lattice-ID runs in two (or more) regions. Each region has its own wasmCloud
cluster, NATS control-plane, and a region-local `nats-data` pod that stores
JetStream KV data locally. There is no shared NATS infrastructure between
regions — no bridge, no leaf nodes, no federation. Each region's NATS is
completely isolated.

Users are bound to a single region for data residency (GDPR / HIPAA).
When a user hits the wrong region, the system discovers the correct one
and redirects the browser with all OIDC parameters preserved.

Tenants and OIDC clients are org-level configuration (no PII) and are
replicated to all regions via **application-level HTTP sync** so that any
region can validate tokens and enforce tenant policies. There is no
NATS-level KV mirroring or JetStream replication between regions.

## Data Model

### Region-Local KV Buckets (prefixed, NOT replicated)

Each region stores user data in buckets prefixed by `kv_prefix` (e.g. `eu-`, `us-`).
The actual bucket names on JetStream are `ldb-{prefix}-{suffix}`.

| Bucket suffix | Contents | Why local |
|---------------|----------|-----------|
| `users` | Email, name, password hash, TOTP secrets, recovery codes | PII / PHI |
| `sessions` | Auth codes, refresh tokens, consumed markers, MFA state | Tied to user identity |
| `audit` | Audit events with actor_id, target_id, details | References user IDs |
| `user-idx` | email → user_id mapping | PII (email in key) |
| `memberships` | user_id ↔ tenant_id links | Links users to orgs |
| `keys` | RSA signing key pairs (per-region) | Each region is its own OIDC issuer |
| `abuse-rate-limits` | Rate limit windows | Per-region tracking |

### Shared KV Buckets (replicated via HTTP sync)

These use a fixed bucket name (no region prefix) configured via
`tenant_bucket` and `client_bucket` in wasi:config/store.

| Bucket | Contents | Why safe to replicate | Sync mechanism |
|--------|----------|-----------------------|----------------|
| `lid-tenants` | Org name, status, display name | No PII — org metadata only | HTTP POST `/internal/replicate` |
| `lid-clients` | OIDC client_id, redirect_uris, grant_types, name | No PII — app config only. `client_secret` stripped before sync | HTTP POST `/internal/replicate` |

### Cross-Region HTTP Endpoints

| Endpoint | Method | Request | Response | PII? |
|----------|--------|---------|----------|------|
| `/internal/lookup` | GET | `?hash=sha256(email)` | `{ found, region }` | No — pseudonymized hash only |
| `/internal/config` | GET | — | `{ clients, tenants }` | No — org/app config only |
| `/internal/replicate` | POST | `{ op, kind, id, data }` | `{ ok: true }` | No — tenant/client metadata only |

All `/internal/*` requests require a matching `X-Internal-Auth` header.
Regions share that secret via `internal_auth_secret` in `wasi:config/store`.

## Infrastructure Topology

### Local Development (two Kind clusters)

```
   Host machine
   ├── localhost:8000 ──► lattice-id-eu Kind cluster (NodePort)
   └── localhost:8001 ──► lattice-id-us Kind cluster (NodePort)

   ┌─────────────────────────────┐       ┌─────────────────────────────┐
   │  lattice-id-eu (Kind)       │       │  lattice-id-us (Kind)       │
   │                             │       │                             │
   │  ┌───────────────────────┐  │ HTTP  │  ┌───────────────────────┐  │
   │  │  wasmcloud host       │  │/inter-│  │  wasmcloud host       │  │
   │  │  ├─ oidc-gateway     ─┼──┼─nal/──┼──┤─ oidc-gateway        │  │
   │  │  ├─ password-hasher   │  │lookup +│  │  ├─ password-hasher   │  │
   │  │  ├─ email-worker      │  │repli- │  │  ├─ email-worker      │  │
   │  │  ├─ abuse-protection  │  │cate   │  │  ├─ abuse-protection  │  │
   │  │  ├─ key-manager       │  │       │  │  ├─ key-manager       │  │
   │  │  ├─ region-authority  │  │       │  │  ├─ region-authority  │  │
   │  │  └─ lattice-db        │  │       │  │  └─ lattice-db        │  │
   │  └───────────────────────┘  │       │  └───────────────────────┘  │
   │                             │       │                             │
   │  ┌──────────┐               │       │  ┌──────────┐               │
   │  │nats-data │               │       │  │nats-data │               │
   │  │ (local)  │               │       │  │ (local)  │               │
   │  └──────────┘               │       │  └──────────┘               │
   │                             │       │                             │
   │  ┌──────────────┐           │       │  ┌──────────────┐           │
   │  │gateway-       │           │       │  │gateway-       │           │
   │  │internal:80    │           │       │  │internal:80    │           │
   │  └──────────────┘           │       │  └──────────────┘           │
   └─────────────────────────────┘       └─────────────────────────────┘

   No NATS bridge, no leaf nodes — regions are fully independent.
   Cross-region traffic is HTTP only (via gateway-internal on port 80).
```

**Key networking details:**
- Cross-region HTTP uses `gateway-internal` NodePort services on port 80
  (the HTTP default, so Host headers omit the port).
- `region_internal_urls` config: `{"eu":"http://eu.lid.internal","us":"http://us.lid.internal"}`
- `region_domains` config (for browser redirects): `{"eu":"http://eu.lid.internal:8000","us":"http://us.lid.internal:8001"}`
- WASI HTTP forbids explicit `Host` headers — the runtime derives Host from
  the URL authority, so port-80 URLs produce the correct bare-hostname Host.
- Each region's `nats-data` pod runs standalone NATS with local JetStream.
  No leaf nodes, no federation, no shared NATS infrastructure between regions.

### Production (separate NATS clusters)

```
                      auth.example.com
                      (Route53 / CloudFront geolocation)
                     ┌──────────┴──────────┐
                     ▼                      ▼
          eu.auth.example.com       us.auth.example.com
          (ALB / Ingress)           (ALB / Ingress)
          ┌──────┬──────┐           ┌──────┐
          ▼      ▼      ▼           ▼      ▼
     oidc-gw  oidc-gw  oidc-gw  oidc-gw  oidc-gw
     (FRA-1)  (FRA-2)  (AMS-1)  (IAD-1)  (IAD-2)
          │      │      │           │      │
          └──────┼──────┘           └──────┘
                 │                          │
          ┌──────┘                          └──────┐
          ▼                                        ▼
    NATS Cluster (EU)     HTTP /internal/   NATS Cluster (US)
    ┌─────────────────┐   replicate        ┌─────────────────┐
    │ eu-users     ✗  │ ◄────────────────► │ us-users     ✗  │
    │ eu-sessions  ✗  │   /internal/       │ us-sessions  ✗  │
    │ eu-audit     ✗  │   lookup           │ us-audit     ✗  │
    │ eu-user-idx  ✗  │                    │ us-user-idx  ✗  │
    │ eu-members   ✗  │                    │ us-members   ✗  │
    │ eu-keys      ✗  │                    │ us-keys      ✗  │
    │                 │                    │                 │
    │ lid-tenants  ⟷  │  ← HTTP sync →    │ lid-tenants  ⟷  │
    │ lid-clients  ⟷  │                    │ lid-clients  ⟷  │
    └─────────────────┘                    └─────────────────┘

    ✗ = region-local only (prefixed by kv_prefix)
    ⟷ = synced via HTTP /internal/replicate
```

## Component Roles

### oidc-gateway (stateless, N replicas per workload)

- Full OIDC authority: /authorize, /login, /token, /userinfo, /register, /api/*
- Signs JWTs locally (loads keys from key-manager component via WIT)
- Uses revision-based CAS (lattice-db) for auth code consumption and refresh token rotation
- On login miss: queries region-authority (local NATS KV) then remote regions via HTTP `/internal/lookup`
- On lookup hit: 302 redirects the browser to the correct region's /authorize endpoint
- Exposes `/internal/lookup`, `/internal/config`, and `/internal/replicate`
- After tenant/client mutations: fires HTTP POST `/internal/replicate` to all other regions
- Requires `internal_auth_secret` on all cross-region `/internal/*` requests

### lattice-db (storage component, co-deployed per workload)

- WIT component bundled within the workload (no separate WorkloadDeployment)
- Provides KV with CAS semantics to co-located components
- Backed by NATS JetStream KV (one bucket per table)
- Connects directly to the region's `nats-data` service; no NATS req/reply broker

### region-authority (stateless WIT component)

- Checks local `lid-user-idx` NATS KV for email hash existence
- Uses `lid-authority-cache` (in-memory) as read-through cache
- Called by oidc-gateway before HTTP fallback to remote regions
- No PII in request or response

### email-worker (1 per workload)

- Receives email send requests via `lattice-id:notify/email` WIT interface
- Delivers via HTTP API or logs (dev mode)
- Region-local only — email addresses never leave the region

### password-hasher (1 per workload)

- Argon2id hashing via `lattice-id:crypto/password` WIT interface
- Stateless computation, region-local

## Cross-Region Login Flow

```
1. User (EU citizen in US) visits https://auth.example.com/authorize?...
2. Route53 geo-routes to us.auth.example.com
3. US oidc-gateway shows login page
4. User submits: email=alice@corp.fi, password=***
5. US oidc-gateway: store::get_user_by_email("alice@corp.fi") → None
6. US oidc-gateway: service_client::lookup_region(sha256("alice@corp.fi"))
7. US gateway: calls region-authority (local NATS KV) → miss
8. US gateway: HTTP GET to EU /internal/lookup?hash=abc...
9. EU gateway: checks lid-user-idx → found
10. EU gateway: replies { found: true, region: "eu" }
11. US oidc-gateway: builds redirect URL preserving all OIDC params
    302 → https://eu.auth.example.com/authorize?client_id=X&...&login_hint=alice@corp.fi
12. Browser follows redirect to EU
13. EU oidc-gateway shows login page (email pre-filled from login_hint)
14. User enters password → EU authenticates → auth code → redirect to app
```

## Tenant/Client Replication Flow

When a superadmin creates, updates, or deletes a tenant or client via the
management API, the originating region pushes the change to all other
regions via HTTP:

```
1. Admin calls POST /api/tenants on EU
2. EU oidc-gateway: store::create_tenant() writes to lid-tenants KV
3. EU oidc-gateway: service_client::replicate_to_regions("put", "tenant", id, data)
4. For each region in region_internal_urls (excluding self):
   a. HTTP POST http://us.lid.internal/internal/replicate
      Body: { "op": "put", "kind": "tenant", "id": "abc", "data": {...} }
      Header: X-Internal-Auth: <shared secret>
5. US oidc-gateway: handle_internal_replicate() → kv_set to lid-tenants
6. Tenant is now available in both regions
```

**Security constraints on replication:**
- `client_secret` is stripped before replication (each region auto-generates its own)
- Only tenant/client metadata crosses regions — never user data
- Replication is fire-and-forget with logging (does not block the API response)
- The receiving endpoint does NOT trigger further replication (no infinite loops)

## Key Rotation with CAS

```
key-manager handles key rotation via CAS:
1. get_revision("lid-keys", "signing_keys") → (exported_keys, revision)
2. Import keys from KV
3. If current key age >= 24h:
   a. Generate new RSA-2048 key pair
   b. Retire old key (48h grace period for verification)
   c. Export new key store
   d. swap("lid-keys", "signing_keys", new_export, revision)
   e. If swap fails → another instance rotated first → go to step 1
   f. If swap succeeds → log rotation, continue
4. If no rotation needed → use current keys from KV
```

Each region generates independent signing keys. Tokens always carry the
issuer URL of the region that created them, so resource servers fetch JWKS
from the correct region. No key replication is needed.

## Configuration Reference

| Key | Example | Purpose |
|-----|---------|---------|
| `region_id` | `"eu"` | Identifies this region (used to skip self in replication) |
| `kv_prefix` | `"eu"` | Prefixes all region-local KV buckets: `eu-users`, `eu-sessions`, etc. |
| `tenant_bucket` | `"lid-tenants"` | Override bucket name for tenants (shared, no prefix) |
| `client_bucket` | `"lid-clients"` | Override bucket name for clients (shared, no prefix) |
| `region_domains` | `'{"eu":"http://eu.lid.internal:8000",...}'` | Public-facing URLs for browser redirects |
| `region_internal_urls` | `'{"eu":"http://eu.lid.internal",...}'` | Internal HTTP URLs for `/internal/*` endpoints |
| `internal_auth_secret` | `"local-two-region-dev-secret"` | Shared secret for authenticating `/internal/*` requests |
| `issuer_url` | `"http://eu.lid.internal:8000"` | OIDC issuer for this region (appears in JWT `iss` claim) |
| `bootstrap_hook` | `set_superadmin(true);` | Script that runs for the first registered user |

## Implementation Summary

| # | Component | What | File(s) |
|---|-----------|------|---------|
| 1 | oidc-gateway | `/internal/lookup` endpoint (email hash check) | `oidc-gateway/src/lib.rs` |
| 2 | oidc-gateway | `/internal/config` endpoint (export clients + tenants) | `oidc-gateway/src/lib.rs` |
| 3 | oidc-gateway | `/internal/replicate` endpoint (receive tenant/client sync) | `oidc-gateway/src/lib.rs` |
| 4 | oidc-gateway | `replicate_to_regions()` — push sync to other regions | `oidc-gateway/src/service_client.rs` |
| 5 | oidc-gateway | `post_json()` — HTTP POST with JSON body for replication | `oidc-gateway/src/http_client.rs` |
| 6 | oidc-gateway | `lookup_region()` with 2-tier lookup (authority → HTTP) | `oidc-gateway/src/service_client.rs` |
| 7 | oidc-gateway | Cross-region redirect on login miss | `oidc-gateway/src/login.rs` |
| 8 | oidc-gateway | Replication calls after create/delete tenant, create client | `oidc-gateway/src/management.rs` |
| 9 | region-authority | Local NATS KV lookup with in-memory cache | `region-authority/src/lib.rs` |
| 10 | key-manager | Per-region RSA key generation + CAS rotation | `key-manager/src/lib.rs` |
| 11 | Config | Region config values in wasi:config/store | `deploy/workloaddeployment-{eu,us}.yaml` |
| 12 | Infrastructure | Region manifests | `deploy/workloaddeployment-{eu,us}.yaml` |

## Compliance Assessment

### GDPR

- **Data residency**: All PII stays in the originating region's JetStream
  KV (prefixed by `kv_prefix`, stored on the region's local `nats-data` pod).
  User records, sessions, audit logs, and email indexes never cross region
  boundaries. There is no NATS federation, leaf node, or shared NATS
  infrastructure between regions — each region's NATS is completely isolated.
- **Cross-region lookup**: Uses `sha256(email)`, a one-way hash. No raw email, name,
  or other PII crosses regions. The response contains only a boolean and
  a region identifier.
- **Tenant/client replication**: Only org metadata (name, display_name, status) and
  OIDC client config (client_id, redirect_uris, grant_types) are replicated
  via HTTP. `client_secret` is stripped before transmission. No PII in
  replicated data.
- **Right to erasure**: Delete user from region-local KV. Hashed cache entries in
  other regions expire via TTL (1 hour). No PII in shared buckets.
- **JWTs**: Contain email and name per OIDC spec. These are issued to the user's
  browser and never stored in cross-region KV.
- **Email messages**: Sent via `lattice-id:notify/email` WIT interface to the
  region-local email-worker. Email addresses do not cross regions.

### HIPAA

- **PHI isolation**: If user records contain health-related data, it remains in
  the region-local KV on the region's `nats-data` pod behind access controls.
- **Audit trail**: Region-local audit logs capture all access events.
- **Signing keys**: Per-region, never leave the originating region's JetStream.

### Known Gaps (must fix before production)

1. **Intra-cluster NATS traffic unencrypted**: NATS traffic within each
   Kind cluster (between the wasmCloud host and nats-data) uses
   plain text. Production requires TLS.

2. **No retry for HTTP replication**: Tenant/client sync is fire-and-forget.
   If a region is temporarily down, it misses the update. Need a retry queue
   or periodic reconciliation.

3. **Cross-region HTTP unencrypted**: The `/internal/*` endpoints use plain
   HTTP. Production requires TLS (HTTPS) between regions.

### Future Security Hardening

- Remove raw email from audit log `details` field (use user_id only)
- Encrypt TOTP secrets and recovery codes at rest
- Add audit log retention/rotation policy
- Consider removing email/name from access_token (keep in id_token only)
- NATS TLS mandatory within each cluster
- HTTPS for cross-region `/internal/*` endpoints
- Add retry/reconciliation for HTTP replication failures

## Local Development Setup

### Prerequisites

- Kubernetes clusters for target regions (or distinct namespaces)
- wasmCloud operator installed in each region
- Independent NATS JetStream instances in each region
- `/etc/hosts` or DNS entries for regional endpoints (e.g. `eu.lid.internal`, `us.lid.internal`)

### Deploy Workloads

Apply the region manifests to their respective clusters or namespaces:

```bash
# EU Region
kubectl apply -f deploy/workloaddeployment-eu.yaml

# US Region
kubectl apply -f deploy/workloaddeployment-us.yaml
```

### Clean Reset (clear all data)

JetStream KV data is stored locally on each region's `nats-data` pod
(in `/tmp/nats/jetstream`). To get a fully clean state:

```bash
# 1. Delete workloads
kubectl -n eu delete workloaddeployment jetauth-eu
kubectl -n us delete workloaddeployment jetauth-us

# 2. Restart nats-data pods (clears /tmp JetStream data)
kubectl -n eu rollout restart deploy/nats-data
kubectl -n us rollout restart deploy/nats-data

# 3. Restart wasmCloud hosts (re-establishes NATS subscriptions)
kubectl -n eu rollout restart deploy/hostgroup-default
kubectl -n us rollout restart deploy/hostgroup-default

# 4. Redeploy workloads
kubectl apply -f deploy/workloaddeployment-eu.yaml
kubectl apply -f deploy/workloaddeployment-us.yaml
```

### Run Integration Tests

```bash
EU_URL=http://localhost:8000 US_URL=http://localhost:8001 \
  EU_HOST=eu.lid.internal US_HOST=us.lid.internal \
  bash tests/integration_two_region.sh
```

Tests cover (20 assertions):
1. OIDC discovery in both regions (independent issuers)
2. JWKS available with independent per-region signing keys
3. User registration in EU
4. Full OIDC login flow in EU (register → authorize → login → token)
5. Cross-region redirect: EU user login attempted from US → 302 to EU with all OIDC params preserved
6. Independent user registration and login in US
7. Data residency: management API accessible per-region
8. Token isolation: EU token rejected by US /userinfo (different signing keys)
9. Tenant sync: tenant created in EU visible in US via HTTP replication
10. Client sync: client created in EU visible in US via HTTP replication
11. User store isolation: EU user not visible in US (per-region kv_prefix)

## Scaling

- **Within a region**: Add workloads (each = N gateways + satellites; lattice-db is co-deployed within each workload).
  All workloads share the same regional NATS KV. CAS prevents conflicts.
- **Across regions**: Deploy independent NATS clusters. Configure
  `region_internal_urls` with each region's HTTP endpoint and configure the
  same `internal_auth_secret` in every region.
- **Tenant/client sync**: The originating region pushes changes via HTTP POST
  to `/internal/replicate` on all other regions. Fire-and-forget with logging.
  Pure application-level HTTP — no NATS federation or JetStream replication.
- **Rate limiting**: Per abuse-protection component instance (approximate). Acceptable for
  abuse prevention. Can move to KV-based `bucket.increment()` later for
  global accuracy.
