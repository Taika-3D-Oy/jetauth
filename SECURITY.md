# JetAuth Security Architecture & Defense-in-Depth Model

This document outlines the **3-Tier Defense-in-Depth Security Model** protecting JetAuth (formerly Lattice-ID), its co-located storage layer ([jetcache](https://github.com/Taika-3D-Oy/jetcache), formerly Lattice-DB), and the messaging fabric (NATS JetStream).

---

## Reporting a Vulnerability

If you discover a security vulnerability in JetAuth, please report it privately:

- **GitHub Advisory**: Use [GitHub Private Vulnerability Reporting](https://github.com/Taika-3D-Oy/jetauth/security/advisories/new).
- **Email**: Send details and reproduction steps to `security@taika3d.com`.

Please **do not** open public GitHub issues for security vulnerabilities. We will acknowledge receipt within 48 hours and coordinate responsible disclosure.

---

## 1. High-Level Architecture Overview

Security in JetAuth is enforced across three distinct, complementary layers. No single layer represents a single point of security failure.

```
 ┌─────────────────────────────────────────────────────────────────────────┐
 │ 1. Identity & Application Layer (Lattice-ID / Lattice-DB)               │
 │    • AES-256-GCM Envelope Encryption on sensitive buckets (users, creds)│
 │    • FIDO2 / WebAuthn Passkey (ES256) signature validation & anti-clone │
 │    • PKCE S256 challenge verification (RFC 7636)                        │
 │    • Refresh token family rotation with automated reuse detection       │
 │    • Append-only semantic audit logging (lid-audit)                     │
 └────────────────────────────────────┬────────────────────────────────────┘
                                      │ Mutual TLS 1.3 in transit + Auth
 ┌────────────────────────────────────▼────────────────────────────────────┐
 │ 2. Transport & Access Control Layer (NATS JetStream)                    │
 │    • Subject-level ACLs (strict pub/sub boundaries on lid-* buckets)    │
 │    • Service-account authentication (NKey / JWT / Auth Token / Pass)    │
 │    • Transport-level authorization violation logging & tracing          │
 │    • System event telemetry ($SYS.ACCOUNT.* & JetStream advisories)     │
 └────────────────────────────────────┬────────────────────────────────────┘
                                      │ Disk I/O
 ┌────────────────────────────────────▼────────────────────────────────────┐
 │ 3. Infrastructure & Storage Layer (GKE / GCP Cloud VPC)                 │
 │    • Persistent Volume disk-level encryption at rest (AES-256 / CMEK)   │
 │    • Private VPC pod networking & Kubernetes NetworkPolicy isolation    │
 │    • Master envelope key protection via GCP Cloud KMS / K8s Secrets     │
 └─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Tier 1: Identity & Application Layer

The application layer implements zero-trust identity verification, cryptographic guarantees, and semantic auditing before data is stored or transmitted.

### 2.1 Per-Table AES-256-GCM Envelope Encryption
- **Opt-in Table Encryption**: High-sensitivity tables (`users`, `credentials`, `vault`, `sessions`) are marked with `"encrypted": true` in their schemas.
- **In-Memory Encryption**: Payloads are encrypted in-memory by Lattice-DB before being published to NATS JetStream.
- **Envelope Hierarchy**:
  - **Master Key**: A 256-bit root key injected via environment (`LDB_MASTER_KEY`), Kubernetes Secret, or GCP Cloud KMS.
  - **Key Derivation (HKDF-SHA256)**: Per-record Data Encryption Keys (DEKs) are derived using HKDF with the table name and key ID as domain separation contexts.
  - **Ciphertext Format**: Stored as `[96-bit nonce][ciphertext][128-bit GCM tag]`.
- **Integrity Guarantee**: Any out-of-band tampering or unauthorized mutation of raw NATS records causes AES-GCM authentication verification to fail, preventing corrupted or injected state from being consumed.

### 2.2 FIDO2 / Passkey & PKCE Security
- **WebAuthn Passkeys**: Authenticated via ECDSA over P-256 (`ES256`). Public keys are stored in COSE format, and `sign_count` counters are tracked to detect authenticator cloning.
- **PKCE (Proof Key for Code Exchange)**: Mandatory for all public and single-page application (SPA) authorization flows using `code_challenge_method=S256` (RFC 7636).
- **Password Hashing**: Supported via `Argon2id` (and PBKDF2 fallback) with per-user cryptographic salts and server-side secret pepper.

### 2.3 Token Security, Sender-Constraining & Client Authentication
- **Access Tokens**: Short-lived (default: 15 minutes) signed JSON Web Tokens (RS256 / ES256).
- **Refresh Token Rotation**:
  - Every refresh token exchange issues a new refresh token and invalidates the old one.
  - If an invalidated refresh token is ever reused (indicating token theft), Lattice-ID immediately revokes the **entire token family** and terminates the user's active session.
- **DPoP (Demonstrating Proof-of-Possession, RFC 9449)**: Binds access tokens cryptographically to client key thumbprints (`cnf: { jkt }`) and sender-constrains requests on `/token` and `/userinfo` with single-use `jti` replay prevention and `ath` access token hash verification.
- **Pushed Authorization Requests (PAR, RFC 9126)**: Allows confidential and public clients to push authorization parameters directly via authenticated backchannel (`POST /connect/par`), returning a short-lived (90s), single-use `request_uri`.
- **Private Key JWT Authentication (RFC 7523)**: Supports asymmetric key authentication (`private_key_jwt` with RS256/ES256) across token, PAR, revocation, and introspection endpoints, eliminating the need for shared static secrets.

### 2.4 Semantic Audit Trail (`lid-audit`)
Every administrative action, authentication attempt, and client modification is recorded to an append-only NATS JetStream stream named `lid-audit`:
- **Event Schema**:
  ```json
  {
    "id": "audit_evt_x912k...",
    "timestamp": 1787736817,
    "event_type": "client_updated | consent_approved | login_success | passkey_registered",
    "actor_id": "user_l8h88sbfo2wyai2x",
    "actor_ip": "10.244.1.42",
    "target_id": "client_msbe878x1efxdfl6",
    "details": {
      "scopes": ["openid", "profile", "email"],
      "first_party": true
    }
  }
  ```
- **Non-Repudiation**: Application-level auditing captures end-user identity, IP address, exact diffs, and business intent that cannot be determined at the raw packet/transport level.

---

## 3. Tier 2: Transport & Access Control Layer (NATS JetStream)

The messaging and transport layer isolates data streams, enforces least-privilege network access, and logs unauthorized transport operations.

### 3.1 Subject-Level Access Control Lists (ACLs)
NATS users and accounts are partitioned so that application services cannot access each other's storage subjects.

#### Principle of Least Privilege:
1. **Lattice-ID / Lattice-DB Service User (`lattice_svc`)**:
   - **Publish Permissions**: Allowed on `$KV.lid-*.*`, `$JS.API.DIRECT.GET.KV_lid-*.*`, `ldb.>`, and `$JS.API.STREAM.MSG.GET.KV_lid-*`.
   - **Subscribe Permissions**: Allowed on `$KV.lid-*.*`, `ldb.>`, and JetStream internal inbox replies (`_INBOX.>`).
2. **Standard Microservices / Public Pods**:
   - Explicitly **denied** `pub` and `sub` on any `$KV.lid-*.*` or `lid.>` subjects.
   - Cannot read or write identity data directly; all interactions must occur via standard OIDC HTTPS endpoints (`https://us.auth.taikavision.com/oauth/v2/...`).

### 3.2 NATS Server Security Configuration (`nats.conf` Blueprint)

```hcl
# NATS Security Configuration for Lattice-ID State
server_name: "nats-data"
port: 4222
jetstream: {
  store_dir: "/data"
  max_mem: 1Gi
  max_file: 20Gi
}

# TLS Encryption in Transit
tls: {
  cert_file: "/etc/nats/certs/tls.crt"
  key_file:  "/etc/nats/certs/tls.key"
  ca_file:   "/etc/nats/certs/ca.crt"
  verify:    true
  timeout:   5
}

# Account & User Isolation
accounts: {
  LATTICE_ID: {
    jetstream: enabled
    users: [
      {
        user: "lattice_svc"
        password: "$LATTICE_DB_NATS_PASSWORD"
        permissions: {
          publish: {
            allow: [
              "$KV.lid-*.*",
              "$JS.API.DIRECT.GET.KV_lid-*.*",
              "$JS.API.STREAM.MSG.GET.KV_lid-*",
              "ldb.>",
              "_INBOX.>"
            ]
          }
          subscribe: {
            allow: [
              "$KV.lid-*.*",
              "ldb.>",
              "_INBOX.>"
            ]
          }
        }
      }
    ]
  },
  APP_WORKLOADS: {
    users: [
      {
        user: "app_worker"
        password: "$APP_WORKLOAD_PASSWORD"
        permissions: {
          publish: {
            deny: ["$KV.lid-*.*", "ldb.>"]
            allow: ["app.>"]
          }
          subscribe: {
            deny: ["$KV.lid-*.*", "ldb.>"]
            allow: ["app.>"]
          }
        }
      }
    ]
  }
}

# Security & Violation Logging
trace: false
logtime: true
log_file: "/var/log/nats/nats.log"
```

### 3.3 Transport Security Violation Auditing
- **Immediate Rejection**: Any message published to an unauthorized subject by a non-privileged account is immediately rejected with `-ERR 'Permissions Violation'`.
- **Audit Trap**: NATS emits authorization failure logs containing:
  - Client Remote IP & Port
  - Connection ID (CID)
  - Configured Username / Account
  - Targeted Subject Name

---

## 4. Tier 3: Infrastructure & Storage Layer

The physical and infrastructure layer guarantees data durability, physical security, and network segmentation.

### 4.1 Storage Encryption at Rest
- **Kubernetes Persistent Volumes (PVCs)**: Backed by Google Cloud `standard-rwo` / `premium-rwo` Persistent Disks.
- **Hardware-Level Encryption**: All disk blocks are automatically encrypted at rest using AES-256 (Google-managed keys or Customer-Managed Encryption Keys / CMEK).
- **Snapshot Protection**: Database snapshots and volume backups inherit underlying cloud storage encryption.

### 4.2 Network Isolation & Segmentation
- **Internal Cluster Service**: `nats-data` is exposed exclusively via a Kubernetes internal `ClusterIP` / headless service (`nats-data.default.svc.cluster.local`).
- **No Public Ingress**: Port 4222 is never exposed to the public internet or external load balancers.
- **NetworkPolicy (Defense-in-Depth)**:
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: allow-nats-lattice-id-only
    namespace: default
  spec:
    podSelector:
      matchLabels:
        app: nats-data
    ingress:
      - from:
          - podSelector:
              matchLabels:
                app.kubernetes.io/name: lattice-id
          - podSelector:
              matchLabels:
                app.kubernetes.io/name: lattice-db
        ports:
          - protocol: TCP
            port: 4222
  ```

### 4.3 Key Management & Secrets Lifecycle
- **Secret Injection**: Sensitive keys (`LDB_MASTER_KEY`, `NATS_DATA_PASSWORD`, `INTERNAL_AUTH_SECRET`, client peppers) are mounted as environment variables from Kubernetes `Secret` objects.
- **KMS Integration**: Master keys can be periodically rotated using GCP Cloud KMS envelope encryption wrappers without requiring database downtime.

---

## 5. Summary Matrix: Security Threat vs Defense Layer

| Threat Scenario | Defense Layer | Mitigation Mechanism |
| :--- | :--- | :--- |
| **Physical Disk / Snapshot Theft** | Tier 3 (Infrastructure) | All disk blocks encrypted at rest with AES-256; snapshots are unreadable without cloud KMS keys. |
| **Compromised Pod in Cluster** | Tier 2 (NATS ACLs & NetPol) | NetworkPolicies block TCP connections to NATS; NATS ACLs reject unauthorized pub/sub on `$KV.lid-*`. |
| **Direct NATS State Inspection** | Tier 1 (Lattice-DB) | High-sensitivity tables (`users`, `credentials`) are stored as AES-256-GCM ciphertext in memory before hitting NATS. |
| **Unauthorized Client / User Edit** | Tier 1 (Lattice-ID) | Operations require Superadmin OIDC session or Bearer token; all mutations are recorded to append-only `lid-audit`. |
| **Stolen Refresh Token Replay** | Tier 1 (Token Engine) | Refresh token family reuse detection immediately terminates all active sessions for that token family. |
| **Man-in-the-Middle (MitM) Attack** | Tier 1 & 2 (TLS / PKCE / DPoP) | Mutual TLS 1.3 in transit, PKCE S256 challenge validation, and DPoP proof-of-possession (RFC 9449). |
