# JetAuth Management REST API Reference

The JetAuth Management REST API allows administrators and tenant operators to programmatically manage clients, tenants, users, identity providers, lifecycle hooks, signing keys, settings, and audit logs.

An OpenAPI 3.1.0 specification for this API is available in [`openapi.yaml`](openapi.yaml).

---

## Table of Contents
1. [Authentication & Authorization](#authentication--authorization)
2. [Global Settings & System Status](#global-settings--system-status)
3. [Signing Key Management](#signing-key-management)
4. [OAuth 2.0 / OIDC Clients](#oauth-20--oidc-clients)
5. [Tenants & Organizations](#tenants--organizations)
6. [Tenant Memberships & Invitations](#tenant-memberships--invitations)
7. [User Management, Privacy & GDPR](#user-management-privacy--gdpr)
8. [Multi-Factor Authentication (MFA / TOTP)](#multi-factor-authentication-mfa--totp)
9. [Hardware Passkeys (WebAuthn / FIDO2)](#hardware-passkeys-webauthn--fido2)
10. [External Identity Providers (SSO)](#external-identity-providers-sso)
11. [Lifecycle Hooks (Rhai Scripting)](#lifecycle-hooks-rhai-scripting)
12. [Audit Trail](#audit-trail)
13. [Dynamic Client Registration (RFC 7591 / RFC 7592)](#dynamic-client-registration-rfc-7591--rfc-7592)
14. [Standard Error Responses](#standard-error-responses)

---

## Authentication & Authorization

All management endpoints (except `/api/bootstrap/status` and `/api/invitations/accept`) require a Bearer token:

```http
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

### Roles and Permission Hierarchy
* **Superadmin**: Global cluster administrator. Token must have `aud: "lid-admin"`, `token_type: "access"`, and `role: "superadmin"`. Superadmins can manage all resources across the entire deployment.
* **Tenant Roles**: Assigned within specific tenants (`owner`, `admin`, `manager`, `member`).
  * `owner` / `admin` / `manager`: Can manage tenant users and send invitations (`require_tenant_role(..., "manager")`). Cannot invite or assign a role higher than their own.
* **Self**: Authenticated user acting on their own account (`require_self_or_superadmin(claims, user_id)`), such as configuring MFA, managing passkeys, triggering password resets, or exercising GDPR data portability and erasure rights.

### Obtaining a Superadmin Token
Admins obtain a token via the standard OIDC Authorization Code Flow with PKCE using `client_id=lid-admin`:

```bash
# 1. Generate PKCE verifier and challenge
VERIFIER=$(openssl rand -base64 32 | tr -d '=\n' | tr '+/' '-_')
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=\n' | tr '+/' '-_')

# 2. Authorize via browser or script:
# GET /authorize?client_id=lid-admin&response_type=code&redirect_uri=http://localhost:8090/callback&scope=openid+email+profile&code_challenge=$CHALLENGE&code_challenge_method=S256

# 3. Exchange authorization code for token:
curl -s -X POST http://localhost:8000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=lid-admin" \
  -d "code=$AUTH_CODE" \
  -d "code_verifier=$VERIFIER" \
  -d "redirect_uri=http://localhost:8090/callback"
```

---

## Global Settings & System Status

### Check Bootstrap Status
Checks whether the authority has an initial superadmin or requires bootstrapping.

* **Method / Path**: `GET /api/bootstrap/status`
* **Access**: Public (No auth required)
* **Response**: `200 OK`
  ```json
  {
    "needs_bootstrap": false
  }
  ```

### Get System Settings
* **Method / Path**: `GET /api/settings`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "allow_registration": true,
    "default_theme": null,
    "idp_session_ttl_seconds": 604800
  }
  ```

### Update System Settings
* **Method / Path**: `PUT /api/settings`
* **Access**: Superadmin
* **Request Body** (partial update; only supplied fields change):
  ```json
  {
    "allow_registration": false,
    "default_theme": { "theme_preset": "glassmorphic" },
    "idp_session_ttl_seconds": 86400
  }
  ```
  * `default_theme.theme_preset` is validated against the known presets: `taika-dark`, `taika-light`, `glassmorphism`, `glassmorphic`, `glassmorphic-frost`, `cyberpunk`, `midnight-neon`, `minimal-noir`, `dark-luxury`, `neo-brutalist`, `default` (returns 400 otherwise).
  * `idp_session_ttl_seconds` must be between `300` (5 minutes) and `7776000` (90 days).
* **Response**: `200 OK` (full settings model, as in `GET /api/settings`)

### Deployment Statistics
Aggregate object counts for dashboards. Deliberately excludes active sessions.

* **Method / Path**: `GET /api/stats`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "tenants": 3,
    "users": 42,
    "clients": 7,
    "identity_providers": 2
  }
  ```

---

## Signing Key Management

Inspect and rotate the RSA (RS256) and EC (ES256) signing-key pair. Signing keys are per-region in multi-region deployments (each region is its own issuer); rotate each region independently.

### List Signing Keys
Returns the full key ring: the current pair plus any retired keys still within their verification grace period. Private key material is never exposed.

* **Method / Path**: `GET /api/keys`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "keys": [
      {
        "kid": "AbC123xYz...",
        "alg": "RS256",
        "status": "current",
        "version": 2,
        "created_at": 1776235000,
        "retired_at": null,
        "grace_expires_at": null
      },
      {
        "kid": "OldKid456...",
        "alg": "RS256",
        "status": "retired",
        "version": 1,
        "created_at": 1775000000,
        "retired_at": 1776235000,
        "grace_expires_at": 1776239200
      }
    ]
  }
  ```
  `status` is `current` (signs new tokens), `retired` (still in JWKS for verification until `grace_expires_at`), or `expired` (past the grace window, dropped from JWKS).

### Rotate Signing Keys
Generates a fresh RSA+EC pair as the next key-ring generation and retires the outgoing pair. New tokens are signed with the new keys immediately; retired keys remain in the JWKS document (verification only) for a **4200-second grace period** (max token lifetime 3600s + 600s skew margin).

* **Method / Path**: `POST /api/keys/rotate`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "rotated": true,
    "version": 2,
    "current": {
      "rsa": { "kid": "AbC123xYz...", "key": "signing-key-v2" },
      "ec": { "kid": "EcK789...", "key": "signing-key-ec-v2" }
    },
    "retired": [
      { "kid": "OldKid456...", "alg": "RS256", "retired_at": 1776235000 },
      { "kid": "OldEcKid...", "alg": "ES256", "retired_at": 1776235000 }
    ],
    "grace_expires_at": 1776239200
  }
  ```
* **Errors**: `409 Conflict` if a concurrent rotation is in progress (the ring metadata is CAS-guarded; retry after the other rotation completes).

> **Verifier note**: during the grace window the JWKS document (`/.well-known/jwks.json`) contains the current *and* retired keys — more than 2 entries. Token verifiers must select keys by the JWT header `kid`, never by position or count.

---

## OAuth 2.0 / OIDC Clients

Endpoints to manage OAuth 2.0 client applications.

### List Clients
* **Method / Path**: `GET /api/clients`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  [
    {
      "client_id": "client_9fa2b3c4d5e6f7a8",
      "name": "Customer Portal",
      "redirect_uris": ["https://portal.example.com/callback"],
      "grant_types": ["authorization_code", "refresh_token"],
      "theme": null,
      "first_party": false
    }
  ]
  ```

### Create Client
* **Method / Path**: `POST /api/clients`
* **Access**: Superadmin
* **Request Body**:
  ```json
  {
    "name": "Customer Portal",
    "redirect_uris": [
      "https://portal.example.com/callback",
      "http://localhost:3000/callback"
    ],
    "post_logout_redirect_uris": [
      "https://portal.example.com/logged-out"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "confidential": true,
    "first_party": true,
    "id_token_signed_response_alg": "RS256",
    "backchannel_logout_uri": "https://portal.example.com/backchannel-logout",
    "backchannel_logout_session_required": true,
    "token_endpoint_auth_method": "client_secret_post",
    "require_pushed_authorization_requests": false,
    "theme": {
      "app_name": "Acme Portal",
      "theme_preset": "glassmorphic",
      "logo_url": "https://portal.example.com/assets/logo.svg",
      "primary_color": "#6366f1",
      "primary_hover_color": "#4f46e5"
    }
  }
  ```
* **Response**: `201 Created`
  ```json
  {
    "client_id": "client_9fa2b3c4d5e6f7a8",
    "client_secret": "9a01f8e234c9876543210fedcba98765",
    "name": "Customer Portal",
    "redirect_uris": ["https://portal.example.com/callback"],
    "post_logout_redirect_uris": ["https://portal.example.com/logged-out"],
    "grant_types": ["authorization_code", "refresh_token"],
    "theme": { ... },
    "first_party": true
  }
  ```
  *(Note: `client_secret` is only returned once upon creation for confidential clients).*

### Get Client
* **Method / Path**: `GET /api/clients/:id`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "client_id": "client_9fa2b3c4d5e6f7a8",
    "name": "Customer Portal",
    "redirect_uris": ["https://portal.example.com/callback"],
    "post_logout_redirect_uris": ["https://portal.example.com/logged-out"],
    "grant_types": ["authorization_code", "refresh_token"],
    "theme": null,
    "first_party": true,
    "backchannel_logout_uri": null,
    "backchannel_logout_session_required": false,
    "id_token_signed_response_alg": "RS256"
  }
  ```

### Update Client
* **Method / Path**: `PUT /api/clients/:id`
* **Access**: Superadmin
* **Request Body** (partial updates supported):
  ```json
  {
    "name": "Updated Portal Name",
    "redirect_uris": ["https://portal.example.com/new-callback"],
    "theme": {
      "theme_preset": "cyberpunk"
    }
  }
  ```
* **Response**: `200 OK`

### Delete Client
* **Method / Path**: `DELETE /api/clients/:id`
* **Access**: Superadmin (`lid-admin` cannot be deleted)
* **Response**: `200 OK`
  ```json
  {
    "deleted": true
  }
  ```

### Rotate Client Secret
Generates a new secret for a confidential client; the raw value is returned exactly once (stored HMAC-hashed).

* **Method / Path**: `POST /api/clients/:id/rotate-secret`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "client_id": "client_9fa2b3c4d5e6f7a8",
    "client_secret": "9a01f8e234c9876543210fedcba98765"
  }
  ```
* **Errors**: `400 Bad Request` for public clients (`token_endpoint_auth_method: "none"` — this includes the built-in `lid-admin`); `404 Not Found` for unknown clients.

---

## Tenants & Organizations

### List Tenants
* **Method / Path**: `GET /api/tenants`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  [
    {
      "id": "tenant_1a2b3c4d",
      "name": "acme-corp",
      "display_name": "Acme Corporation",
      "status": "active",
      "created_at": 1775630000
    }
  ]
  ```

### Create Tenant
* **Method / Path**: `POST /api/tenants`
* **Access**: Superadmin
* **Request Body**:
  ```json
  {
    "name": "acme-corp",
    "display_name": "Acme Corporation"
  }
  ```
* **Response**: `201 Created`
  ```json
  {
    "id": "tenant_1a2b3c4d",
    "name": "acme-corp",
    "display_name": "Acme Corporation",
    "status": "active"
  }
  ```

### Get Tenant
* **Method / Path**: `GET /api/tenants/:id`
* **Access**: Superadmin
* **Response**: `200 OK`

### Update Tenant
Partially updates a tenant's display name and/or lifecycle status. Replicated to remote regions.

* **Method / Path**: `PATCH /api/tenants/:id`
* **Access**: Superadmin
* **Request Body** (only supplied fields change):
  ```json
  {
    "display_name": "Acme Corporation",
    "status": "suspended"
  }
  ```
  `status` must be `active` or `suspended` (returns 400 otherwise).
* **Response**: `200 OK`
  ```json
  {
    "id": "tenant_1a2b3c4d",
    "name": "acme-corp",
    "display_name": "Acme Corporation",
    "status": "suspended",
    "created_at": 1775630000
  }
  ```

### Delete Tenant
* **Method / Path**: `DELETE /api/tenants/:id`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "deleted": true
  }
  ```

---

## Tenant Memberships & Invitations

### List Tenant Users
* **Method / Path**: `GET /api/tenants/:id/users`
* **Access**: Tenant Manager/Admin/Owner, or Superadmin
* **Response**: `200 OK`
  ```json
  [
    {
      "id": "user_4f9a0c1e",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "admin",
      "joined_at": 1775631200
    }
  ]
  ```

### Add User Directly to Tenant
* **Method / Path**: `POST /api/tenants/:id/users`
* **Access**: Tenant Manager/Admin/Owner, or Superadmin
* **Request Body**:
  ```json
  {
    "user_id": "user_4f9a0c1e",
    "role": "member"
  }
  ```
* **Response**: `201 Created`
  ```json
  {
    "tenant_id": "tenant_1a2b3c4d",
    "user_id": "user_4f9a0c1e",
    "role": "member"
  }
  ```

### Remove User from Tenant
* **Method / Path**: `DELETE /api/tenants/:tid/users/:uid`
* **Access**: Tenant Manager/Admin/Owner, Superadmin, or the user removing themselves
* **Response**: `200 OK`
  ```json
  {
    "removed": true
  }
  ```

### Invite User to Tenant
Generates a 7-day token and dispatches an invitation email. The invitable roles are `admin`, `manager`, and `member` — `owner` cannot be granted via invitation (use `POST /api/tenants/:id/users` with sufficient privilege instead). You cannot invite to a role higher than your own (returns 403).

* **Method / Path**: `POST /api/tenants/:id/users/invite`
* **Access**: Tenant Manager/Admin/Owner, or Superadmin
* **Request Body**:
  ```json
  {
    "email": "newuser@example.com",
    "role": "member"
  }
  ```
* **Response**: `201 Created`
  ```json
  {
    "email": "newuser@example.com",
    "role": "member",
    "invite_token": "a1b2c3d4e5f6...",
    "expires_at": 1776235000
  }
  ```

### Accept Invitation
* **Method / Path**: `POST /api/invitations/accept`
* **Access**: Public
* **Request Body**:
  ```json
  {
    "token": "a1b2c3d4e5f6...",
    "user_id": "user_4f9a0c1e"
  }
  ```
* **Response**: `201 Created`
  ```json
  {
    "tenant_id": "tenant_1a2b3c4d",
    "user_id": "user_4f9a0c1e",
    "role": "member"
  }
  ```

---

## User Management, Privacy & GDPR

### List Users
Global user list with optional filtering.

* **Method / Path**: `GET /api/users?q=&limit=`
* **Access**: Superadmin
* **Query Parameters**:
  * `q` *(optional)*: case-insensitive substring filter on email and name
  * `limit` *(optional)*: default `100`, max `500`
* **Response**: `200 OK`
  ```json
  [
    {
      "id": "user_4f9a0c1e",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "status": "active",
      "created_at": 1775630000,
      "totp_enabled": true,
      "superadmin": false
    }
  ]
  ```

### Activate User
Sets the user's status to `active` — intended for accounts stuck in `pending` (e.g. a lost verification email).

* **Method / Path**: `POST /api/users/:id/activate`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "id": "user_4f9a0c1e",
    "status": "active"
  }
  ```

### Initiate Password Reset
Dispatches a password reset email with a 1-hour reset token (rate limited to 3 requests per hour).

* **Method / Path**: `POST /api/users/:id/password-reset`
* **Access**: Self or Superadmin
* **Response**: `200 OK`
  ```json
  {
    "user_id": "user_4f9a0c1e",
    "email": "jane@example.com",
    "expires_in": 3600,
    "message": "Password reset email sent"
  }
  ```

### GDPR Data Export (Article 15 / 20)
Exports all first-party personal data, tenant memberships, and OAuth scope consents. Sensitive secrets (password hash, MFA seeds) are redacted.

* **Method / Path**: `GET /api/users/:id/export`
* **Access**: Self or Superadmin
* **Response**: `200 OK`
  ```json
  {
    "id": "user_4f9a0c1e",
    "email": "jane@example.com",
    "name": "Jane Doe",
    "status": "active",
    "created_at": 1775630000,
    "superadmin": false,
    "totp_enabled": true,
    "passkey_count": 1,
    "memberships": [
      {
        "tenant_id": "tenant_1a2b3c4d",
        "role": "admin"
      }
    ],
    "consents": [
      {
        "client_id": "client_9fa2b3c4d5e6f7a8",
        "scopes": ["openid", "email", "profile"],
        "granted_at": 1775630100,
        "updated_at": 1775630100
      }
    ]
  }
  ```

### GDPR Right to Erasure (Article 17)
Permanently hard-deletes the user record, email index, sessions, and tenant memberships.

* **Method / Path**: `DELETE /api/users/:id`
* **Access**: Self or Superadmin (Superadmin cannot self-delete)
* **Response**: `200 OK`
  ```json
  {
    "deleted": true,
    "id": "user_4f9a0c1e"
  }
  ```

---

## Multi-Factor Authentication (MFA / TOTP)

### Initiate MFA Setup
Generates an RFC 6238 TOTP seed and an `otpauth://` URI for authenticator apps.

* **Method / Path**: `POST /api/users/:id/mfa/setup`
* **Access**: Self or Superadmin
* **Response**: `200 OK`
  ```json
  {
    "secret": "JBSWY3DPEHPK3PXP",
    "otpauth_uri": "otpauth://totp/JetAuth:jane@example.com?secret=JBSWY3DPEHPK3PXP&issuer=JetAuth"
  }
  ```

### Confirm MFA Setup
Verifies the initial 6-digit TOTP code and generates single-use recovery codes.

* **Method / Path**: `POST /api/users/:id/mfa/confirm`
* **Access**: Self or Superadmin
* **Request Body**:
  ```json
  {
    "code": "123456"
  }
  ```
* **Response**: `200 OK`
  ```json
  {
    "enabled": true,
    "recovery_codes": [
      "a1b2-c3d4-e5f6",
      "f7g8-h9j0-k1l2"
    ]
  }
  ```

### Disable MFA
Disables TOTP and revokes all active refresh tokens and sessions for security.

* **Method / Path**: `DELETE /api/users/:id/mfa`
* **Access**: Self or Superadmin
* **Response**: `200 OK`
  ```json
  {
    "disabled": true
  }
  ```

---

## Hardware Passkeys (WebAuthn / FIDO2)

### List User Passkeys
* **Method / Path**: `GET /api/users/:id/passkeys`
* **Access**: Self or Superadmin
* **Response**: `200 OK`
  ```json
  [
    {
      "credential_id": "Ac_34g...",
      "name": "YubiKey 5 NFC",
      "created_at": 1775630000,
      "sign_count": 14
    }
  ]
  ```

### Passkey Registration: Options
* **Method / Path**: `POST /api/users/:id/passkeys/register-options`
* **Access**: Self or Superadmin
* **Response**: `200 OK`
  ```json
  {
    "token": "challenge_token_hex_32",
    "publicKey": {
      "challenge": "base64url_challenge",
      "rp": { "name": "JetAuth", "id": "auth.example.com" },
      "user": {
        "id": "base64url_user_id",
        "name": "jane@example.com",
        "displayName": "Jane Doe"
      },
      "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
    }
  }
  ```

### Passkey Registration: Complete
* **Method / Path**: `POST /api/users/:id/passkeys/register-complete`
* **Access**: Self or Superadmin
* **Request Body**:
  ```json
  {
    "token": "challenge_token_hex_32",
    "name": "MacBook TouchID",
    "clientDataJSON": "base64url_string",
    "attestationObject": "base64url_string"
  }
  ```
* **Response**: `200 OK`
  ```json
  {
    "credential_id": "Ac_34g...",
    "name": "MacBook TouchID",
    "created_at": 1775631200
  }
  ```

### Delete Passkey
* **Method / Path**: `DELETE /api/users/:id/passkeys/:cred_id`
* **Access**: Self or Superadmin
* **Response**: `200 OK`
  ```json
  {
    "deleted": true
  }
  ```

---

## External Identity Providers (SSO)

Configure upstream identity providers for social login. Supported `provider_type` values: `google`, `github` (dedicated handlers) and `microsoft` (generic OIDC federation path; set `discovery_url` via the update endpoint).

### List Identity Providers
* **Method / Path**: `GET /api/identity-providers`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  [
    {
      "id": "idp_google_01",
      "provider_type": "google",
      "client_id": "123456789.apps.googleusercontent.com",
      "enabled": true
    }
  ]
  ```

### Create Identity Provider
* **Method / Path**: `POST /api/identity-providers`
* **Access**: Superadmin
* **Request Body**:
  ```json
  {
    "provider_type": "google",
    "client_id": "123456789.apps.googleusercontent.com",
    "client_secret": "GOCSPX-secret",
    "enabled": true
  }
  ```
* **Response**: `201 Created`

### Update Identity Provider
Only supplied fields are considered, with deliberate empty-string semantics:

* `client_id` / `client_secret`: an empty string (or omission) **leaves the stored value unchanged**.
* `display_name` / `discovery_url`: an empty string **clears** the field.
* `discovery_url`, when non-empty, must use the `https` scheme (returns 400 otherwise).
* The stored `client_secret` is never echoed in any response.

* **Method / Path**: `PUT /api/identity-providers/:id`
* **Access**: Superadmin
* **Request Body**:
  ```json
  {
    "client_id": "",
    "client_secret": "GOCSPX-new-secret",
    "enabled": false,
    "display_name": "Sign in with Google",
    "discovery_url": ""
  }
  ```
* **Response**: `200 OK`
  ```json
  {
    "id": "idp_google_01",
    "provider_type": "google",
    "client_id": "123456789.apps.googleusercontent.com",
    "enabled": false,
    "display_name": "Sign in with Google",
    "discovery_url": null
  }
  ```

### Delete Identity Provider
* **Method / Path**: `DELETE /api/identity-providers/:id`
* **Access**: Superadmin
* **Response**: `200 OK`

---

## Lifecycle Hooks (Rhai Scripting)

Manage sandboxed Rhai script hooks executed during authentication events (`post-login`, `post-registration`).

### List Hooks
* **Method / Path**: `GET /api/hooks`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  [
    {
      "id": "hook_a1b2c3d4",
      "name": "Assign Default Tenant",
      "trigger": "post-registration",
      "script": "if user.email.ends_with(\"@example.com\") { add_to_tenant(\"acme\", \"member\"); }",
      "enabled": true,
      "priority": 10,
      "version": 1,
      "script_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "created_at": 1775630000,
      "updated_at": 1775630000,
      "updated_by": "user_admin"
    }
  ]
  ```

### Create Hook
* **Method / Path**: `POST /api/hooks`
* **Access**: Superadmin
* **Request Body**:
  ```json
  {
    "name": "Assign Default Tenant",
    "trigger": "post-registration",
    "script": "if user.email.ends_with(\"@example.com\") { add_to_tenant(\"acme\", \"member\"); }",
    "enabled": true,
    "priority": 10
  }
  ```
* **Response**: `201 Created`

### Update Hook
* **Method / Path**: `PUT /api/hooks/:id`
* **Access**: Superadmin
* **Response**: `200 OK` (creates an immutable version snapshot)

### Test Hook (Dry-Run)
Compiles and simulates execution with mock user attributes.

* **Method / Path**: `POST /api/hooks/:id/test`
* **Access**: Superadmin
* **Response**: `200 OK`
  ```json
  {
    "success": true,
    "deny_reason": null,
    "set_superadmin": false,
    "add_to_tenants": [
      { "tenant_id": "acme", "role": "member" }
    ],
    "extra_claims": [],
    "log_messages": ["User assigned to acme tenant"]
  }
  ```

### View Hook Versions
* **Method / Path**: `GET /api/hooks/:id/versions`
* **Access**: Superadmin
* **Response**: `200 OK`

### Delete Hook
* **Method / Path**: `DELETE /api/hooks/:id`
* **Access**: Superadmin
* **Response**: `200 OK`

---

## Audit Trail

Query the immutable semantic audit stream recorded in NATS JetStream.

* **Method / Path**: `GET /api/audit`
* **Access**: Superadmin
* **Query Parameters**:
  * `actor_id` *(optional)*: Filter by actor user ID
  * `target_id` *(optional)*: Filter by target entity ID
  * `event_type` *(optional)*: e.g. `client_created`, `tenant_created`, `tenant_updated`, `identity_provider_updated`, `mfa_enabled`, `user_deleted`
  * `since` *(optional)*: Unix epoch timestamp in seconds
  * `until` *(optional)*: Unix epoch timestamp in seconds
  * `limit` *(optional)*: Default `100`, max `500`
* **Response**: `200 OK`
  ```json
  {
    "events": [
      {
        "id": "audit_evt_9fa1b2c3",
        "timestamp": 1775630000,
        "event_type": "client_created",
        "actor_id": "user_superadmin",
        "target_id": "client_9fa2b3c4d5e6f7a8",
        "details": "Customer Portal"
      }
    ],
    "filters": {
      "actor_id": null,
      "target_id": null,
      "event_type": "client_created",
      "since": null,
      "until": null,
      "limit": 100
    }
  }
  ```

---

## Dynamic Client Registration (RFC 7591 / RFC 7592)

Endpoints available at `/connect/register` or `/oauth/register`:

| Method | Path | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/connect/register` | Initial Access Token (if mode is `protected`) | RFC 7591 Dynamic Client Registration |
| `GET` | `/connect/register/:id` | Registration Access Token | RFC 7592 Client Configuration Read |
| `PUT` | `/connect/register/:id` | Registration Access Token | RFC 7592 Client Configuration Update |
| `DELETE` | `/connect/register/:id` | Registration Access Token | RFC 7592 Client Configuration Delete |

`POST` is gated by the `client_registration_mode` config: `disabled` (default, returns 403 `access_denied`), `open`, or `protected` (requires a Bearer initial access token; missing/invalid token returns 401 `invalid_token`). A successful registration returns `201` with `client_id`, `client_secret` (confidential clients only, shown once), `registration_client_uri`, and `registration_access_token` (shown once — required for the RFC 7592 operations below).

`GET`/`PUT`/`DELETE /connect/register/:id` authenticate with the registration access token as a Bearer token; a missing or invalid token returns 401 with a `WWW-Authenticate: Bearer` challenge. An unknown client returns 404 `invalid_client`. `PUT` applies partial updates (only supplied fields change) and returns the updated configuration. `DELETE` returns `204 No Content`; the built-in `lid-admin` client cannot be deleted (403). Validation failures on metadata (redirect URIs, grant types, auth methods) return 400 with RFC 7591 §3.2.2 error codes (`invalid_redirect_uri`, `invalid_client_metadata`).

---

## Standard Error Responses

When an error occurs, the API returns a standard JSON error envelope:

```json
{
  "error": "invalid_request",
  "error_description": "name is required"
}
```

The `error` code is derived from the HTTP status (`invalid_request`, `invalid_token`, `insufficient_scope`, `not_found`, `too_many_requests`, `server_error`).

### Common HTTP Status Codes
* `200 OK`: Request succeeded.
* `201 Created`: Resource successfully created.
* `400 Bad Request`: Validation failure or malformed payload.
* `401 Unauthorized`: Missing, invalid, or expired Bearer token.
* `403 Forbidden`: Insufficient role or authority to perform operation.
* `404 Not Found`: Target resource (tenant, user, client, hook, identity provider, membership, or passkey) not found.
* `409 Conflict`: Conflicting state — the user is already a member of the tenant, MFA is already enabled, the passkey is already registered, or a concurrent signing-key rotation is in progress.
* `429 Too Many Requests`: Rate limit exceeded (e.g. password resets).
* `500 Internal Server Error`: Storage outage or other internal failure. The response body is a generic `internal error` message; diagnostic detail is logged server-side only and never sent to the client.

> **Exception**: `POST /api/invitations/accept` deliberately returns `400` (not `404`/`410`) for unknown or expired invitation tokens, so the endpoint cannot be used as a token-validity oracle.
