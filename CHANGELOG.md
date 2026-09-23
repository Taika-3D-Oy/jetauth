# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.11.0] - 2026-09-23

### Added

- **RFC 7591 Dynamic Client Registration & RFC 7592 Management**:
  - Implemented `POST /connect/register` (and `/oauth/register`) supporting RFC 7591 metadata registration, client credentials generation (HMAC hashed), and RFC 7592 `registration_access_token` issuance (SHA-256 hashed).
  - Added RFC 7592 Client Configuration Management (`GET`, `PUT`, `DELETE /connect/register/:id`) authenticated with registration access tokens.
  - Added configurable gating via `client_registration_mode` ("disabled" by default, "open", or "protected" with Bearer Initial Access Token).
- **RFC 8414 Authorization Server Metadata**:
  - Added fast-path and main router support for `/.well-known/oauth-authorization-server`.
- **REST Client Management**:
  - Added programmatic `GET /api/clients/:id` and `DELETE /api/clients/:id` endpoints.
- **Admin Console UI/UX Alignment**:
  - Added `post_logout_redirect_uris` inputs to the "Add Client" modal and Client Detail settings page.
  - Added Dynamic Client Registration (RFC 7591) status indicator to System Settings.
  - Displayed login and post-logout redirect counts in the client overview table.

### Changed

- **RFC 9207 Issuer Identification in Authorization Responses**:
  - Enforced `iss` parameter inclusion in all authorization code redirects across authorization, login, consent, and passkey flows.
  - Advertised `"authorization_response_iss_parameter_supported": true` in discovery metadata.
- **RP-Initiated Logout Separation**:
  - Added dedicated `post_logout_redirect_uris` field on `OidcClient`.
  - Enforced strict post-logout URI validation matching only against `post_logout_redirect_uris`.
- **Discovery Alignment**:
  - Removed misleading `/register` signup endpoint from discovery metadata.
  - Conditionally advertise RFC 7591 `registration_endpoint` only when dynamic registration is enabled.

### Security & Fixed

- **RFC 7009 Token Revocation Hardening**:
  - Required client authentication on token revocation requests.
  - Verified refresh token ownership before revocation to prevent cross-client token probing.
- **RFC 6750 §3.1 Bearer Challenges**:
  - UserInfo endpoint returns `HTTP 401 Unauthorized` with `WWW-Authenticate: Bearer` challenge header on failed or missing tokens.
- **RFC 7662 Introspection Challenge**:
  - Corrected introspection challenge header to `Basic realm="token-introspection"`.
- **TOTP Replay Mitigation**:
  - Added time-step tracking (`record_totp_used`) to prevent TOTP replay within clock-skew windows.
- **XSS & Injection Hardening**:
  - Prevented DOM XSS in admin toast messages using `textContent`.
  - Added HTML escaping to recipient names in email worker templates.
  - Hardened custom CSS sanitization against `</style>` / `<script>` breakouts.
- **Documentation**:
  - Clarified RFC 9449 (DPoP) roadmap status in `SECURITY.md`.

## [1.10.0] - 2026-08-31

### Breaking Changes

- **NATS ADR-32 & Framed TCP Protocol**:
  - Migrated localhost `lattice-db` loopback communication to the framed binary protocol (`[4-byte total_len][1-byte op_len][op][payload]` request and `[4-byte total_len][2-byte status_code][payload]` response), matching `lattice-db` v1.11.0.

### Fixed

- **Discovery Endpoints & TCP Connection Resilience**:
  - Moved dev mode test client seeding (`ensure_default_client`, `ensure_admin_client`) out of the global request pipeline into the authenticated/management flow handlers. Public discovery and health endpoints (`/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/healthz`, `/version`) now bypass dev client seeding, eliminating redundant KV writes and connection spikes.
  - Enhanced `try_ldb_tcp` with per-attempt network instantiation, dynamic `LDB_TCP_PORT` resolution, and progressive backoff (5ms–50ms over 15 retries), resolving `ErrorCode::ConcurrencyConflict` during rapid sequential TCP requests.

## [1.9.5] - 2026-08-27

### Security

- **Client Secret HMAC-SHA256 Hashing & Show-Once Admin Pattern**:
  - `POST /admin/clients` and `POST /admin/clients/{id}/rotate-secret` hash client secrets with HMAC-SHA256 using `client_secret_pepper` before persisting to database.
  - Raw secrets are never stored in plaintext and are revealed only once upon creation/rotation.
  - Client detail view masks secrets (`•••••••••••••••••••••••••••••••• (HMAC-SHA256 Protected)`).
- **Constant-Time Verification & Backward Compatibility**:
  - Constant-time secret comparison (`subtle::ConstantTimeEq`) in token authentication (`token.rs`) against HMAC hashes, with graceful constant-time fallback for pre-existing legacy raw client secrets.
- **Session Token Hashing in KV Store**:
  - User session tokens are hashed (`sha256_hex(token)`) before storing in KV keyspace (`store.rs`), preventing session hijacking if KV backups or database records are accessed.
  - Graceful fallback for active unhashed legacy sessions.
- **Admin CSRF Protection Enforcement**:
  - Enforced CSRF validation across all mutating admin routes (`POST`, `PUT`, `DELETE`).

## [1.9.4] - 2026-08-26

### Added

- **Persistent User Consent Grants (RFC 6749 & GDPR)**:
  - Saved user consent decisions in NATS KV (`consent:{user_id}:{client_id}`) upon user approval on the consent screen.
  - Fast-path authorization and login flows now automatically verify prior consent grants and skip the consent prompt when identical or subset scopes were already approved.
  - Forced consent prompt continues to be supported when clients specify `prompt=consent` or when new scopes are requested.
  - GDPR compliance: User consent grants are exported in GDPR data export (`GET /api/users/:id/export`) and automatically purged on user deletion (`DELETE /api/users/:id`).

- **First-Party Client Management & OAuth Settings in Admin UI**:
  - Added "First-Party / Trusted Application" toggle in client registration modal and client detail page, allowing administrative bypass of the consent prompt for official applications.
  - Added full OAuth client configuration in Admin UI for ID token signing algorithm selection (`RS256` / `ES256`), allowed grant types, and OpenID Connect Back-Channel Logout URL / session configuration.
  - Added visual trust level and signing algorithm badges to the Admin clients table overview.

- **Dynamic SSO Session Longevity & Settings**:
  - Increased default IdP SSO browser cookie session duration (`DEFAULT_IDP_SESSION_TTL`) from 30 minutes to 7 days (`604800s`) with automatic rolling expiration extension on user activity.
  - Added IdP SSO Browser Session Duration setting (1–90 days) in `/admin/settings` with persistence to `RuntimeSettings`.

## [1.9.3] - 2026-08-25

### Fixed

- **Admin Portal Passkey Registration**:
  - Added dedicated cookie-session authenticated endpoints `POST /admin/account/passkeys/register-options` and `POST /admin/account/passkeys/register-complete` with CSRF protection.
  - Fixed Admin UI passkey script calling Management API endpoints without Bearer tokens, resolving `missing Authorization header` error.
  - Fixed self-service account passkey registration script referencing undefined variable and missing challenge endpoint.

## [1.9.2] - 2026-08-24

### Fixed

- **Security Hardening**:
  - Added SSRF protection for backchannel logout and social IdP endpoints with strict external URL validation.
  - Mitigated timing side-channels on user authentication paths.
  - Enforced session-bound CSRF token validation across state-mutating admin routes.

## [1.9.1] - 2026-08-24

### Fixed

- **Complete Multi-Cookie & IdP Session Logout**:
  - Fixed sign-out from Admin portal (`/admin/logout`), Account self-service (`/account/logout`), and RP-initiated logout (`/logout`) where active `lid_session` IdP sessions previously persisted SSO authentication.
  - Added centralized `append_clear_all_cookies` helper to invalidate both `lid_account` (across `/` and `/account` paths), `lid_session` IdP cookie, and `lid_tenant` cookie with `Max-Age=0` and `no-store, no-cache` cache headers.
  - Ensured server-side session records in NATS KV are deleted for all session tokens present in request headers during sign-out.

## [1.9.0] - 2026-08-24

### Added

- **Full Identity Provider Lifecycle & In-Place Management**:
  - Added HTMX-powered instant enable/disable toggle switch (`POST /admin/identity-providers/:id/toggle`) for real-time activation without page reloads.
  - Added IdP Edit modal (`GET /admin/identity-providers/:id/modal/edit` and `POST /admin/identity-providers/:id/update`) allowing updates to Client ID, Client Secret, and enabled state.
  - Added branded SVG icons and status badges for Google, GitHub, Microsoft, and generic OpenID Connect providers in the Admin console.
  - Dynamic login button rendering on `/login` that automatically shows or hides provider buttons (e.g., "Continue with Google", "Continue with GitHub") based on active provider configuration.
- **Unified Sign-In Architecture**:
  - Unified Admin UI authentication with the standard OIDC authorization flow via the `lid-admin` first-party client.
  - Unauthenticated access to `/admin` seamlessly redirects through `/authorize` to the unified sign-in screen, enabling Google SSO, Passkeys, Email/Password, and MFA across all portals.
  - Automatic admin privilege verification (`superadmin` or tenant `admin`/`owner`) on session establishment.
- **Enhanced Design System & Interaction States**:
  - Added toggle switch components, social button states, and HTMX request indicators to `admin.css`.

## [1.8.0] - 2026-08-24

### Added

- **Dynamic Theming & Modern Presets Engine**:
  - Implemented dedicated theme engine (`theme.rs`) supporting 6 built-in presets: `taika-dark` (default), `taika-light`, `glassmorphic` (frosted glass blur), `cyberpunk` (neon cyan & pink grid), `minimal-noir` (luxury monochrome), and `neo-brutalist` (bold 3px black borders & hard shadows).
  - Dynamic resolution hierarchy: Built-in Base Preset $\rightarrow$ System Global Default Theme $\rightarrow$ Per-OAuth-Client Theme Override.
  - Automatic `:root` CSS variables generator for customizable colors, typography, card background, border, shadow, backdrop blur, and inputs.
  - Custom Google Fonts & Web Fonts loading via configurable `font_url` and `font_family`.
- **Comprehensive White-Labeling**:
  - Ability to fully customize brand and application titles (e.g. from "Lattice-ID" to "Taika ID" or custom portal name) purely via theme configuration.
  - Support for custom logo URLs, height settings, and favicon URLs with strict protocol/URL safety validation.
  - Customizable footer copyright notice, terms/privacy/help links, and "Powered by" text with option to completely hide vendor branding (`hide_powered_by`).
- **Surface-Wide Theming**:
  - Refactored login, registration, MFA (TOTP, Passkeys, Recovery Codes), consent screen, account dashboard, and device flow pages to dynamically use the theme engine.
- **Admin UI & REST Management**:
  - Added Global White-Labeling & Theme Defaults form in `/admin/settings`.
  - Added per-client theme editor card in `/admin/clients/:id` and new client registration modal.
  - Added `theme` support to Client REST APIs (`POST /api/clients`, `PUT /api/clients/:id`, and `GET /api/clients`).
- **Documentation**:
  - Added comprehensive [`THEMING.md`](THEMING.md) guide with preset overviews, CSS variable tables, admin/API instructions, security rules, and copy-paste theme recipes.

## [1.7.1] - 2026-08-24

### Added

- **Bootstrap Email Verification**:
  - Enforced verification token generation and confirmation email dispatch when `require_email_verification` is enabled on `/admin/bootstrap`.
  - Added "Check Your Inbox" pending page to prevent unauthorized session creation during bootstrap.

### Fixed

- **Superadmin Activation Guard**:
  - Prevented hooks from prematurely promoting unverified superadmin accounts to active status when email verification is required.
- **AWS SES SigV4 Request Signing**:
  - Fixed `signed_headers` order and payload hash canonicalization in `email-worker` to properly sign requests to the AWS SES v2 API.

## [1.7.0] - 2026-08-24

### Added

- **Unified SSR Maud + HTMX Admin Panel**:
  - Replaced the external client-side Leptos SPA (`admin-ui` and `admin-ui-host`) with a full server-side rendered (SSR) admin dashboard embedded directly in `oidc-gateway`.
  - Implemented compile-time type-checked templates using `maud` with zero client runtime build dependencies (no Trunk, no npm, no wasm-opt required).
  - Embedded standalone minified HTMX 2.0.4 runtime and comprehensive CSS design system directly into gateway memory with immutable cache headers.
  - Complete support for all admin features: First-run Bootstrap Wizard, Dashboard & Metrics, Tenants & Memberships, OAuth2/OIDC Clients & Secret Rotation, Users & Passkey Credentials, Identity Providers, Rhai Hooks & Live Simulator, System Settings, Audit Log Explorer, and Account Management.

### Removed

- **Legacy Leptos Admin UI & Host Crate**:
  - Removed `admin-ui/` directory, `admin-ui-host` crate, and `lattice-id:admin/assets` WIT dependency.
  - Removed `admin-ui-host` from all Kubernetes WorkloadDeployment manifests (`deploy/workloaddeployment-*.yaml`) and GitHub Actions publish workflows.
  - Eliminated WASI string proxying bottlenecks and SRI asset mismatch issues.

## [1.6.1] - 2026-08-24

### Changed

- **Stable Rust & WASI 0.3 Toolchain**:
  - Upgraded workspace dependencies to `wasip3 0.7` and `wit-bindgen 0.57`.
  - Updated toolchain documentation to stable Rust targeting `wasm32-wasip2`.
  - Updated runtime requirements to Wasmtime ≥ 47 / wasmCloud ≥ 2.7.0.

### Fixed

- **TCP Co-Located Storage Client**:
  - Added retry loop with exponential backoff for socket creation and `start_connect` in `try_ldb_tcp`.
  - Replaced polling loops with blocking WASI stream reads.
  - Adjusted TCP loopback handling and removed unnecessary messaging dependency from `oidc-gateway`.

## [1.6.0] - 2026-08-22

### Added

- **wasmCloud 2.7.0 & WASI Component Model Compatibility**:
  - Registered WASI random provider (`wasi:random/random@0.2.2`) via `getrandom::register_custom_getrandom!` to enable `OsRng` on wasmCloud 2.7.0 hosts.
  - Added localhost TCP client support to connect to co-located `storage-service` over `127.0.0.1:4080` with automatic NATS fallback.
  - Optimized public JWKS extraction (`/.well-known/jwks.json`) to return in sub-5ms directly from stored key attributes without expensive private key CRT reconstructions.
  - Made PKCE optional for registered confidential clients.

## [1.5.8] - 2026-05-10

### Added

- **IdP browser session (SSO / prompt=none support)**: New `lid_session` cookie
  enables silent authentication for SPAs (`prompt=none`) and cross-client SSO.
  `lid_session` is set after every successful login, cleared on logout, and
  validated on each `/authorize` call with a 30-minute sliding TTL.
- **`acr_from_amr` helper**: Derives an ACR value from AMR claims for use in
  the IdP session fast-path.
- **Consent form CSRF protection**: Defense-in-depth CSRF token added to the
  consent form (`POST /consent`). Enforced for approve decisions only (deny has
  no security value).
- **IP-based rate limiting on `/register`**: 100 registration attempts per hour
  per source IP, alongside the existing per-email limit.
- **Unit tests**: 30+ new tests across `abuse`, `token`, `jwt`, `authorize`,
  `login`, `passkeys`, `backchannel`, and `device` modules (104 total).
- **Integration tests**: New `integration_concurrent` (CAS race-condition
  safety), `integration_sso` (browser session / prompt / SSO flow).

### Changed

- **`dev_mode` no longer skips consent for non-first-party clients**: Consent
  is now always required for third-party clients, even in dev mode.
- **Port 8000 for local deployment**: Changed from port 80 to 8000 to avoid
  conflicts with other local Kind clusters. Uses nginx proxy to preserve
  `Host` header for wasmCloud's virtual-host routing.
- **Removed direct `rand_core` dependency**: Uses `p256::elliptic_curve::rand_core`
  re-export instead, matching the version used by the crypto crates.

### Fixed

- **CI runs `cargo test` and `cargo audit` before publish**: Tests and
  dependency vulnerability scanning now block publishing broken or vulnerable
  artifacts.
- **`getrandom::getrandom` call sites**: No code changes needed — `getrandom`
  0.3 is not supported on `wasm32-wasip3`, so left at 0.2.
- **`require_email_verification: "false"` respected during registration**: The
  registration handler reads the config value correctly to bypass email
  verification.
- **GDPR export test expectations**: `integration_account` test now matches
  the API's consistent 400 response for non-existent users.

## [1.5.7] - 2026-05-07

### Fixed

- **OAuth consent redirect blocked in Chrome with localhost callback**: Chrome
  enforces CSP `form-action` against cross-origin redirect targets after form
  submission. In the OAuth flow (`POST /consent` -> `302` to client
  `redirect_uri`), `form-action 'self'` could block redirects to
  `http://localhost:*` even though consent POST itself was same-origin.
  Resolved by removing `form-action` from the gateway CSP while keeping strict
  defaults (`default-src 'none'`, explicit `script-src/style-src/img-src`,
  `frame-ancestors 'none'`, `base-uri 'none'`).

## [1.5.6] - 2026-05-07

### Fixed

- **Consent form CSP violation**: The "Allow access" button on the OAuth
  consent page was blocked by the `form-action 'self'` Content-Security-Policy
  directive when the page was delivered through a reverse proxy or CDN whose
  public origin differed from the configured `issuer_url`. Fixed by:
  1. Using an absolute form action (`{issuer_url}/consent`) so the POST always
     targets the canonical issuer endpoint regardless of delivery origin.
  2. Explicitly including the issuer URL in the CSP `form-action` directive
     (`form-action 'self' {issuer_url}`) for an unambiguous, auditable policy.

## [1.5.5] - 2026-05-06

- **Data epoch in consistency cookie**: The `__lid_cr` cookie (and
  `x-lid-consistency` header) now includes a `data_epoch` identifier from
  lattice-db. When NATS data is wiped or restored to an earlier point, the
  epoch changes and stale cookies are silently discarded instead of causing
  "stale replica" errors for users. Cookie format changed from
  `{"table":rev}` to `{"e":"<epoch>","r":{"table":rev}}` (legacy format
  without epoch is still accepted).

### Removed

- **Dead vault/encryption code**: Removed `vault.rs` (351 lines), encryption
  helpers in `store.rs` and `service_client.rs`, and `aes-gcm`/`hkdf` crate
  dependencies. Encryption now lives in lattice-db v1.9.0 (per-table opt-in).

## [1.5.4] - 2026-05-05

### Fixed

- **Login email lookup now uses HMAC key**: `get_user_by_email` was constructing
  the user-idx key as `email:{plaintext_email}` while registration stores it as
  `email:{hmac_email(email)}`. This caused all password logins to fail with
  "Invalid email or password" even for correctly registered accounts. The lookup
  now consistently applies `hmac_email` so it finds the same key that
  registration wrote.

## [1.5.3] - 2026-05-05

### Security

- **Fail-fast on missing KMS config**: `vault.rs` no longer falls back to a
  hardcoded development seed when `kms_endpoint` is absent. The component now
  panics at startup with a descriptive error unless either `kms_endpoint`
  (production) or `kms_dev_seed + dev_mode=true` (development) is explicitly
  configured. Using `kms_dev_seed` while `dev_mode=false` is also rejected so a
  misconfigured deployment cannot silently use a weak key.

- **HMAC-peppered email index**: All email-keyed KV entries
  (`email:{hash}` in the user-idx store) now use `HMAC-SHA256(lowercase_email,
  pepper)` as the key instead of the plaintext email address. The pepper is
  supplied via the `email_pepper` config key (32+ random bytes). Without the
  pepper, an attacker with NATS read access cannot enumerate or rainbow-table
  user emails. Deployments must set `email_pepper`; a warning is logged and
  operation continues without HMAC if the config key is absent so existing dev
  environments keep working. **Migration note**: existing records in
  `user-idx` use plaintext keys and will become unreachable after deploying this
  change; a one-time reindex or fresh deployment is required.

- **Hashed client secrets**: `OidcClient.client_secret` now stores
  `HMAC-SHA256(raw_secret, client_secret_pepper)` rather than the raw 32-byte
  hex value. The raw secret is returned exactly once at client creation. Token
  endpoint verification recomputes the HMAC before the constant-time compare.
  Configure via `client_secret_pepper`. Existing confidential clients must be
  rotated after deploying this change.

- **Rate-limit `/internal/lookup`**: Cross-region email-hash lookups are now
  limited to 60 requests per minute per source IP using the existing abuse
  protection component. Exceeding the limit returns `429 Too Many Requests`.
  This prevents an authenticated-but-malicious peer region from enumerating
  email hashes at high speed.

## [1.5.2] - 2026-05-04

### Fixed

- **Admin UI wasm-opt CI fix**: Trunk's bundled wasm-opt does not enable
  bulk-memory operations, causing a `wasm-validator` error on the `memory.copy`
  instructions emitted by Rust's `wasm32-unknown-unknown` target. `data-wasm-opt`
  is now set to `"0"` so Trunk skips its built-in pass; a dedicated CI step
  installs `binaryen` from apt and runs `wasm-opt --enable-bulk-memory -Oz`
  on the built wasm files before they are bundled into the host component.

## [1.5.1] - 2026-05-04

### Fixed

- **Admin UI SPA routing**: Added `base="/admin"` to the Leptos `<Router>` so
  all routes are correctly scoped under `/admin/`. Previously, navigating to e.g.
  `/admin/tenants` and refreshing would serve raw API JSON (or trigger the
  user-facing passkeys/account UI for conflicting paths). All sidebar `<A>` hrefs
  and in-view back-links updated to match.
- **Admin route prefix check**: Gateway handler now matches `/admin` exactly or
  `/admin/*`, preventing paths like `/administer` from being caught by the SPA
  fallback.
- **Admin asset cache-control**: Hashed-filename detection now requires the hash
  suffix to be exactly 16 lowercase hex digits (matching Trunk's actual output),
  avoiding a 1-year immutable cache for any file that merely has a hyphen in its
  name.
- **Admin UI wasm-opt**: Trunk's wasm-opt was explicitly disabled (`"0"`) in
  `index.html`; changed to `"z"` (optimize for size). Expected to reduce the wasm
  bundle significantly on next build.
- **Admin host MIME types**: Added `jpg/jpeg`, `gif`, `webp`, `ico`, `woff`,
  `woff2`, `txt`, and source maps (`.map`) to the content-type table. `text/html`
  and `text/css` now include `charset=utf-8`.

## [1.5.0] - 2026-05-03

### Changed

- **Removed satellite components**: `abuse-protection`, `key-manager`,
  `region-authority`, and `crypto-vault` are no longer separate crates. Their
  functionality has been consolidated into `oidc-gateway` (rate limiting, key
  management, region lookup, and encryption all run inline via TCP to lattice-db).
- **Co-located lattice-db service**: All deployment manifests now include
  lattice-db as a co-located service inside the WorkloadDeployment (TCP on
  `127.0.0.1:4080`). Separate `latticedb-{region}.yaml` manifests removed.
- **Workspace reduced**: From 7 crates to 3 (`oidc-gateway`, `password-hasher`,
  `email-worker`). `admin-ui` remains excluded (separate build).
- **CI publish**: Only builds and pushes `oidc-gateway`, `password-hasher`,
  `email-worker`, and `admin-ui-host`.

## [1.4.1] - 2026-05-02

### Fixed

- **TCP client EOF handling**: Fixed `drop(tx)` closing write stream before response
  was read, and added `Complete(0)` EOF detection to prevent infinite read loops in
  all five service clients (oidc-gateway, key-manager, abuse-protection,
  region-authority, crypto-vault).
- **Public endpoint performance**: JWKS, OpenID configuration, version, and healthz
  endpoints no longer make a rate-limit TCP call on every request.
- **CORS origin fast-path**: `allowed_origin()` checks issuer origin directly before
  calling `list_clients()`, avoiding N+1 TCP calls on every XHR response.
- Removed debug logging added during diagnosis.

## [1.4.0] - 2026-04-30

### Changed

- **Switched lattice-db communication from NATS to localhost TCP** — all
  components that talk to lattice-db now connect to `127.0.0.1:4080` (the
  co-located lattice-db service) via `wasi:sockets/types` instead of
  `wasmcloud:messaging/consumer` over NATS request/reply.
  - Wire protocol: 4-byte big-endian length prefix + JSON body with `_op` field.
  - Eliminates NATS round-trip overhead; reads hit the local cache via virtual
    pipes (sub-millisecond latency).
  - Updated components: oidc-gateway, key-manager, abuse-protection,
    region-authority, crypto-vault.
  - oidc-gateway retains NATS messaging for metrics publish.

## [1.3.2] - 2026-04-30

### Fixed

- **Double-login race condition** — submitting the login form twice (e.g. via
  double-click during the 2+ second bcrypt verification) could issue two
  separate authorization codes for the same session, causing downstream
  consistency errors.
  - **Backend:** `complete_login` now consumes the auth session atomically via
    a CAS delete (`consume_auth_session`). A concurrent second request finds the
    session already gone and receives a clear error rather than issuing a
    duplicate code.
  - **Frontend:** the Sign In and Verify (MFA) buttons are disabled and relabelled
    (*Signing in…* / *Verifying…*) immediately on form submit, preventing
    double-clicks from reaching the server at all.

## [1.3.1] - 2026-04-29

### Fixed

- **Admin UI OAuth client** — added `{issuer}/admin/callback` to the
  `lid-admin` redirect URIs so the admin SPA callback works when served
  under the `/admin` path.

## [1.3.0] - 2026-04-29

### Added

- **Session consistency tokens (lattice-db 1.6.0)** — all five components now
  track per-table revision watermarks within each request. Read operations
  inject `consistency.min_revision` and write responses update the map from
  `session.revisions`. This provides read-your-write guarantees even when NATS
  queue groups route successive requests to different lattice-db replicas.

- **Consistency propagation for browsers and API clients** — the oidc-gateway
  emits an `x-lid-consistency` response header and a `__lid_cr` HttpOnly cookie
  containing session revisions JSON. Inbound requests seed the consistency
  context from the header (preferred, for API clients) or cookie (automatic for
  browsers). Backward compatible: missing context falls back to eventual reads.

- **CORS headers updated** — `x-lid-consistency` added to
  `access-control-allow-headers` and `access-control-expose-headers`.

- **New integration test** `tests/integration_consistency.sh` — verifies
  header/cookie emission, round-trip, and backward compatibility.

### Changed

- **Deploy scripts pin lattice-db to `v1.6.0`** — `LATTICE_DB_IMAGE` default
  updated from `:v1.5.0` to `:v1.6.0` in `deploy-local.sh` and
  `deploy-two-region.sh`.

- **lattice-db workload manifests** — added `LDB_CONSISTENCY_WATCHER_WAIT_STEPS`
  and `LDB_CONSISTENCY_WATCHER_WAIT_STEP_SECS` environment variables (defaults:
  `2` and `1`) to `latticedb-eu.yaml`, `latticedb-us.yaml`, `deploy-local.sh`,
  and `deploy-two-region.sh`.

### Fixed

- **crypto-vault** — `ldb.set` corrected to `ldb.put` to match the documented
  lattice-db protocol.

## [1.2.1] - 2026-04-29

### Fixed

- **Bootstrap now creates the `lid-admin` OAuth client** — when the first
  superadmin is promoted via the bootstrap hook, the gateway ensures the
  `lid-admin` client exists so the admin UI can log in immediately. Previously
  the client was only created lazily in dev mode, which meant production
  deployments required an extra request before the admin UI worked.

### Removed

- `kv_prefix` config key from `workloaddeployment-local-prod.yaml` — this
  leftover key was removed for consistency with the 1.2.0 migration.

## [1.2.0] - 2026-04-23

### Changed

- **Migrated to lattice-db 1.2.0** — replaced the old per-request `_partition` /
  `ldb_tenant` scheme with lattice-db's new `LDB_INSTANCE` deploy-time isolation.
  All five components (`oidc-gateway`, `key-manager`, `abuse-protection`,
  `crypto-vault`, `region-authority`) no longer inject `"_partition"` into every
  request; isolation is now fully handled by the storage-service with
  `LDB_INSTANCE=lid` set in its deployment manifest.

- **Configurable lattice-db instance prefix** (`ldb_instance` config key) — the
  NATS subject prefix used by all components when communicating with lattice-db
  is now read from the `ldb_instance` wasmCloud config value (defaults to
  `"lid"`). This must match the `LDB_INSTANCE` environment variable set on the
  lattice-db storage-service. All deployment manifests set `ldb_instance: "lid"`
  explicitly.

- **Deploy scripts pin lattice-db to `v1.2.0`** — `LATTICE_DB_IMAGE` default
  updated from `:latest` to `:v1.2.0` in `deploy-local.sh` and
  `deploy-two-region.sh`.

### Removed

- `ldb_tenant` config key — replaced by `ldb_instance` / `LDB_INSTANCE`.
- `kv_prefix` config key from `oidc-gateway` and satellite components — KV
  bucket names are now derived entirely from `LDB_INSTANCE` on the server side.
  The `kv_prefix` key in `crypto-vault` and two-region EU/US manifests is also
  removed.

## [1.1.0] - 2026-04-22

### Added

- **`create_tenant(id, name, display_name)` Rhai function** available in all
  hook scripts (bootstrap hook, `post-registration`, `post-login`).  
  Allows the bootstrap hook to create the first tenant and enroll the founding
  user in a single script, without requiring a separate API call after
  bootstrapping:

  ```rhai
  if user.email == "founder@acme.com" {
      set_superadmin(true);
      create_tenant("acme", "acme", "Acme Inc.");
      add_to_tenant("acme", "owner");
      log("Bootstrap: created acme tenant + promoted owner");
  }
  ```

  The function validates the tenant id at call time (lowercase alphanumeric,
  internal hyphens allowed, 2–63 chars, no leading/trailing hyphen) and is
  idempotent — if the tenant already exists the call is silently skipped, so
  hooks are safe to re-run. Tenant creation is applied *before*
  `add_to_tenant` memberships within the same outcome, so create + join works
  atomically in a single hook invocation. Each creation is recorded as a
  `hook_create_tenant` audit event.

## [1.0.0] - 2026-04-22

### Added

- Initial release — NATS-native OIDC identity provider for wasmCloud.
- Rhai scripting hooks (`post-login`, `post-registration`, bootstrap hook)
  with `set_superadmin`, `add_to_tenant`, `set_claim`, `deny`, and `log`.
- Multi-region active-active deployment via wasmCloud.
- Admin UI (Leptos/WASM) for user, tenant, hook, and OIDC client management.
- WebAuthn / passkey, TOTP, and password authentication.
- RFC 8628 Device Authorization Grant.
- Abuse-protection and rate-limiting component.
- Crypto-vault component for key management.

[1.2.1]: https://github.com/Taika-3D-Oy/lattice-id/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Taika-3D-Oy/lattice-id/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Taika-3D-Oy/lattice-id/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Taika-3D-Oy/lattice-id/releases/tag/v1.0.0
