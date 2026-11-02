# SAML 2.0 and SCIM 2.0

JetAuth can act as a SAML 2.0 identity provider for downstream applications and as an inbound SCIM 2.0 server for user provisioning. Both protocol surfaces are disabled by default.

Enable them explicitly in the gateway configuration:

```yaml
saml_enabled: "true"
scim_enabled: "true"
```

The local development manifest enables both for integration testing. The features use `saml-rs` for SAML message construction, XML canonicalization, and signatures. No native XML or OpenSSL libraries are required.

## SAML identity provider

### Supported profile

- SP-initiated Web Browser SSO
- HTTP-Redirect and HTTP-POST AuthnRequests
- HTTP-POST responses with RSA-SHA256 signed assertions
- Email-address and persistent NameID formats
- Existing JetAuth browser SSO, password, passkey, upstream OIDC, MFA, and post-login hooks
- `ForceAuthn`, passive-request rejection when interaction would be required, exact ACS allow-listing, request age checks, and request/flow replay protection
- Dedicated signing certificate with a 30-day previous-certificate overlap after rotation

SAML Single Logout, IdP-initiated SSO, encrypted assertions, and artifact/SOAP profiles are not currently supported.

### Endpoints

- Metadata: `GET /saml/metadata`
- SSO: `GET|POST /saml/sso`

The IdP entity ID is `<issuer>/saml/metadata`. The signing certificate is available in the metadata. Rotate it with `POST /api/saml-signing-key/rotate` or `jetauth saml rotate-key`; distribute the new metadata to service providers during the overlap period.

### Register an application

SAML applications are distinct from OIDC clients and upstream identity providers. Use **Admin → SAML Applications**, the Management API, or the CLI:

```json
{
  "name": "Example portal",
  "entity_id": "https://portal.example.com/saml/metadata",
  "acs_urls": ["https://portal.example.com/saml/acs"],
  "name_id_format": "email",
  "attribute_mappings": [
    ["email", "email"],
    ["displayName", "name"],
    ["groups", "roles"]
  ]
}
```

```bash
jetauth saml create --input saml-application.json
jetauth saml list
```

Attribute sources are `email`, `name`, `user_id`, `tenant_id`, `role`, and `roles`. `tenant_id` and `role` use the first membership; `roles` is a comma-separated list of `tenant:role` pairs. No arbitrary user fields or hook values are exposed.

If the SP signs AuthnRequests, put its PEM signing certificate in `request_signing_certificate`. JetAuth verifies signatures when present; metadata created from a configured certificate also marks requests as signed. ACS URLs must use HTTPS except in development mode.

## SCIM provisioning

### Supported API

- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/ResourceTypes` and `/ResourceTypes/User`
- `GET /scim/v2/Schemas` and the core User schema
- `GET|POST /scim/v2/Users`
- `GET|PUT|PATCH|DELETE /scim/v2/Users/{id}`
- Bearer authentication, ETags/`If-Match`, `userName`, `externalId`, and `id` equality filters, and `startIndex`/`count` pagination

SCIM Groups, bulk requests, sorting, and password changes are not supported. Unsupported capabilities are marked disabled in `ServiceProviderConfig`.

### Create a connection

Use **Admin → SCIM Provisioning**, the Management API, or:

```json
{
  "name": "Corporate directory",
  "tenant_id": "tenant_example",
  "default_role": "member"
}
```

```bash
jetauth scim create --input scim-connection.json
```

The response contains `token` exactly once. Configure the client with:

- Base URL: `<issuer>/scim/v2`
- Header: `Authorization: Bearer <token>`

Tokens are stored only as SHA-256 hashes. Rotate a token with `jetauth scim rotate-token CONNECTION_ID` and update the directory client immediately. A connection can only manage users it provisioned, and only within its configured tenant. Default roles cannot be `owner`; SCIM can never modify a superadmin.

### User mapping and lifecycle

- `userName` maps to JetAuth email and must be unique globally.
- `externalId` is required, immutable, and unique within a connection.
- `name.formatted` maps to display name.
- `active` maps to account status.
- New users receive a membership with the connection's default role and no usable local password. They can authenticate through an upstream identity provider or complete a separately configured password setup flow.
- `active: false` disables login and revokes browser sessions and refresh tokens.
- `DELETE` permanently deletes a user only when that user is owned by the requesting connection.
- Existing local accounts are not automatically adopted. Create returns `409 Conflict` when the email already exists.

Example create request:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "person@example.com",
  "externalId": "directory-user-123",
  "name": { "formatted": "Example Person" },
  "active": true
}
```

Example deactivation:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{ "op": "replace", "path": "active", "value": false }]
}
```

Use the returned `ETag` in `If-Match` on subsequent updates to prevent lost writes. Management actions and provisioning changes are written to the audit log; bearer tokens are never logged.

## Multi-region operation

SAML application and SCIM connection configuration replicates through the existing internal configuration channel. SCIM token hashes are replicated so the same connection token works in each region; raw tokens are never included in configuration exports. SAML signing keys remain region-specific, like OIDC signing keys, so each region's metadata must be distributed with its own issuer and certificate.

A provisioned user and its SCIM identity link are owned by the region that accepted the create request, consistent with JetAuth's regional user model. Configure each directory client with a stable regional SCIM endpoint for subsequent updates and deletes. Connection configuration replication does not turn a user into a second regional copy.
