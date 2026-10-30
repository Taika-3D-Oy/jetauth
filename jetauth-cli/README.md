# JetAuth CLI

`jetauth` is a native command-line client for the JetAuth Management API. It uses the built-in `lid-admin` public OIDC client and the OAuth 2.0 Device Authorization Grant, so passwords, SSO, and MFA stay in the browser.

## Build and install

Install a published release from crates.io:

```bash
cargo install jetauth-cli --locked
```

Tagged releases also provide prebuilt Linux, macOS, and Windows binaries. To build from this repository instead:

```bash
cargo build -p jetauth-cli --release
cargo install --path jetauth-cli
```

The binary is written to `target/release/jetauth` by the build command. Source builds on Debian/Ubuntu require the D-Bus development package for Linux Secret Service support: `sudo apt-get install libdbus-1-dev`.

## Sign in

```bash
jetauth login --issuer https://auth.example.com
```

Open the displayed URL and confirm the verification code. The CLI polls JetAuth, stores the resulting tokens, and refreshes them when needed. Use `--no-browser` when working over SSH or on a headless machine.

```bash
jetauth login --issuer https://auth.example.com --no-browser
jetauth login --issuer http://localhost:8000 --profile dev
jetauth --profile dev status
jetauth token
```

Login requests `offline_access` by default and stores the rotating refresh token. Use `--no-refresh` to keep only the one-hour access token. Logout removes local credentials:

```bash
jetauth logout
```

HTTPS is required except for loopback development addresses.

## Management commands

```bash
jetauth clients list
jetauth clients get CLIENT_ID
jetauth clients create --input client.json
jetauth clients update CLIENT_ID --input changes.json
jetauth clients rotate-secret CLIENT_ID

jetauth tenants list
jetauth tenants members TENANT_ID
jetauth tenants invite TENANT_ID --email user@example.com --role admin

jetauth users list --query alice --limit 100
jetauth users activate USER_ID
jetauth users reset-password USER_ID
jetauth users export USER_ID

jetauth idps list
jetauth hooks list
jetauth hooks test HOOK_ID
jetauth keys list
jetauth keys rotate
jetauth settings get
jetauth settings update --input settings.json
jetauth audit list --event-type client_created --since 1775630000
jetauth stats
```

Every Management API operation is also available through the raw API command:

```bash
jetauth api GET /api/stats
jetauth api POST /api/clients --input client.json
cat changes.json | jetauth api PATCH /api/tenants/TENANT_ID --input -
```

Raw paths must begin with `/api/`; the CLI will not send the management token to an arbitrary URL.

Destructive commands ask for confirmation. Automation must pass `--yes`; `--no-input` disables all interactive input.

## Output

Interactive output defaults to tables, while redirected output defaults to JSON. Select a format explicitly with:

```bash
jetauth clients list --output table
jetauth clients list --output json | jq -r '.[].client_id'
```

API responses retain their original JSON field names. Diagnostics are written to stderr. `jetauth token` writes only the token to stdout.

## Profiles and credentials

```bash
jetauth login --issuer https://auth.prod.example.com --profile prod
jetauth login --issuer http://localhost:8000 --profile dev
jetauth config list
jetauth config use prod
jetauth --profile dev clients list
```

Configuration contains no tokens and is stored in the platform configuration directory. Set `JETAUTH_CONFIG_DIR` to override its location.

Credentials use the OS keyring by default: macOS Keychain, Windows Credential Manager, or Linux Secret Service. If the keyring is unavailable, automatic mode warns and uses a `0600` credentials file. Choose a backend explicitly at login:

```bash
jetauth login --issuer https://auth.example.com --credential-store keyring
jetauth login --issuer https://auth.example.com --credential-store file
```

For CI, skip profiles and stored credentials with environment variables:

```bash
export JETAUTH_ISSUER=https://auth.example.com
export JETAUTH_ACCESS_TOKEN='...'
jetauth clients list
```

`JETAUTH_PROFILE` and `JETAUTH_ISSUER` can also select the profile and issuer for normal commands. Do not put access tokens in command-line arguments.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Management API or server error |
| 2 | Invalid input or configuration |
| 3 | Authentication required or failed |
| 4 | Permission denied |
| 5 | Resource not found |
| 6 | Resource conflict |
| 7 | Network or discovery failure |

## Development

```bash
cargo test -p jetauth-cli
cargo clippy -p jetauth-cli --all-targets -- -D warnings
```

Integration tests execute the real binary against a local mock OIDC and Management API server; no cluster or real credentials are required.
