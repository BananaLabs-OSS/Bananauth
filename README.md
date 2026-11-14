# Bananauth

Identity and authentication service — email/password + Discord OAuth, JWT sessions with revocation, and user profiles. Ships as a [Pulp](https://github.com/BananaLabs-OSS/Pulp) WASM cell.

From [BananaLabs OSS](https://github.com/bananalabs-oss).

## Overview

Bananauth handles:

- **Native Auth**: Email/password registration and login
- **OAuth**: Discord login and account creation
- **Sessions**: JWT tokens with in-memory session revocation
- **Password Management**: Change password, forgot/reset via OTP (Resend)
- **Account Lifecycle**: Registration, deletion, and session validation
- **Profiles**: Display name management for platform identity

## Repository layout

```
pkg/authcrypto/   Pure-Go crypto shared between cell and future consumers
                  (GenerateOTP, GenerateState, MintJWT)
pulp-cell/        WASM cell source — builds to bananauth.wasm (wasip1/wasm)
  otpscope/       Pure-Go subpackage: OTP match predicate + regression tests
  pulp.cell.toml  Cell manifest (capabilities + default config)
pulp-deployment/  Standalone Pulp host that loads the cell
Dockerfile.pulp   Multi-stage Docker image (build context = GolandProjects/)
docker-entrypoint.sh  Injects JWT_SECRET into manifest at container start
```

## Quick Start (standalone container)

Build context is the **parent directory** of this repo (modules use local `replace` directives):

```bash
cd /path/to/GolandProjects
docker build -f Bananauth/Dockerfile.pulp -t bananauth:latest .
docker run -e JWT_SECRET=your-secret-here -p 3000:3000 bananauth:latest
```

## Configuration

All config is in `pulp-cell/pulp.cell.toml` (`[config]` section). The entrypoint script injects `JWT_SECRET` from the environment at container start; everything else can be set directly in the manifest.

| Key                    | Default                          | Notes                                     |
| ---------------------- | -------------------------------- | ----------------------------------------- |
| `jwt_secret`           | _(required — placeholder fails)_ | Injected via `JWT_SECRET` env var         |
| `token_expiry_minutes` | `1440` (24 h)                    |                                           |
| `auth_methods`         | `["password","discord"]`         | Drop `"discord"` if OAuth not configured  |
| `discord_client_id`    | `""`                             | Discord OAuth app credential              |
| `discord_client_secret`| `""`                             | Discord OAuth app credential              |
| `discord_redirect_url` | `""`                             | Must match Discord app settings           |
| `resend_api_key`       | `""`                             | Leave blank to log OTP to stdout (dev)    |
| `resend_from`          | `"no-reply@example.com"`         |                                           |

**Container environment variables** (injected by `docker-entrypoint.sh`):

| Variable     | Required | Notes                                         |
| ------------ | -------- | --------------------------------------------- |
| `JWT_SECRET` | yes      | Shared HS256 secret; must match other services|
| `HTTP_PORT`  | no       | Default `3000`                                |

## API Reference

### Public Endpoints

| Method | Endpoint                       | Description                        |
| ------ | ------------------------------ | ---------------------------------- |
| `GET`  | `/health`                      | Health check                       |
| `GET`  | `/auth/config`                 | Enabled login methods              |
| `POST` | `/auth/register`               | Create account with email/password |
| `POST` | `/auth/login`                  | Login with email/password          |
| `POST` | `/auth/password/forgot`        | Request password reset OTP         |
| `POST` | `/auth/password/reset`         | Reset password with OTP code       |
| `GET`  | `/auth/oauth/discord`          | Begin Discord OAuth flow           |
| `GET`  | `/auth/oauth/discord/callback` | Discord OAuth callback             |
| `GET`  | `/profiles/:id`                | Get user profile by account ID     |

### Protected Endpoints (requires `Authorization: Bearer <token>`)

| Method   | Endpoint         | Description                       |
| -------- | ---------------- | --------------------------------- |
| `GET`    | `/auth/session`  | Validate token and get account ID |
| `POST`   | `/auth/logout`   | Revoke current session            |
| `POST`   | `/auth/password` | Change password                   |
| `DELETE` | `/auth/account`  | Delete account                    |
| `POST`   | `/profiles`      | Create profile                    |
| `PUT`    | `/profiles`      | Update profile                    |

### Register

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"player1","password":"securepass"}'
```

```json
{ "access_token": "eyJ...", "expires_in": 86400, "account_id": "uuid" }
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass"}'
```

```json
{ "access_token": "eyJ...", "expires_in": 86400, "account_id": "uuid" }
```

### Validate Session

```bash
curl http://localhost:3000/auth/session \
  -H "Authorization: Bearer <token>"
```

```json
{ "account_id": "uuid", "valid": true }
```

### Password Reset

```bash
# 1. Request a reset code
curl -X POST http://localhost:3000/auth/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'

# 2. Reset with the code (email field is required — scopes the code to your account)
curl -X POST http://localhost:3000/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","code":"ABC123","new_password":"newsecurepass"}'
```

### Delete Account

```bash
# Native account — provide password
curl -X DELETE http://localhost:3000/auth/account \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"password":"securepass"}'

# OAuth-only account — provide the provider email instead
curl -X DELETE http://localhost:3000/auth/account \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'
```

### Create / Update Profile

```bash
curl -X POST http://localhost:3000/profiles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"PlayerOne"}'

curl -X PUT http://localhost:3000/profiles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"NewName"}'
```

### Get Profile

```bash
curl http://localhost:3000/profiles/<account_id>
```

## Database

SQLite via the Pulp `storage.sqlite` capability (mounted by the host). Tables are created on first boot:

- `auth_accounts` — Identity records
- `auth_native` — Email/password credentials
- `auth_oauth` — OAuth provider links
- `auth_otp_codes` — Password reset codes (10-minute expiry)
- `profiles` — User display names

## Building the cell locally

```bash
cd pulp-cell
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o bananauth.wasm .
```

## License

MIT

## Standalone Go candidate

Build the candidate with `go build -o bananauth ./cmd/server` or use
`Dockerfile.native` for port 3000. Set `BANANAUTH_IDENTITY_DB` and
`BANANAUTH_SESSION_DB` to the corresponding SQLite files or PostgreSQL
connection URLs. For PostgreSQL, preserve the schema selection used by each
owner in its connection URL. For SQLite, rehearse against consistent copies
of the two existing owner files before opening deployed data.

Keep the current `JWT_SECRET` and OTP keyring for a handoff so existing
session tokens and encrypted delivery intents can still be read. The native
service reads `BANANAUTH_OTP_KEY_CURRENT` and `BANANAUTH_OTP_KEY_PREVIOUS`
and accepts the existing `BANANAAUTH_OTP_KEY_CURRENT` and
`BANANAAUTH_OTP_KEY_PREVIOUS` aliases. The Discord settings also accept
the previous `PULP_OAUTH_DISCORD_*` names. Configure `LISTEN_ADDR` when
running the binary directly to select the listener.

For a Sessions handoff, set `BANANAUTH_VERIFICATION_REPLAY_KEY` to the
legacy backend's verification request key (its internal service secret).
This allows an unexpired V2 consume receipt written before the handoff to
replay on native Bananauth. Fresh installations default to the signing key.

Exercise registration, profile reads, session validation after restart,
logout, and email and Discord flows against the candidate. Keep
`OUTBOUND_DELIVERY_ENABLED` off in a rehearsal using copied data, and
enable delivery on the replacement only after stopping the previous worker.
To restrict verification mail to test inboxes, set
`SESSIONS_TRANSACTIONAL_TEST_RECIPIENTS` to a comma-separated list of bare
addresses. Set `SESSIONS_TRANSACTIONAL_TEST_RECIPIENTS_REQUIRED=true` to
require the list whenever outbound delivery is enabled. Mail for other
recipients stays in the outbox until it expires or the restriction changes.
