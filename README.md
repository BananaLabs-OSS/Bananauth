# Bananauth

Identity and authentication service — email/password + Discord OAuth, JWT sessions with revocation, and user profiles. Runs as a standalone Go HTTP service.

From [BananaLabs OSS](https://github.com/bananalabs-oss).

## Overview

Bananauth handles:

- **Native Auth**: Email/password registration and login
- **OAuth**: Discord login and account creation
- **Sessions**: JWT tokens with persistent session revocation
- **Password Management**: Change password, forgot/reset via OTP (Resend)
- **Account Lifecycle**: Registration, deletion, and session validation
- **Profiles**: Display name management for platform identity

## Run locally

```sh
go build -o /tmp/bananauth ./cmd/server
BANANAUTH_IDENTITY_DB=/tmp/bananauth-identity.db \
BANANAUTH_SESSION_DB=/tmp/bananauth-session.db \
BANANAUTH_OTP_KEY_CURRENT="$(openssl rand -hex 32)" \
JWT_SECRET="$(openssl rand -hex 32)" \
LISTEN_ADDR=127.0.0.1:3000 /tmp/bananauth
```

Reuse the same keys after restart to preserve sessions and pending verification.
The default listener is `127.0.0.1:8080`. Build the container with
`docker build -t bananauth .`.

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
| `GET`    | `/auth/session`  | Validate token and get account ID, username, and display name |
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

## Configuration and storage

Set `BANANAUTH_IDENTITY_DB` and
`BANANAUTH_SESSION_DB` to the corresponding SQLite files or PostgreSQL
connection URLs. For PostgreSQL, preserve the schema selection used by each
owner in its connection URL. For SQLite, rehearse against consistent copies
of the two existing owner files before opening deployed data.

Preserve the OTP keyring for existing encrypted delivery data. The only accepted
key settings are `BANANAUTH_OTP_KEY_CURRENT` and `BANANAUTH_OTP_KEY_PREVIOUS`.
Discord uses `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, and `DISCORD_REDIRECT_URL`.
Configure `LISTEN_ADDR` to select the listener.

JWTs now use the canonical issuer `bananauth`, with strict issuer, audience, expiry,
and signing-method verification. Tokens with the previous issuer are rejected;
a future authorized cutover requires those clients to log in again. No deployment
or user-session change has been performed by this local refactor.

For a Sessions handoff, set `BANANAUTH_VERIFICATION_REPLAY_KEY` to the
legacy backend's verification request key (its internal service secret).
This allows an unexpired V2 consume receipt written before the handoff to
replay on native Bananauth. Fresh installations default to the signing key.

When serving through a reverse proxy, set `BANANAUTH_TRUSTED_PROXY_CIDRS` to
the comma-separated addresses or subnets of proxies that append the actual
peer address to `X-Forwarded-For`. Verification and password reset limits
then use the first untrusted address from the right of the forwarded chain.
Leave this unset for direct listeners.

Exercise registration, profile reads, session validation after restart,
logout, and email and Discord flows against the service. Keep
`OUTBOUND_DELIVERY_ENABLED` off in a rehearsal using copied data, and
enable delivery on the replacement only after stopping the previous worker.
To restrict verification mail to test inboxes, set
`SESSIONS_TRANSACTIONAL_TEST_RECIPIENTS` to a comma-separated list of bare
addresses. Set `SESSIONS_TRANSACTIONAL_TEST_RECIPIENTS_REQUIRED=true` to
require the list whenever outbound delivery is enabled. Mail for other
recipients stays in the outbox until it expires or the restriction changes.

## License

MIT

## Offline identity import

The native owner can import an explicit legacy identity export without starting
HTTP, OAuth, or outbound email workers:

```sh
go build -o /tmp/bananauth-import ./cmd/import-legacy
BANANAUTH_OTP_KEY_CURRENT="$BANANAUTH_OTP_KEY_CURRENT" \
  /tmp/bananauth-import -input /private/identity-export.json \
  -database /private/rehearsal-identity.db
```

Use a consistent offline export and an isolated destination first. The JSON
object uses `request_id`, `accounts`, `native`, `oauth_links`, `otps`, and
`profiles`. Field names match the owner's import contract: accounts use
`account_id`, `email`, `username`, `created_at`; native credentials use `id`,
`account_id`, `email`, `username`, `password_hash`, `created_at`; OAuth links use
`id`, `account_id`, `provider`, `provider_id`, `provider_email`, `created_at`;
OTPs use `id`, `email`, `code`, `type`, `expires_at`, `account_id`; profiles use
`account_id`, `display_name`, `created_at`, `updated_at`. Timestamps are exact
integer Unix milliseconds. Preserve password hashes without rehashing. Treat the
export as secret material and use private file permissions.

Choose a stable `request_id` and retain the exact original export. Import is an
atomic owner command: conflicting identities fail, and retrying the same command
replays its receipt without reverting later account changes. The command rejects
unknown fields, fractional timestamps, trailing documents, and oversized input.
Its output contains only the request ID and imported counts. The OTP key must
match the destination server. Session-owner state, existing delivery/effect
journals, and pending workflow receipts require their own consistent backups;
this account import does not migrate them. Never point the importer at an active
writer during a cutover rehearsal.

## Offline encrypted-notification store conversion

Historical database conversion is maintained separately from the active service.
Use the preserved `bananauth-offline-converter-source` archive when migrating an
older installation; fresh installs require no conversion. The local archive is
`~/.codex/archives/bananakit-retired-source-20261121/bananauth-offline-converter-source`.
From its standalone module root, rehearse against private copies only:

```sh
go test -mod=readonly ./cmd/migrate-store ./internal/migration
go run -mod=readonly ./cmd/migrate-store -source /private/old-copy.db -target /private/new-native.db
```

For a PostgreSQL rehearsal, restore into an isolated cluster with a Unix
socket and create a separate empty destination database in that cluster.
The command copies identity history only. Keep the restored session store
available separately for the native startup check.

```sh
BANANAUTH_MIGRATION_SOURCE='postgresql:///restored?host=/private/rehearsal&port=55477' \
BANANAUTH_MIGRATION_TARGET='postgresql:///native?host=/private/rehearsal&port=55477' \
go run -mod=readonly ./cmd/migrate-store -postgres
```

The source transaction is read-only. The destination publishes command
history and the identity head atomically. An unsupported legacy payload
requires explicit reconciliation before conversion can finish. To archive the
recognized historical email format, add `-archive-key-file /private/archive.key`
with a fresh, private key for that conversion. Retain the key separately
from the destination database and keep it out of the running server.
This option refuses any archived notification that still exists in the
current identity snapshot.

This converter is an offline operator tool and is never loaded by the server.

The runtime rejects historical notification records until this conversion completes.
Ciphertext, authenticated message IDs, idempotency keys, account credentials, and
outstanding leases remain intact. Old framework headers are not runtime aliases.
A live unbound generic verification fails closed for explicit offline reconciliation.
Only synthetic fixture conversion is currently qualified; this is not proof of a
production authentication snapshot or permission to activate delivery.
