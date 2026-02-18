# Bananauth

Identity and authentication service with native and OAuth support, JWT sessions, and account linking.

From [BananaLabs OSS](https://github.com/bananalabs-oss).

## Overview

Bananauth handles:

- **Native Auth**: Email/password registration and login
- **OAuth**: Discord login and account creation
- **Sessions**: JWT tokens with in-memory session tracking and revocation
- **Password Management**: Change password, forgot/reset via OTP
- **Account Lifecycle**: Registration, deletion, and session validation
- **Profiles**: Display name management for platform identity

## Quick Start

```bash
JWT_SECRET=your-secret-here go run ./cmd/server
```

## Configuration

Configuration priority: CLI flags > Environment variables > Defaults

| Setting               | Env Var                       | CLI Flag                       | Default                 |
| --------------------- | ----------------------------- | ------------------------------ | ----------------------- |
| Host                  | `HOST`                        | `-host`                        | `0.0.0.0`               |
| Port                  | `PORT`                        | `-port`                        | `8001`                  |
| Database URL          | `DATABASE_URL`                | `-database-url`                | `sqlite://bananauth.db` |
| JWT Secret            | `JWT_SECRET`                  | `-jwt-secret`                  | _(required)_            |
| Token Expiry          | `TOKEN_EXPIRY`                | `-token-expiry`                | `1440` (minutes)        |
| Discord Client ID     | `OAUTH_DISCORD_CLIENT_ID`     | `-oauth-discord-client-id`     | _(optional)_            |
| Discord Client Secret | `OAUTH_DISCORD_CLIENT_SECRET` | `-oauth-discord-client-secret` | _(optional)_            |
| Discord Redirect URL  | `OAUTH_DISCORD_REDIRECT_URL`  | `-oauth-discord-redirect-url`  | _(optional)_            |

Discord OAuth is enabled automatically when client ID and secret are provided.

**CLI:**

```bash
./bananauth -jwt-secret my-secret -port 8001
```

**Docker Compose:**

```yaml
bananauth:
  image: ghcr.io/bananalabs-oss/bananauth:latest
  ports:
    - "8001:8001"
  volumes:
    - ./data:/app/data
  environment:
    - JWT_SECRET=your-secret-here
    - DATABASE_URL=sqlite:///app/data/bananauth.db
    - OAUTH_DISCORD_CLIENT_ID=your-client-id
    - OAUTH_DISCORD_CLIENT_SECRET=your-client-secret
    - OAUTH_DISCORD_REDIRECT_URL=https://your-domain/auth/oauth/discord/callback
```

## API Reference

### Public Endpoints

| Method | Endpoint                       | Description                        |
| ------ | ------------------------------ | ---------------------------------- |
| `GET`  | `/health`                      | Health check                       |
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
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"player1","password":"securepass"}'
```

```json
{ "access_token": "eyJ...", "expires_in": 86400, "account_id": "uuid" }
```

### Login

```bash
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass"}'
```

```json
{ "access_token": "eyJ...", "expires_in": 86400, "account_id": "uuid" }
```

### Validate Session

```bash
curl http://localhost:8001/auth/session \
  -H "Authorization: Bearer <token>"
```

```json
{ "account_id": "uuid", "valid": true }
```

### Password Reset

```bash
# Request reset code (logged to console if no email configured)
curl -X POST http://localhost:8001/auth/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'

# Reset with code
curl -X POST http://localhost:8001/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{"code":"ABC123","new_password":"newsecurepass"}'
```

### Delete Account

```bash
curl -X DELETE http://localhost:8001/auth/account \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"password":"securepass"}'
```

### Create Profile

```bash
curl -X POST http://localhost:8001/profiles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"PlayerOne"}'
```

```json
{
  "account_id": "uuid",
  "display_name": "PlayerOne",
  "created_at": "...",
  "updated_at": "..."
}
```

### Get Profile

```bash
curl http://localhost:8001/profiles/<account_id>
```

### Update Profile

```bash
curl -X PUT http://localhost:8001/profiles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"NewName"}'
```

## Database

Bananauth uses SQLite by default. Tables:

- `auth_accounts` — Identity records
- `auth_native` — Email/password credentials
- `auth_oauth` — OAuth provider links
- `auth_otp_codes` — Password reset codes
- `profiles` — User display names

Tables are auto-created on startup.

## Architecture

```
Client → Bananauth API → SQLite
           ↓
         JWT Token
           ↓
    Other services validate
    via /auth/session
```

Other services in your stack call `/auth/session` with the bearer token to verify identity. No shared database required.

## License

MIT
