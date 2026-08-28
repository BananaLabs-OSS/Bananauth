#!/bin/sh
# Bananauth container entrypoint.
#
# Injects the shared HS256 secret into the cell manifest at start (the Pulp host
# does not forward OS env into WASM cells, so the secret reaches the cell via
# the manifest config). JWT_SECRET MUST match the bananadoro deployment so the
# tokens bananauth issues verify there.
#
# Discord OAuth and Resend (password-reset email) are left to the committed
# manifest blanks by default — uncomment the lines below to inject them too.
set -e

: "${JWT_SECRET:?set JWT_SECRET (shared HS256 secret with bananadoro)}"
export HTTP_PORT="${HTTP_PORT:-3000}"
export PULP_JWT_HS256_SECRET="$JWT_SECRET"
APP_MANIFEST=/app/Bananauth/application/pulp.app.toml
export PULP_OAUTH_DISCORD_CLIENT_ID="${PULP_OAUTH_DISCORD_CLIENT_ID:-${DISCORD_CLIENT_ID:-}}"
export PULP_OAUTH_DISCORD_CLIENT_SECRET="${PULP_OAUTH_DISCORD_CLIENT_SECRET:-${DISCORD_CLIENT_SECRET:-}}"
export PULP_OAUTH_DISCORD_REDIRECT_URL="${PULP_OAUTH_DISCORD_REDIRECT_URL:-${DISCORD_REDIRECT_URL:-}}"

exec /app/bananauth-host -app "$APP_MANIFEST"
