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

MANIFEST=/app/cell/pulp.cell.toml
sed -i "s#^jwt_secret = .*#jwt_secret = \"${JWT_SECRET}\"#" "$MANIFEST"

# Optional extra secrets (only if provided):
# [ -n "$DISCORD_CLIENT_ID" ]     && sed -i "s#^discord_client_id = .*#discord_client_id = \"${DISCORD_CLIENT_ID}\"#" "$MANIFEST"
# [ -n "$DISCORD_CLIENT_SECRET" ] && sed -i "s#^discord_client_secret = .*#discord_client_secret = \"${DISCORD_CLIENT_SECRET}\"#" "$MANIFEST"
# [ -n "$RESEND_API_KEY" ]        && sed -i "s#^resend_api_key = .*#resend_api_key = \"${RESEND_API_KEY}\"#" "$MANIFEST"

exec /app/bananauth-host -manifest "$MANIFEST"
