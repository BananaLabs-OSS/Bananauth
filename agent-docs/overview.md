# Bananauth package map

- `cmd/server`: HTTP startup and canonical public/private handlers.
- `internal/identity`: typed account, credential, OTP, retention, and notification commands; SQL CAS receipts.
- `internal/session`: typed durable sessions with revocation and immutable verification proof.
- `internal/browser`: in-process verified-session orchestration and live principal resolution.
- `internal/notification`: application-owned encrypted messages and fenced delivery leases.
- `internal/storage` and `internal/sqlitecompat`: ordinary database/sql connections and bounded SQL dialect adaptation.
- `internal/token`: canonical application JWT signing and verification.
- `cmd/import-legacy`: explicit offline JSON account/credential import through the typed identity service.

The HTTP server never loads the historical provider protocol or the offline converter.
Historical sources and original dirty/untracked bytes are preserved outside Projects
in `~/.local/state/sessions-go-migration/reference-20261118/bananauth` with SHA256 inventory.
Retired runtime data was moved opaquely to a separate private directory; it was not
read, hashed, imported, or treated as authoritative production data.
