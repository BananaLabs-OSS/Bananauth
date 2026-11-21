# Canonical authentication API

Public JSON routes are `POST /auth/email-verification`,
`POST /auth/email-verification/consume`, and
`POST /auth/email-verification/session`. Login is the default intent; signup is
explicit. Unknown-account login never creates an account. Existing request IDs,
intent-bound durable keys, and strict OTP/session replay rules remain unchanged.
The retired versioned public routes and private completion alias return404.

## Private JSON services

All private requests require the separately configured service bearer credential.
They accept one bounded JSON object with snake_case typed fields. Duplicate or
unknown fields are rejected. Successful identity operations return the domain value
directly; errors use HTTP400/401/404/409/503 and `{error, message?}`. There is no
provider version/ok/value envelope.

- `/internal/identity/accounts/lookup`: `{account_id}` or `{email}` to account.
- `/internal/identity/holds/acquire` and `/release`: exact request/account/hold/reason/acquisition IDs; no caller clock or expiry.
- `/internal/identity/leases/create`, `/renew`, `/release`, and `/retention/eligibility`: existing typed retention fields.
- `/internal/browser/session/resolve`: `{credential}` to account/session IDs, expiry, email, verified email and assurance.
- `/internal/browser/session/logout`: `{credential}` to `{ok:true}`.
- `/internal/browser/email/complete`: `{request_id,email,code,intent?}` to token, account/session IDs and expiry.
- `/internal/browser/email/login/issue`, `/login/consume`, `/signup/issue`, `/signup/consume`, and `/fact`: typed strict verification fields.
- `/internal/erasure/accounts/lookup`, `/retention/eligibility`, `/accounts/delete`, `/accounts/erase`, and `/receipts/lookup`: separately authorized typed erasure operations.

Generic private email issue/consume and the old versioned completion path are absent.
Internal services call Go methods directly. Storage encodings and their explicit
conversion are separate from HTTP; no retired provider protocol runs in the server.

The canonical JWT issuer is `bananauth`; old-issuer tokens require login after a
future authorized cutover. SQL account/session history is retained. Keep email
and all external activation disabled during local qualification.
