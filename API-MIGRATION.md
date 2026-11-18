# Canonical email authentication API

Use the unversioned strict-intent endpoints:

- `POST /auth/email-verification`
- `POST /auth/email-verification/consume`
- `POST /auth/email-verification/session`
- Private workflow: `/internal/browser/email/complete`

Login uses `intent: "login"` (the public default), and signup uses
`intent: "signup"`. Unknown-account login does not create an account. Browser
and mobile session creation preserve the existing request identity, intent-bound
consume purpose, durable provider contract versions and replay behavior.
The retired `/auth/email-verification/v2*` and
`/internal/browser/email/v2/complete` routes return404.

The canonical routes replace the earlier unversioned legacy HTTP handlers as
well as the versioned strict routes. Callers must use the strict intent payload;
there is no fallback from a rejected strict request to legacy account creation.
Internal durable owner readers and old state identifiers remain available for
compatibility. This HTTP migration does not rename queues or reset databases.

The Sessions/mobile caller and ingress changes are coordinated in the Evolution
task. Local parity includes native email/session replay tests, retired-route404
checks, focused caller tests and the staged native preflight. Existing rollback
releases are preserved; no deployment is performed by this migration.
