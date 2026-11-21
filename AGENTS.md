# Bananauth

Bananauth is a conventional Go identity and authentication service. `cmd/server`
composes typed identity, session, browser, and encrypted-notification services.
It uses standard `net/http`, `database/sql`, the JWT library, and the configured
SQL drivers. There is one root Go module and no guest/provider registry.

Read [agent-docs/overview.md](agent-docs/overview.md),
[development.md](agent-docs/development.md), and
[connections.md](agent-docs/connections.md) for package boundaries and checks.

Do not read dotenv files, private keys, credentials, or local runtime databases
as source. Keep source archives and authenticated artifacts outside Projects.
Never deploy, push, or send email without explicit current authorization. During
this migration every actual email delivery remains disabled, including fixtures.
