# Bananauth connections

Public clients use canonical JSON HTTP endpoints. Trusted application services use
separately authenticated private JSON routes documented in [API-MIGRATION.md](../API-MIGRATION.md).
All operations inside the process use concrete Go requests and results. There are no
provider names, dispatch maps, guest callbacks, or internal byte-message roundtrips.

MessagePack remains only for durable SQL records and explicit offline conversion.
The notification queue stores one encrypted-email type, not an arbitrary effect SDK.
The browser service directly calls identity and session methods. Discord uses its
normal OAuth HTTP API. The optional delivery worker uses the normal provider HTTP API
and stays disabled during local migration work.

The JWT issuer is `bananauth`, verified strictly. Prior-issuer tokens require a new
login at a future authorized cutover; account and session records are preserved.
