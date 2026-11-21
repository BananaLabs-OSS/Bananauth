# Bananauth development

From the root module run:

```sh
go test -mod=readonly ./...
go vet -mod=readonly ./...
go test -race -mod=readonly ./...
```

Some SQL connector tests create disposable loopback listeners. Run them inside a
network-isolated namespace when validating without provider access. Database-backed
integration fixtures remain separate from default tests and require explicit private
fixture locations; a skipped opt-in test is not integration qualification.

The canonical HTTP lifecycle tests exercise actual SQLite identity/session services,
strict login/signup, replay, live revocation, direct private JSON, and retired-route404.
Notification tests use an in-process fake transport and never send real email.

The explicit notification-format converter is qualified with synthetic local data,
including unchanged ciphertext/AAD, active lease fencing, credential/receipt replay,
OTP consumption, physical reopen, atomic publication, and rollback. No authoritative
production authentication snapshot has been supplied. An unbound, still-live old
verification requires explicit offline intent reconciliation; it is never silently
upgraded or accepted by a runtime compatibility route.
