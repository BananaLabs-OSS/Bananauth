package session

import (
	"database/sql"
	"errors"
	"github.com/vmihailenco/msgpack/v5"
	_ "modernc.org/sqlite"
	"path/filepath"
	"testing"
	"time"
)

func verifiedRequest() CreateEmailVerifiedOwnedRequest {
	return CreateEmailVerifiedOwnedRequest{RequestID: "verified-create", SessionID: "verified-session", AccountID: "account", LifetimeMillis: 86400000, VerifiedEmail: "member@example.test", EmailVerifiedAtUnixMilli: 1000, EmailVerificationExpiresAtUnixMilli: 61000, VerificationRequestID: "otp-consume-proof"}
}
func openVerifiedStore(t *testing.T, path string) (*sql.DB, *sqliteStore) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	store, err := newSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, store
}
func TestVerifiedSessionSQLiteFirstCommitReplayAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verified.db")
	db, store := openVerifiedStore(t, path)
	req := verifiedRequest()
	first, err := store.CreateEmailVerifiedOwned(req, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if first.VerifiedEmail != req.VerifiedEmail || first.CreatedAt != 2000 || first.EmailVerificationExpiresAtUnixMilli != 61000 {
		t.Fatalf("invalid durable proof: %#v", first)
	}
	db.Close()
	db, store = openVerifiedStore(t, path)
	defer db.Close()
	again, err := store.CreateEmailVerifiedOwned(req, 7200000)
	if err != nil || again != first {
		t.Fatalf("exact late replay changed original result: %#v %v", again, err)
	}
	got, ok, err := store.Get(req.SessionID)
	if err != nil || !ok || got != first {
		t.Fatalf("reopened assurance differs: %#v %v", got, err)
	}
	revoked, ok, err := store.RevokeOwned(RevokeOwnedRequest{RequestID: "logout", SessionID: req.SessionID}, 8000)
	if err != nil || !ok || revoked.Active || revoked.VerifiedEmail != first.VerifiedEmail {
		t.Fatal("revocation lost assurance/lifecycle", err)
	}
	replay, err := store.CreateEmailVerifiedOwned(req, 7300000)
	if err != nil || replay != first {
		t.Fatal("creation receipt was rewritten by revocation", err)
	}
	got, ok, err = store.Get(req.SessionID)
	if err != nil || !ok || got.RevokedAt != 8000 || got.Active {
		t.Fatal("creation replay reactivated revoked session")
	}
	for _, mutate := range []func(*CreateEmailVerifiedOwnedRequest){func(r *CreateEmailVerifiedOwnedRequest) { r.VerifiedEmail = "other@example.test" }, func(r *CreateEmailVerifiedOwnedRequest) { r.EmailVerifiedAtUnixMilli++ }, func(r *CreateEmailVerifiedOwnedRequest) { r.EmailVerificationExpiresAtUnixMilli++ }, func(r *CreateEmailVerifiedOwnedRequest) { r.VerificationRequestID += "other" }, func(r *CreateEmailVerifiedOwnedRequest) { r.AccountID += "other" }, func(r *CreateEmailVerifiedOwnedRequest) { r.SessionID += "other" }, func(r *CreateEmailVerifiedOwnedRequest) { r.LifetimeMillis++ }} {
		changed := req
		mutate(&changed)
		_, err := store.CreateEmailVerifiedOwned(changed, 7200000)
		var conflict requestConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("changed proof accepted: %v", err)
		}
	}
}
func TestVerifiedSessionLateFirstCommitRejectedAndAtomicFailure(t *testing.T) {
	db, store := openVerifiedStore(t, filepath.Join(t.TempDir(), "atomic.db"))
	defer db.Close()
	req := verifiedRequest()
	for _, at := range []int64{61000, 7200000} {
		_, err := store.CreateEmailVerifiedOwned(req, at)
		var expired verificationTimeError
		if !errors.As(err, &expired) || expired.code != "verification_expired" {
			t.Fatalf("late first creation accepted %d: %v", at, err)
		}
	}
	if _, ok, _ := store.Get(req.SessionID); ok {
		t.Fatal("late rejected creation persisted session")
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_verified_receipt BEFORE INSERT ON auth_session_commands BEGIN SELECT RAISE(ABORT,'receipt fault'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateEmailVerifiedOwned(req, 2000); err == nil {
		t.Fatal("receipt failure accepted")
	}
	if _, ok, _ := store.Get(req.SessionID); ok {
		t.Fatal("receipt failure left orphan session")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_verified_receipt`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateEmailVerifiedOwned(req, 3000); err != nil {
		t.Fatal(err)
	}
}
func TestVerifiedSessionGenericPathsCannotAssertOrAcquireAssurance(t *testing.T) {
	for _, store := range []sessionStore{newMemoryStore(), func() sessionStore {
		db, s := openVerifiedStore(t, filepath.Join(t.TempDir(), "generic.db"))
		t.Cleanup(func() { db.Close() })
		return s
	}()} {
		o := newOwner(store)
		o.now = func() time.Time { return time.UnixMilli(2000) }
		generic := map[string]any{"request_id": "generic", "session_id": "generic-session", "account_id": "account", "lifetime_millis": 60000, "verified_email": "forged@example.test", "email_verified_at_unix_milli": 1000, "email_verification_expires_at_unix_milli": 61000, "verification_request_id": "forged"}
		raw, _ := msgpack.Marshal(generic)
		response, err := o.createOwned(raw)
		if err != nil {
			t.Fatal(err)
		}
		var value Result[Session]
		msgpack.Unmarshal(response, &value)
		if !value.OK || value.Value.VerifiedEmail != "" || value.Value.EmailVerifiedAtUnixMilli != 0 {
			t.Fatal("generic provider manufactured assurance")
		}
		req := verifiedRequest()
		first, err := store.CreateEmailVerifiedOwned(req, 2000)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Create(CreateRequest{RequestID: "generic-collision", SessionID: first.SessionID, AccountID: first.AccountID, CreatedAt: first.CreatedAt, ExpiresAt: first.ExpiresAt}); err == nil {
			t.Fatal("generic create acquired verified-session assurance")
		}
		req.SessionID = "generic-session"
		req.RequestID = "upgrade-generic"
		if _, err := store.CreateEmailVerifiedOwned(req, 2000); err == nil {
			t.Fatal("generic session upgraded with new operation")
		}
	}
}
func TestVerifiedSessionOwnerClockAndProofValidation(t *testing.T) {
	o := newOwner(newMemoryStore())
	now := int64(2000)
	o.now = func() time.Time { return time.UnixMilli(now) }
	req := verifiedRequest()
	for _, tc := range []struct {
		at   int64
		code string
	}{{999, "invalid_verification"}, {61000, "verification_expired"}} {
		now = tc.at
		got := call[Session](t, o.createEmailVerifiedOwned, req)
		if got.OK || got.Error == nil || got.Error.Code != tc.code {
			t.Fatalf("clock validation %#v", got)
		}
	}
	now = 2000
	first := call[Session](t, o.createEmailVerifiedOwned, req)
	if !first.OK {
		t.Fatal(first.Error)
	}
	now = 7200000
	replayed := call[Session](t, o.createEmailVerifiedOwned, req)
	if !replayed.OK || replayed.Value.CreatedAt != first.Value.CreatedAt || replayed.Value.ExpiresAt != first.Value.ExpiresAt {
		t.Fatal("owner replay rebased session clock")
	}
	bad := req
	bad.RequestID = "bad-proof"
	bad.VerifiedEmail = "Member@Example.Test"
	got := call[Session](t, o.createEmailVerifiedOwned, bad)
	if got.OK || got.Error.Code != "invalid_verification" {
		t.Fatal("noncanonical email proof accepted")
	}
	native, err := o.CreateEmailVerifiedOwned(req)
	if err != nil || !native.OK || native.Value.VerificationRequestID != req.VerificationRequestID {
		t.Fatal("typed verified-session service changed proof", err)
	}

}
func TestVerifiedSessionLegacyMigrationRemainsUnassured(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE auth_sessions(session_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER NOT NULL DEFAULT 0);INSERT INTO auth_sessions VALUES('legacy','account',100,10000,0)`)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.Get("legacy")
	if err != nil || !ok || v.VerifiedEmail != "" || v.EmailVerifiedAtUnixMilli != 0 || v.VerificationRequestID != "" {
		t.Fatal("legacy migration invented assurance", err)
	}
}
