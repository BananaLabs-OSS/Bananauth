package identity

import (
	"path/filepath"
	"testing"
)

func TestEmailConsumeProofKeepsOriginalExpiryAndVerifiedEmailAcrossSQLiteReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof.db")
	store, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	cell := newTestOwner(t, store)
	issued := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, EmailVerificationIssueRequest{RequestID: "issue-proof", VerificationID: "proof", EffectID: "mail-proof", Email: " User@Example.test ", Code: "123456", Now: 100000, ExpiresAt: 160000})
	if !issued.OK {
		t.Fatal("issue failed")
	}
	req := EmailVerificationConsumeRequest{RequestID: "consume-proof", AccountID: "account-proof", Email: "user@example.test", Code: "123456", Now: 101000}
	first := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, req)
	if !first.OK || first.Value.VerifiedEmail != "user@example.test" || first.Value.EmailVerifiedAtUnixMilli != 101000 || first.Value.EmailVerificationExpiresAtUnixMilli != 160000 || first.Value.VerificationRequestID != req.RequestID {
		t.Fatalf("missing original proof: %#v", first)
	}
	store.db.Close()
	store, err = openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	cell = newTestOwner(t, store)
	req.Now = 1000000000
	replay := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, req)
	if !replay.OK || replay.Value != first.Value {
		t.Fatal("durable replay renewed or lost original proof")
	}
	req.RequestID = "different"
	if got := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, req); got.OK || got.Error == nil || got.Error.Code != "invalid_code" {
		t.Fatal("used expired code authorized another operation")
	}
}
