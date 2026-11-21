package identity

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/vmihailenco/msgpack/v5"
)

func TestConsumedSignupIsHeldBeforeAndAfterClaim(t *testing.T) {
	for _, claimFirst := range []bool{false, true} {
		store := &memoryEventStore{}
		owner := newTestOwner(t, store)
		worker := newTestOwner(t, store)
		now := time.Now().Add(-time.Second).UnixMilli()
		const email = "signup@example.test"
		if result := issueV2(t, owner, "signup", "signup", email, now); !result.OK || !result.Value.EffectQueued {
			t.Fatal(result)
		}
		request, err := notification.NewClaimRequest("worker", 1, 30_000)
		if err != nil {
			t.Fatal(err)
		}
		requestWire, err := msgpack.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		claim := func() []notification.Lease {
			t.Helper()
			wire, err := worker.effectsClaim(requestWire)
			if err != nil {
				t.Fatal(err)
			}
			var result notification.ClaimResult
			if err := msgpack.Unmarshal(wire, &result); err != nil {
				t.Fatal(err)
			}
			return result.Leases
		}
		var lease notification.Lease
		if claimFirst {
			leases := claim()
			if len(leases) != 1 {
				t.Fatal("expected one active issuance lease")
			}
			lease = leases[0]
			if result := callResult[bool](t, worker.effectsCheckDelivery, lease); !result.OK || !result.Value {
				t.Fatal("active issuance was held")
			}
		}
		if result := consumeV2(t, owner, "signup", "consume", email, now+1); !result.OK {
			t.Fatal(result)
		}
		if claimFirst {
			if result := callResult[bool](t, worker.effectsCheckDelivery, lease); !result.OK || result.Value {
				t.Fatal("previous lease authorized delivery after consumption")
			}
		} else if len(claim()) != 0 {
			t.Fatal("consumed issuance was leased")
		}
	}
}

func issueV2(t *testing.T, o *owner, purpose, id, email string, now int64) Result[EmailVerificationIssueResult] {
	p := o.emailLoginIssueV2
	if purpose == "signup" {
		p = o.emailSignupIssueV2
	}
	return callResult[EmailVerificationIssueResult](t, p, EmailVerificationIssueRequest{RequestID: id, VerificationID: id + "-otp", EffectID: id + "-effect", Email: email, Code: "123456", Now: now, ExpiresAt: now + 60000})
}
func consumeV2(t *testing.T, o *owner, purpose, id, email string, now int64) Result[EmailVerificationConsumeResult] {
	p := o.emailLoginConsumeV2
	if purpose == "signup" {
		p = o.emailSignupConsumeV2
	}
	return callResult[EmailVerificationConsumeResult](t, p, EmailVerificationConsumeRequest{RequestID: id, AccountID: "new-account", Email: email, Code: "123456", Now: now})
}
func TestEmailIntentV2UnknownLoginNoImplicitSignup(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	r := issueV2(t, o, "login", "login", "unknown@example.test", 1000)
	if !r.OK || !r.Value.Accepted || r.Value.EffectQueued || len(o.state.Effects) != 0 || len(o.state.OTPs) != 0 || len(o.state.Accounts) != 0 {
		t.Fatalf("unknown login created authority: %#v", r)
	}
	if consumeV2(t, o, "login", "consume", "unknown@example.test", 1001).OK {
		t.Fatal("unknown login consumed")
	}
}
func TestEmailIntentV2SignupOnlyOwnFactAndSingleUse(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	r := issueV2(t, o, "signup", "signup", "new@example.test", 1000)
	if !r.OK || !r.Value.EffectQueued {
		t.Fatal(r)
	}
	fact := callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "signup-effect", Email: "new@example.test", Now: 1001})
	if !fact.OK || !fact.Value.Active || fact.Value.Purpose != "signup" || fact.Value.IssuanceRequestID != "signup" || fact.Value.AccountID != "" {
		t.Fatal(fact)
	}
	wrong := callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "signup-effect", Email: "client@example.test", Now: 1001})
	if wrong.OK {
		t.Fatal("fact recipient redirected")
	}
	if consumeV2(t, o, "login", "wrong-purpose", "new@example.test", 1002).OK {
		t.Fatal("signup code accepted as login")
	}
	consumed := consumeV2(t, o, "signup", "consume", "new@example.test", 1002)
	if !consumed.OK || !consumed.Value.Verified || consumed.Value.AccountID != "new-account" {
		t.Fatal(consumed)
	}
	replay := consumeV2(t, o, "signup", "consume", "new@example.test", 90000)
	if !replay.OK || replay.Value.EmailVerifiedAtUnixMilli != 1002 {
		t.Fatal("replay renewed proof", replay)
	}
	if consumeV2(t, o, "signup", "other-consume", "new@example.test", 1003).OK {
		t.Fatal("code reused")
	}
	fact = callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "signup-effect", Email: "new@example.test", Now: 1003})
	if !fact.OK || fact.Value.Active {
		t.Fatal("consumed issuance still active", fact)
	}
}
func TestEmailIntentV2LegacyCannotBecomeSignup(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	o.state.OTPs["legacy-otp"] = otpRecord{ID: "legacy-otp", Email: "legacy@example.test", Code: "123456", Type: "sessions_email_verification", ExpiresAt: 61000}
	store := o.store.(*memoryEventStore)
	store.records = append(store.records, durableRecord{Snapshot: o.state})
	if consumeV2(t, o, "signup", "new-consume", "legacy@example.test", 1001).OK {
		t.Fatal("legacy code upgraded to signup")
	}
	f := callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "legacy-effect", Email: "legacy@example.test", Now: 1001})
	if f.OK {
		t.Fatal("invented legacy signup fact")
	}

}
func TestEmailIntentV2ExistingNativeMembershipLoginAndStaleBinding(t *testing.T) {
	store := &memoryEventStore{}
	o := newTestOwner(t, store)
	r := callResult[AccountProjection](t, o.nativeRegister, NativeRegisterRequest{RequestID: "register", AccountID: "existing", CredentialID: "credential", Email: "member@example.test", Username: "Member", Password: "password-123", Now: 1000})
	if !r.OK {
		t.Fatal(r)
	}
	if r := issueV2(t, o, "login", "login", "member@example.test", 1001); !r.OK || !r.Value.EffectQueued {
		t.Fatal(r)
	}
	consumed := consumeV2(t, o, "login", "consume", "member@example.test", 1002)
	if !consumed.OK || consumed.Value.AccountID != "existing" || len(o.state.Accounts) != 1 {
		t.Fatal(consumed)
	}
	// A current owner mutation changing the canonical address invalidates old
	// issuance. This uses the store transaction, not a caller-provided profile bit.
	if r := issueV2(t, o, "login", "stale", "member@example.test", 1003); !r.OK || !r.Value.EffectQueued {
		t.Fatal(r)
	}
	_, err := o.command("test-only-canonical-change", "change", map[string]string{"id": "existing"}, func(s *snapshot) (any, error) {
		a := s.Accounts["existing"]
		a.Email = "new@example.test"
		s.Accounts["existing"] = a
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if consumeV2(t, o, "login", "stale-consume", "member@example.test", 1004).OK {
		t.Fatal("stale canonical email accepted")
	}
}
func TestEmailIntentV2BoundsRatesAndConflictingAccountID(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	for i, id := range []string{"one", "two", "three", "four"} {
		r := issueV2(t, o, "signup", id, "new@example.test", int64(1000+i))
		if !r.OK || r.Value.EffectQueued != (i < 3) {
			t.Fatal(i, r)
		}
	}
	if r := consumeV2(t, o, "signup", "expired", "new@example.test", 100000); r.OK {
		t.Fatal("expired signup consumed")
	}
	o = newTestOwner(t, &memoryEventStore{})
	issueV2(t, o, "signup", "signup", "new@example.test", 1000)
	_, _ = o.command("test-only-account", "occupied", true, func(s *snapshot) (any, error) {
		s.Accounts["new-account"] = AccountProjection{AccountID: "new-account", Email: "other@example.test"}
		return true, nil
	})
	if consumeV2(t, o, "signup", "consume", "new@example.test", 1001).OK {
		t.Fatal("signup overwrote another account")
	}
	if o.state.Accounts["new-account"].Email != "other@example.test" {
		t.Fatal("account overwritten")
	}
}
func TestEmailIntentV2DurableSQLiteFactsAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	store, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	o := newTestOwner(t, store)
	issueV2(t, o, "signup", "signup", "new@example.test", 1000)
	store.db.Close()
	reopened, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.db.Close()
	again, err := openOwner(context.Background(), reopened, o.otpKeys)
	if err != nil {
		t.Fatal(err)
	}
	f := callResult[EmailVerificationFactV2](t, again.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "signup-effect", Email: "new@example.test", Now: 1001})
	if !f.OK || !f.Value.Active {
		t.Fatal(f)
	}
	r := consumeV2(t, again, "signup", "consume", "new@example.test", 1002)
	if !r.OK {
		t.Fatal(r)
	}
	replayOwner := newTestOwner(t, reopened)
	r = consumeV2(t, replayOwner, "signup", "consume", "new@example.test", 90000)
	if !r.OK || r.Value.EmailVerifiedAtUnixMilli != 1002 {
		t.Fatal(r)
	}
}

func TestEmailIntentV2CallerFlagsCannotUpgradeUnknownLogin(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	wire, _ := msgpack.Marshal(map[string]any{"request_id": "forged", "verification_id": "forged-otp", "effect_id": "forged-effect", "email": "unknown@example.test", "code": "123456", "now": int64(1000), "expires_at": int64(61000), "intent": "signup", "purpose": "signup", "account_id": "claimed-member", "account_holder": true})
	raw, err := o.emailLoginIssueV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	var r Result[EmailVerificationIssueResult]
	msgpack.Unmarshal(raw, &r)
	if !r.OK || r.Value.EffectQueued || len(o.state.OTPs) != 0 || len(o.state.Accounts) != 0 {
		t.Fatal("untrustedflagsupgradedlogin", r)
	}
}
func TestEmailIntentV2CurrentFactsErasedWithAccount(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	r := callResult[AccountProjection](t, o.nativeRegister, NativeRegisterRequest{RequestID: "register", AccountID: "member", CredentialID: "credential", Email: "member@example.test", Username: "Member", Password: "password-123", Now: 1000})
	if !r.OK {
		t.Fatal(r)
	}
	issueV2(t, o, "login", "login", "member@example.test", 1001)
	removed := callResult[AccountProjection](t, o.accountDelete, AccountDeleteRequest{RequestID: "delete", AccountID: "member", Password: "password-123", Now: 1002})
	if !removed.OK {
		t.Fatal(removed)
	}
	fact := callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "login-effect", Email: "member@example.test", Now: 1003})
	if fact.OK {
		t.Fatal("erasedaccountretainedcurrentpurposefact", fact)
	}
}

func TestEmailIntentV2OriginalIntentHashCannotBeLaundered(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	issueV2(t, o, "signup", "signup", "new@example.test", 1000)
	before := callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "signup-effect", Email: "new@example.test", Now: 1001})
	if !before.OK || !before.Value.Active || before.Value.MessageIdempotencyKey != "signup-effect" || len(before.Value.EncryptedPayloadSHA256) != 64 {
		t.Fatal(before)
	}
	_, err := o.command("test-only-effect-tamper", "tamper", true, func(s *snapshot) (any, error) {
		record := s.Effects["signup-effect"]
		record.Message.Ciphertext = append(append([]byte(nil), record.Message.Ciphertext...), 0)
		s.Effects["signup-effect"] = record
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	after := callResult[EmailVerificationFactV2](t, o.emailVerificationFactGetV2, EmailVerificationFactRequestV2{EffectID: "signup-effect", Email: "new@example.test", Now: 1002})
	if !after.OK || after.Value.Active || after.Value.EncryptedPayloadSHA256 != before.Value.EncryptedPayloadSHA256 {
		t.Fatal("mutatedeffectupgradedtooriginalsignupfact", after)
	}
	if consumeV2(t, o, "signup", "consume", "new@example.test", 1003).OK {
		t.Fatal("mutatedissuedintentconsumed")
	}
}
