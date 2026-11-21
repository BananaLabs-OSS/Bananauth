package identity

import (
	"bytes"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"testing"
	"time"
)

func TestTypedNotificationClaimCannotMutateDurableOwnerState(t *testing.T) {
	o := newTestOwner(t, &memoryEventStore{})
	now := time.Now().UnixMilli()
	issued, err := o.EmailSignupIssueV2(EmailVerificationIssueRequest{RequestID: "issue", VerificationID: "otp", EffectID: "message", Email: "member@example.test", Code: "ABC123", Now: now, ExpiresAt: now + 600000})
	if err != nil || !issued.OK || !issued.Value.EffectQueued {
		t.Fatal(issued, err)
	}
	claim, err := o.EffectsClaim(notification.ClaimRequest{ConsumerID: "worker", Limit: 1, LeaseDurationMillis: 60000})
	if err != nil || len(claim.Leases) != 1 {
		t.Fatal(claim, err)
	}
	original := append([]byte(nil), o.state.Effects["message"].Message.Ciphertext...)
	claim.Leases[0].Message.Ciphertext[0] ^= 0xff
	if !bytes.Equal(original, o.state.Effects["message"].Message.Ciphertext) || !bytes.Equal(original, o.state.Effects["message"].Lease.Message.Ciphertext) {
		t.Fatal("typed response aliases owner ciphertext")
	}
	fact, err := o.EmailVerificationFactGetV2(EmailVerificationFactRequestV2{EffectID: "message", Email: "member@example.test", Now: now + 1})
	if err != nil || !fact.OK || !fact.Value.Active {
		t.Fatal("caller mutation changed durable verification authority", err)
	}
}
