package notification

import (
	"strings"
	"testing"
)

func TestNotificationLeaseAndSettlementBindExactMessageAndConsumer(t *testing.T) {
	message, err := NewMessage("message", "stable-key", []byte("encrypted-data"))
	if err != nil {
		t.Fatal(err)
	}
	lease := Lease{ConsumerID: "worker", LeaseID: "lease", Attempt: 1, LeasedUntilUnixMilli: 1000, Message: message}
	claim := ClaimResult{ConsumerID: "worker", Leases: []Lease{lease}}
	if err := claim.Validate(); err != nil {
		t.Fatal(err)
	}
	receipt, err := NewCompletedReceipt(message, "provider-message")
	if err != nil {
		t.Fatal(err)
	}
	ack := AcknowledgeRequest{ConsumerID: "worker", LeaseID: "lease", Receipt: receipt}
	if err := ack.ValidateFor(lease); err != nil {
		t.Fatal(err)
	}
	bad := ack
	bad.ConsumerID = "other"
	if bad.ValidateFor(lease) == nil {
		t.Fatal("foreign consumer acknowledged")
	}
	bad = ack
	bad.LeaseID = "old"
	if bad.ValidateFor(lease) == nil {
		t.Fatal("stale lease acknowledged")
	}
	bad = ack
	bad.Receipt.MessageID = "other"
	if bad.ValidateFor(lease) == nil {
		t.Fatal("foreign message acknowledged")
	}
	duplicate := claim
	duplicate.Leases = append(duplicate.Leases, lease)
	if duplicate.Validate() == nil {
		t.Fatal("duplicate claimed lease accepted")
	}
	retry := RetryRequest{ConsumerID: "worker", LeaseID: "lease", Failure: Failure{Code: "temporary", Message: "retry later"}, RetryAtUnixMilli: 2000}
	if retry.ValidateFor(lease) != nil {
		t.Fatal("valid retry rejected")
	}
	retry.ConsumerID = "other"
	if retry.ValidateFor(lease) == nil {
		t.Fatal("foreign retry accepted")
	}
}
func TestNotificationAdmissionIsBoundedAndCopiesCiphertext(t *testing.T) {
	ciphertext := []byte("encrypted")
	message, err := NewMessage("message", "key", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	if string(message.Ciphertext) != "encrypted" {
		t.Fatal("constructor aliases ciphertext")
	}
	for _, m := range []Message{{}, {ID: "m", IdempotencyKey: "key"}, {ID: strings.Repeat("x", 257), IdempotencyKey: "key", Ciphertext: []byte{1}}, {ID: "m", IdempotencyKey: "key", Ciphertext: make([]byte, (1<<20)+1)}} {
		if m.Validate() == nil {
			t.Fatal("invalid message accepted")
		}
	}
	for _, r := range []ClaimRequest{{ConsumerID: "w", Limit: 0, LeaseDurationMillis: 1}, {ConsumerID: "w", Limit: 1001, LeaseDurationMillis: 1}, {ConsumerID: "w", Limit: 1, LeaseDurationMillis: 3600001}} {
		if r.Validate() == nil {
			t.Fatal("unbounded claim accepted")
		}
	}
}
