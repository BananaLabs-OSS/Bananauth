package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/vmihailenco/msgpack/v5"
)

func TestDeliveryHoldsUnlistedRecipient(t *testing.T) {
	for _, config := range [][2]string{
		{"", "true"},
		{"allowed@example.com", "yes"},
		{"allowed@example.com,ALLOWED@example.com", ""},
		{"Tester <allowed@example.com>", ""},
	} {
		if _, err := parseTestRecipients(config[0], config[1]); err == nil {
			t.Fatalf("invalid restriction was accepted: %q", config)
		}
	}
	allowed, err := parseTestRecipients(" ALLOWED@example.com ", "true")
	if err != nil || !allowed["allowed@example.com"] {
		t.Fatal("valid restriction was not accepted", err)
	}
	keys, err := otpsecure.Parse(strings.Repeat("k", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	const recipient = "unlisted@example.com"
	body, err := msgpack.Marshal(map[string]string{"to": recipient, "subject": "Fixture", "text": "Fixture"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.Seal("fixture", recipient, time.Now().Add(time.Minute).UnixMilli(), body)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := notification.NewMessage("fixture", "fixture", sealed)
	if err != nil {
		t.Fatal(err)
	}
	worker := newDeliveryWorker(nil, keys, "fixture-key", "sender@example.com")
	worker.testRecipients = allowed
	worker.client.Transport = testTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unlisted recipient reached provider")
		return nil, nil
	})
	if _, err := worker.deliver(context.Background(), notification.Lease{Message: intent}); err == nil ||
		err.Error() != "notification held by verification recipient restriction" {
		t.Fatalf("expected retryable recipient hold, got %v", err)
	}
}

func TestDeliverySettlesInvalidNotificationsWithoutSending(t *testing.T) {
	keys, err := otpsecure.Parse(strings.Repeat("k", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]string{"to": "fixture@example.com", "subject": "Fixture", "text": "Fixture"}
	plain, err := msgpack.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	expired, err := keys.Seal("fixture", payload["to"], now.Add(-time.Minute).UnixMilli(), plain)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := keys.Seal("fixture", "other@example.com", now.Add(time.Minute).UnixMilli(), plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body any
	}{
		{"unsealed", payload},
		{"expired", expired},
		{"recipient mismatch", mismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent, err := notification.NewMessage("fixture", "fixture", testEncryptedBytes(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			commands := &testNotificationOutbox{}
			worker := newDeliveryWorker(commands, keys, "fixture-key", "sender@example.com")
			worker.client.Transport = testTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid intent reached provider")
				return nil, nil
			})
			lease := notification.Lease{
				ConsumerID: worker.consumer,
				LeaseID:    "fixture-lease", Attempt: 1, LeasedUntilUnixMilli: now.Add(time.Minute).UnixMilli(), Message: intent,
			}
			commands.claim = func(notification.ClaimRequest) (notification.ClaimResult, error) {
				return notification.ClaimResult{ConsumerID: lease.ConsumerID, Leases: []notification.Lease{lease}}, nil
			}
			commands.ack = func(ack notification.AcknowledgeRequest) (notification.SettlementResult, error) {
				if ack.Receipt.ValidateFor(intent) != nil || ack.Receipt.Failure == nil || ack.Receipt.Failure.Code != "invalid_notification_payload" {
					t.Fatal("expected terminal receipt for invalid notification")
				}
				return notification.SettlementResult{ConsumerID: lease.ConsumerID, LeaseID: lease.LeaseID, Settled: true}, nil
			}
			if err := worker.drain(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type testNotificationOutbox struct {
	claim func(notification.ClaimRequest) (notification.ClaimResult, error)
	ack   func(notification.AcknowledgeRequest) (notification.SettlementResult, error)
}

func (o *testNotificationOutbox) EffectsClaim(q notification.ClaimRequest) (notification.ClaimResult, error) {
	return o.claim(q)
}
func (o *testNotificationOutbox) EffectsAck(q notification.AcknowledgeRequest) (notification.SettlementResult, error) {
	return o.ack(q)
}
func (o *testNotificationOutbox) EffectsRetry(notification.RetryRequest) (notification.SettlementResult, error) {
	panic("unexpected retry")
}
func (o *testNotificationOutbox) EffectsCheckDelivery(notification.Lease) (identity.Result[bool], error) {
	panic("invalid notification reached authorization")
}
func testEncryptedBytes(v any) []byte {
	if b, ok := v.([]byte); ok {
		return b
	}
	b, _ := msgpack.Marshal(v)
	return b
}
