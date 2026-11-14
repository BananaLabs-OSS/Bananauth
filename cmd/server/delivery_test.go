package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/effect"
	"github.com/bananalabs-oss/bananauth/internal/identity"
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
	intent, err := effect.NewIntent("fixture", effect.KindNotificationEmailSend, "fixture", sealed)
	if err != nil {
		t.Fatal(err)
	}
	worker := newDeliveryWorker(nil, keys, "fixture-key", "sender@example.com")
	worker.testRecipients = allowed
	worker.client.Transport = testTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("unlisted recipient reached provider")
		return nil, nil
	})
	if _, err := worker.deliver(context.Background(), effect.Lease{Intent: intent}); err == nil ||
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
			intent, err := effect.NewIntent("fixture", effect.KindNotificationEmailSend, "fixture", tc.body)
			if err != nil {
				t.Fatal(err)
			}
			commands := map[string]func([]byte) ([]byte, error){}
			worker := newDeliveryWorker(commands, keys, "fixture-key", "sender@example.com")
			worker.client.Transport = testTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid intent reached provider")
				return nil, nil
			})
			lease := effect.Lease{
				Version: effect.OutboxVersionV1, Owner: "auth-identity", ConsumerID: worker.consumer,
				LeaseID: "fixture-lease", Attempt: 1, LeasedUntilUnixMilli: now.Add(time.Minute).UnixMilli(), Intent: intent,
			}
			commands[identity.FnEffectsClaim] = func([]byte) ([]byte, error) {
				return msgpack.Marshal(effect.ClaimResult{
					Version: lease.Version, Owner: lease.Owner, ConsumerID: lease.ConsumerID, Leases: []effect.Lease{lease},
				})
			}
			commands[identity.FnEffectsAck] = func(raw []byte) ([]byte, error) {
				var ack effect.AcknowledgeRequest
				if err := msgpack.Unmarshal(raw, &ack); err != nil {
					t.Fatal(err)
				}
				if ack.Receipt.ValidateFor(intent) != nil || ack.Receipt.Failure == nil || ack.Receipt.Failure.Code != "invalid_notification_payload" {
					t.Fatal("expected terminal receipt for the invalid intent")
				}
				return msgpack.Marshal(effect.SettlementResult{
					Version: lease.Version, Owner: lease.Owner, ConsumerID: lease.ConsumerID, LeaseID: lease.LeaseID, Settled: true,
				})
			}
			if err := worker.drain(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
