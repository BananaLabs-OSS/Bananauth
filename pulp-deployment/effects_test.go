package main

import (
	"context"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	workersext "github.com/BananaLabs-OSS/Pulp-ext-workers"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/BananaLabs-OSS/Pulp/run"
	"github.com/vmihailenco/msgpack/v5"
)

type fakeProviderAccess struct {
	identity run.ApplicationIdentity
	call     func(string, string, []byte) ([]byte, error)
}

func (f fakeProviderAccess) Identity() run.ApplicationIdentity { return f.identity }
func (f fakeProviderAccess) CallProvider(_ context.Context, cell, provider string, request []byte) ([]byte, error) {
	return f.call(cell, provider, request)
}

type fakeNotificationExecutor struct {
	receipt workersext.EffectReceipt
}

func (f fakeNotificationExecutor) Submit(context.Context, ext.Scope, effect.Intent) (workersext.EffectReceipt, error) {
	return f.receipt, nil
}
func (f fakeNotificationExecutor) Receipt(context.Context, ext.Scope, string) (workersext.EffectReceipt, error) {
	return f.receipt, nil
}

func testIdentityLease(t *testing.T) (ext.Scope, effect.Lease) {
	t.Helper()
	scope, err := ext.NewScope(identityApplicationID, "test", identityCellID, "default")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := effect.NewIntent("email-1", effect.KindNotificationEmailSend, "email-1", map[string]string{
		"to": "member@example.test", "subject": "Reset", "text": "Code",
	})
	if err != nil {
		t.Fatal(err)
	}
	return scope, effect.Lease{
		Version: effect.OutboxVersionV1, Owner: identityEffectOwner,
		ConsumerID: identityEffectConsumer(scope), LeaseID: "lease-1",
		Attempt: 1, LeasedUntilUnixMilli: time.Now().Add(time.Minute).UnixMilli(), Intent: intent,
	}
}

func TestExecuteIdentityEffectAcknowledgesOnlyCompletedReceipt(t *testing.T) {
	scope, lease := testIdentityLease(t)
	completed, err := effect.NewCompletedReceipt(lease.Intent, map[string]string{"provider": "resend"})
	if err != nil {
		t.Fatal(err)
	}
	var acknowledged bool
	access := fakeProviderAccess{
		identity: run.ApplicationIdentity{ApplicationID: identityApplicationID, InstanceID: "test"},
		call: func(cell, provider string, wire []byte) ([]byte, error) {
			if cell != identityCellID || provider != identityEffectAck {
				t.Fatalf("provider call = %s/%s", cell, provider)
			}
			var request effect.AcknowledgeRequest
			if err := msgpack.Unmarshal(wire, &request); err != nil {
				t.Fatal(err)
			}
			if err := request.ValidateFor(lease); err != nil {
				t.Fatalf("acknowledgement: %v", err)
			}
			acknowledged = true
			return msgpack.Marshal(effect.SettlementResult{
				Version: effect.OutboxVersionV1, Owner: lease.Owner, ConsumerID: lease.ConsumerID,
				LeaseID: lease.LeaseID, Settled: true,
			})
		},
	}
	executor := fakeNotificationExecutor{receipt: workersext.EffectReceipt{Intent: lease.Intent, Receipt: completed}}
	if err := executeIdentityEffect(context.Background(), scope, access, executor, lease); err != nil {
		t.Fatal(err)
	}
	if !acknowledged {
		t.Fatal("completed receipt was not acknowledged")
	}
}

func TestExecuteIdentityEffectRetriesFailedReceipt(t *testing.T) {
	scope, lease := testIdentityLease(t)
	failed, err := effect.NewFailedReceipt(lease.Intent, effect.Failure{Code: "provider_unavailable", Message: "delivery unavailable"})
	if err != nil {
		t.Fatal(err)
	}
	var retried bool
	access := fakeProviderAccess{
		identity: run.ApplicationIdentity{ApplicationID: identityApplicationID, InstanceID: "test"},
		call: func(cell, provider string, wire []byte) ([]byte, error) {
			if cell != identityCellID || provider != identityEffectRetry {
				t.Fatalf("provider call = %s/%s", cell, provider)
			}
			var request effect.RetryRequest
			if err := msgpack.Unmarshal(wire, &request); err != nil {
				t.Fatal(err)
			}
			if err := request.ValidateFor(lease); err != nil {
				t.Fatalf("retry: %v", err)
			}
			retried = true
			return msgpack.Marshal(effect.SettlementResult{
				Version: effect.OutboxVersionV1, Owner: lease.Owner, ConsumerID: lease.ConsumerID,
				LeaseID: lease.LeaseID, Settled: true,
			})
		},
	}
	executor := fakeNotificationExecutor{receipt: workersext.EffectReceipt{Intent: lease.Intent, Receipt: failed}}
	if err := executeIdentityEffect(context.Background(), scope, access, executor, lease); err != nil {
		t.Fatal(err)
	}
	if !retried {
		t.Fatal("failed receipt was not released for retry")
	}
}
