package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	workersext "github.com/BananaLabs-OSS/Pulp-ext-workers"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/BananaLabs-OSS/Pulp/run"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	identityApplicationID = "bananauth"
	identityCellID        = "auth-identity"
	identityEffectOwner   = "auth-identity"
	identityEffectClaim   = "auth.identity.effects.v1.claim"
	identityEffectAck     = "auth.identity.effects.v1.acknowledge"
	identityEffectRetry   = "auth.identity.effects.v1.retry"
)

type notificationExecutor interface {
	Submit(context.Context, ext.Scope, effect.Intent) (workersext.EffectReceipt, error)
	Receipt(context.Context, ext.Scope, string) (workersext.EffectReceipt, error)
}

type identityEffectRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	scope  ext.Scope
}

type identityEffectObserver struct {
	factory *workersext.ScopedNotificationEffectExecutorFactory
	mu      sync.Mutex
	runs    map[run.ApplicationIdentity]identityEffectRun
}

func init() {
	factory, err := workersext.NewResendScopedNotificationEffectExecutorFactory(func(ext.Scope) (workersext.ResendNotificationEmailConfig, error) {
		apiKey := os.Getenv("RESEND_API_KEY")
		if apiKey == "" {
			return workersext.ResendNotificationEmailConfig{}, errors.New("RESEND_API_KEY is not configured")
		}
		from := os.Getenv("RESEND_FROM")
		if from == "" {
			from = "no-reply@example.com"
		}
		return workersext.ResendNotificationEmailConfig{APIKey: apiKey, From: from, Timeout: 15 * time.Second}, nil
	})
	if err != nil {
		panic(fmt.Sprintf("configure Bananauth identity effects: %v", err))
	}
	observer := &identityEffectObserver{
		factory: factory,
		runs:    make(map[run.ApplicationIdentity]identityEffectRun),
	}
	if err := run.RegisterApplicationLifecycleObserver(observer); err != nil {
		panic(fmt.Sprintf("register Bananauth identity effects: %v", err))
	}
}

func (o *identityEffectObserver) AfterApplicationStart(context.Context, run.ApplicationIdentity) error {
	return nil
}

func (o *identityEffectObserver) AfterApplicationStartWithProvider(
	parent context.Context,
	identity run.ApplicationIdentity,
	access run.ApplicationProviderAccess,
) error {
	if identity.ApplicationID != identityApplicationID || os.Getenv("RESEND_API_KEY") == "" {
		return nil
	}
	scope, err := ext.NewScope(identity.ApplicationID, identity.InstanceID, identityCellID, "default")
	if err != nil {
		return err
	}
	executor, err := o.factory.ForScope(scope)
	if err != nil {
		return fmt.Errorf("configure identity email executor: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	active := identityEffectRun{cancel: cancel, done: make(chan struct{}), scope: scope}

	o.mu.Lock()
	if _, exists := o.runs[identity]; exists {
		o.mu.Unlock()
		cancel()
		return fmt.Errorf("identity effect dispatcher already exists for %s", identity)
	}
	o.runs[identity] = active
	o.mu.Unlock()

	go func() {
		defer close(active.done)
		runIdentityEffectLoop(ctx, scope, access, executor)
	}()
	return nil
}

func (o *identityEffectObserver) BeforeApplicationShutdown(_ context.Context, identity run.ApplicationIdentity) error {
	o.mu.Lock()
	active, exists := o.runs[identity]
	if exists {
		delete(o.runs, identity)
	}
	o.mu.Unlock()
	if !exists {
		return nil
	}
	active.cancel()
	select {
	case <-active.done:
	case <-time.After(5 * time.Second):
		return errors.New("identity effect dispatcher did not stop")
	}
	return o.factory.TeardownScope(active.scope)
}

func runIdentityEffectLoop(ctx context.Context, scope ext.Scope, access run.ApplicationProviderAccess, executor notificationExecutor) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := drainIdentityEffects(ctx, scope, access, executor); err != nil && ctx.Err() == nil {
			log.Printf("bananauth identity effect drain failed: %v", err)
		}
		timer.Reset(time.Second)
	}
}

func drainIdentityEffects(ctx context.Context, scope ext.Scope, access run.ApplicationProviderAccess, executor notificationExecutor) error {
	claim, err := effect.NewClaimRequest(identityEffectOwner, identityEffectConsumer(scope), 10, int64((30 * time.Second).Milliseconds()))
	if err != nil {
		return err
	}
	wire, err := msgpack.Marshal(claim)
	if err != nil {
		return err
	}
	response, err := access.CallProvider(ctx, identityCellID, identityEffectClaim, wire)
	if err != nil {
		return fmt.Errorf("claim identity effects: %w", err)
	}
	var result effect.ClaimResult
	if err := msgpack.Unmarshal(response, &result); err != nil {
		return fmt.Errorf("decode identity effect claim: %w", err)
	}
	if err := result.Validate(); err != nil || result.Owner != identityEffectOwner || result.ConsumerID != claim.ConsumerID {
		return errors.New("identity effect owner returned an invalid claim")
	}
	for _, lease := range result.Leases {
		if err := executeIdentityEffect(ctx, scope, access, executor, lease); err != nil {
			return err
		}
	}
	return nil
}

func executeIdentityEffect(ctx context.Context, scope ext.Scope, access run.ApplicationProviderAccess, executor notificationExecutor, lease effect.Lease) error {
	receipt, submitErr := executor.Submit(ctx, scope, lease.Intent)
	if submitErr != nil && receipt.Status == "" {
		return fmt.Errorf("submit identity effect: %w", submitErr)
	}
	deadline := time.UnixMilli(lease.LeasedUntilUnixMilli).Add(-500 * time.Millisecond)
	for receipt.Status == effect.Pending && time.Now().Before(deadline) {
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		current, err := executor.Receipt(ctx, scope, lease.Intent.IdempotencyKey)
		if err != nil {
			return fmt.Errorf("read identity effect receipt: %w", err)
		}
		receipt = current
	}
	switch receipt.Status {
	case effect.Completed:
		return settleIdentityEffect(ctx, access, identityEffectAck, effect.AcknowledgeRequest{
			Version: effect.OutboxVersionV1, Owner: lease.Owner, ConsumerID: lease.ConsumerID,
			LeaseID: lease.LeaseID, Receipt: receipt.Receipt,
		}, lease)
	case effect.Failed:
		failure := receipt.Failure
		if failure == nil {
			failure = &effect.Failure{Code: "host_execution_failed", Message: "notification delivery failed"}
		}
		return settleIdentityEffect(ctx, access, identityEffectRetry, effect.RetryRequest{
			Version: effect.OutboxVersionV1, Owner: lease.Owner, ConsumerID: lease.ConsumerID,
			LeaseID: lease.LeaseID, Failure: *failure, RetryAtUnixMilli: time.Now().Add(30 * time.Second).UnixMilli(),
		}, lease)
	case effect.Pending:
		// Leave the lease fenced. A later claim will replay the durable host
		// receipt after the lease expires without delivering the email twice.
		return nil
	default:
		return fmt.Errorf("identity effect executor returned status %q", receipt.Status)
	}
}

func settleIdentityEffect(ctx context.Context, access run.ApplicationProviderAccess, provider string, request any, lease effect.Lease) error {
	wire, err := msgpack.Marshal(request)
	if err != nil {
		return err
	}
	response, err := access.CallProvider(ctx, identityCellID, provider, wire)
	if err != nil {
		return fmt.Errorf("settle identity effect: %w", err)
	}
	var result effect.SettlementResult
	if err := msgpack.Unmarshal(response, &result); err != nil {
		return fmt.Errorf("decode identity effect settlement: %w", err)
	}
	if err := result.ValidateFor(lease); err != nil {
		return fmt.Errorf("validate identity effect settlement: %w", err)
	}
	if !result.Settled {
		return errors.New("identity effect settlement lost its lease")
	}
	return nil
}

func identityEffectConsumer(scope ext.Scope) string {
	return "bananauth-email:" + scope.ApplicationInstanceID()
}
