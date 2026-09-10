package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp/effect"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/bananalabs-oss/bananauth/pkg/passwordcrypto"
	"github.com/vmihailenco/msgpack/v5"
)

func TestRetentionEngineHasNoApplicationReasonVocabulary(t *testing.T) {
	contract := mustReadSource(t, "contract.go")
	owner := mustReadSource(t, "owner.go")
	for _, source := range []string{
		contract[strings.Index(contract, "type RetentionLease"):strings.Index(contract, "type OAuthState")],
		owner[strings.Index(owner, "func retentionLeaseKey"):strings.Index(owner, "func (o *owner) oauthStateIssue")],
	} {
		for _, forbidden := range []string{"server", "world", "platform account"} {
			if strings.Contains(strings.ToLower(source), forbidden) {
				t.Fatalf("retention engine leaked application vocabulary %q", forbidden)
			}
		}
	}
}

func mustReadSource(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func callResult[T any](t *testing.T, provider func([]byte) ([]byte, error), request any) Result[T] {
	t.Helper()
	raw, err := msgpack.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider(raw)
	if err != nil {
		t.Fatal(err)
	}
	var result Result[T]
	if err := msgpack.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func newTestOwner(t *testing.T, store eventStore) *owner {
	t.Helper()
	keys, err := otpsecure.Parse("test-current-otp-key-material-32-bytes-minimum", "")
	if err != nil {
		t.Fatal(err)
	}
	value, err := openOwner(context.Background(), store, keys)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNativeOAuthProfileAndResetLifecycle(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	registered := callResult[AccountProjection](t, cell.nativeRegister, NativeRegisterRequest{
		RequestID: "register-1", AccountID: "account-1", CredentialID: "credential-1",
		Email: " Member@Example.Test ", Username: "Member", Password: "password-1", Now: 100,
	})
	if !registered.OK || registered.Value.Email != "member@example.test" {
		t.Fatalf("register = %#v", registered)
	}
	if conflict := callResult[AccountProjection](t, cell.nativeRegister, NativeRegisterRequest{
		RequestID: "register-2", AccountID: "account-2", CredentialID: "credential-2",
		Email: "member@example.test", Username: "Other", Password: "password-2", Now: 101,
	}); conflict.OK || conflict.Error == nil || conflict.Error.Code != "email_taken" {
		t.Fatalf("email conflict = %#v", conflict)
	}
	if login := callResult[AccountProjection](t, cell.nativeAuthenticate, NativeAuthenticateRequest{Email: "MEMBER@example.test", Password: "password-1"}); !login.OK || login.Value.AccountID != "account-1" {
		t.Fatalf("login = %#v", login)
	}
	if wrong := callResult[AccountProjection](t, cell.nativeAuthenticate, NativeAuthenticateRequest{Email: "member@example.test", Password: "wrong"}); wrong.OK || wrong.Error == nil || wrong.Error.Code != "invalid_credentials" {
		t.Fatalf("wrong login = %#v", wrong)
	}
	changed := callResult[map[string]any](t, cell.passwordChange, PasswordChangeRequest{RequestID: "change-1", AccountID: "account-1", CurrentPassword: "password-1", NewPassword: "password-2", Now: 120})
	if !changed.OK {
		t.Fatalf("change = %#v", changed)
	}
	issued := callResult[PasswordResetIssueResult](t, cell.passwordResetIssue, PasswordResetIssueRequest{
		RequestID: "issue-1", OTPID: "otp-1", EffectID: "email-1", Email: "member@example.test",
		Code: "abc123", Now: 130, ExpiresAt: 230,
	})
	if !issued.OK || !issued.Value.EffectQueued {
		t.Fatalf("issue = %#v", issued)
	}
	reset := callResult[map[string]any](t, cell.passwordResetConsume, PasswordResetConsumeRequest{RequestID: "reset-1", Email: "member@example.test", Code: "ABC123", NewPassword: "password-3", Now: 150})
	if !reset.OK {
		t.Fatalf("reset = %#v", reset)
	}
	if reused := callResult[map[string]any](t, cell.passwordResetConsume, PasswordResetConsumeRequest{RequestID: "reset-2", Email: "member@example.test", Code: "ABC123", NewPassword: "password-4", Now: 151}); reused.OK || reused.Error == nil || reused.Error.Code != "invalid_code" {
		t.Fatalf("reused OTP = %#v", reused)
	}
	profile := callResult[Profile](t, cell.profileCreate, ProfileCreateRequest{RequestID: "profile-1", Profile: Profile{AccountID: "account-1", DisplayName: "Member", CreatedAt: 160, UpdatedAt: 160}})
	if !profile.OK {
		t.Fatalf("profile = %#v", profile)
	}
	updated := callResult[Profile](t, cell.profileUpdate, ProfileUpdateRequest{RequestID: "profile-2", AccountID: "account-1", DisplayName: "Renamed", Now: 170})
	if !updated.OK || updated.Value.DisplayName != "Renamed" {
		t.Fatalf("profile update = %#v", updated)
	}
	state := OAuthState{State: "state-1", Provider: "discord", RedirectBinding: "redirect-1", ExpiresAt: 300}
	if issuedState := callResult[OAuthState](t, cell.oauthStateIssue, OAuthStateIssueRequest{RequestID: "state-issue", State: state}); !issuedState.OK {
		t.Fatalf("state issue = %#v", issuedState)
	}
	if consumed := callResult[OAuthState](t, cell.oauthStateConsume, OAuthStateConsumeRequest{RequestID: "state-consume", State: state.State, Provider: "discord", RedirectBinding: "redirect-1", Now: 200}); !consumed.OK || consumed.Value.ConsumedAt != 200 {
		t.Fatalf("state consume = %#v", consumed)
	}
	if replay := callResult[OAuthState](t, cell.oauthStateConsume, OAuthStateConsumeRequest{RequestID: "state-consume-2", State: state.State, Provider: "discord", RedirectBinding: "redirect-1", Now: 201}); replay.OK || replay.Error == nil || replay.Error.Code != "invalid_state" {
		t.Fatalf("state replay = %#v", replay)
	}
}

func TestOAuthAccountCanAttachNativeCredentialWithoutChangingIdentity(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	oauth := callResult[OAuthUpsertResult](t, cell.oauthUpsert, OAuthUpsertRequest{
		RequestID: "oauth-upsert", AccountID: "oauth-account", LinkID: "discord-link", Provider: "discord", ProviderID: "discord-user",
		ProviderEmail: "member@example.test", Now: 100,
	})
	if !oauth.OK || !oauth.Value.Created || oauth.Value.Account.AccountID != "oauth-account" {
		t.Fatalf("oauth upsert = %#v", oauth)
	}
	attached := callResult[AccountProjection](t, cell.nativeCredentialAttach, NativeCredentialAttachRequest{
		RequestID: "attach-native", AccountID: "oauth-account", CredentialID: "native-credential", Email: "member@example.test",
		Username: "Member", Password: "password-1", Now: 110,
	})
	if !attached.OK || attached.Value.AccountID != "oauth-account" || attached.Value.CreatedAt != 100 {
		t.Fatalf("attached = %#v", attached)
	}
	login := callResult[AccountProjection](t, cell.nativeAuthenticate, NativeAuthenticateRequest{Email: "MEMBER@example.test", Password: "password-1"})
	if !login.OK || login.Value.AccountID != "oauth-account" {
		t.Fatalf("native login = %#v", login)
	}
	if duplicate := callResult[AccountProjection](t, cell.nativeCredentialAttach, NativeCredentialAttachRequest{
		RequestID: "attach-native-again", AccountID: "oauth-account", CredentialID: "native-credential-2", Email: "member@example.test",
		Username: "Member", Password: "password-2", Now: 120,
	}); duplicate.OK || duplicate.Error == nil || duplicate.Error.Code != "native_exists" {
		t.Fatalf("duplicate attach = %#v", duplicate)
	}
}

func TestRetentionLeasesGuardDeletionAndExpireByCallerPolicy(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	registered := callResult[AccountProjection](t, cell.nativeRegister, NativeRegisterRequest{
		RequestID: "register", AccountID: "account", CredentialID: "credential", Email: "member@example.test", Username: "Member", Password: "password-1", Now: 100,
	})
	if !registered.OK {
		t.Fatalf("register = %#v", registered)
	}
	lease := RetentionLease{AccountID: "account", LeaseID: "lease-1", ReasonID: "opaque-reason-1", ExpiresAt: 200}
	created := callResult[RetentionLease](t, cell.retentionLeaseCreate, RetentionLeaseCreateRequest{RequestID: "retain", Lease: lease, Now: 101})
	if !created.OK || created.Value != lease {
		t.Fatalf("create = %#v", created)
	}
	renewedLease := lease
	renewedLease.ExpiresAt = 300
	renewed := callResult[RetentionLease](t, cell.retentionLeaseRenew, RetentionLeaseRenewRequest{RequestID: "renew", Lease: renewedLease, Now: 120})
	if !renewed.OK || renewed.Value != renewedLease {
		t.Fatalf("renew = %#v", renewed)
	}
	blocked := callResult[AccountProjection](t, cell.accountDelete, AccountDeleteRequest{RequestID: "delete-blocked", AccountID: "account", Password: "password-1", Now: 150})
	if blocked.OK || blocked.Error == nil || blocked.Error.Code != "retention_active" {
		t.Fatalf("delete while retained = %#v", blocked)
	}
	listed := callResult[RetentionLeaseListResult](t, cell.retentionLeaseList, RetentionLeaseListRequest{AccountID: "account", Now: 150})
	if !listed.OK || len(listed.Value.Leases) != 1 || listed.Value.Leases[0].ReasonID != "opaque-reason-1" {
		t.Fatalf("list = %#v", listed)
	}
	released := callResult[RetentionEligibility](t, cell.retentionLeaseRelease, RetentionLeaseReleaseRequest{RequestID: "release", AccountID: "account", LeaseID: "lease-1", ReasonID: "opaque-reason-1", Now: 160})
	if !released.OK || !released.Value.Deletable || len(released.Value.LiveLeases) != 0 {
		t.Fatalf("release = %#v", released)
	}
	if deleted := callResult[AccountProjection](t, cell.accountDelete, AccountDeleteRequest{RequestID: "delete", AccountID: "account", Password: "password-1", Now: 161}); !deleted.OK {
		t.Fatalf("delete after release = %#v", deleted)
	}

	second := newTestOwner(t, &memoryEventStore{})
	if !callResult[AccountProjection](t, second.nativeRegister, NativeRegisterRequest{RequestID: "register", AccountID: "account", CredentialID: "credential", Email: "member@example.test", Username: "Member", Password: "password-1", Now: 100}).OK {
		t.Fatal("second register failed")
	}
	if !callResult[RetentionLease](t, second.retentionLeaseCreate, RetentionLeaseCreateRequest{RequestID: "retain", Lease: RetentionLease{AccountID: "account", LeaseID: "lease-2", ReasonID: "opaque-reason-2", ExpiresAt: 200}, Now: 101}).OK {
		t.Fatal("second retain failed")
	}
	expired := callResult[RetentionEligibility](t, second.retentionEligibility, RetentionEligibilityRequest{AccountID: "account", Now: 200})
	if !expired.OK || !expired.Value.Deletable || len(expired.Value.LiveLeases) != 0 {
		t.Fatalf("expired eligibility = %#v", expired)
	}
	if deleted := callResult[AccountProjection](t, second.accountDelete, AccountDeleteRequest{RequestID: "delete-expired", AccountID: "account", Password: "password-1", Now: 200}); !deleted.OK {
		t.Fatalf("delete after expiry = %#v", deleted)
	}
}

func TestEmailEffectUsesFencedLeaseAndDurableReceipt(t *testing.T) {
	store := &memoryEventStore{}
	cell := newTestOwner(t, store)
	register := NativeRegisterRequest{RequestID: "register", AccountID: "account", CredentialID: "credential", Email: "member@example.test", Username: "Member", Password: "password-1", Now: 100}
	if !callResult[AccountProjection](t, cell.nativeRegister, register).OK {
		t.Fatal("register failed")
	}
	now := time.Now().UTC().UnixMilli()
	issue := PasswordResetIssueRequest{RequestID: "issue", OTPID: "otp", EffectID: "email", Email: register.Email, Code: "ABC123", Now: now, ExpiresAt: now + int64((10 * time.Minute).Milliseconds())}
	if !callResult[PasswordResetIssueResult](t, cell.passwordResetIssue, issue).OK {
		t.Fatal("issue failed")
	}
	claimRequest, err := effect.NewClaimRequest(effectOwner, "worker-1", 1, 10000)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := msgpack.Marshal(claimRequest)
	response, err := cell.effectsClaim(raw)
	if err != nil {
		t.Fatal(err)
	}
	var claimed effect.ClaimResult
	if err := msgpack.Unmarshal(response, &claimed); err != nil {
		t.Fatal(err)
	}
	if len(claimed.Leases) != 1 || claimed.Leases[0].Intent.Kind != effect.KindNotificationEmailSend {
		t.Fatalf("claim = %#v", claimed)
	}
	var encrypted []byte
	if err := msgpack.Unmarshal(claimed.Leases[0].Intent.Payload, &encrypted); err != nil {
		t.Fatal(err)
	}
	plain, _, err := cell.otpKeys.Open(claimed.Leases[0].Intent.ID, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var payload notificationEmailPayload
	if err := msgpack.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.To != register.Email || payload.Subject != "Password reset code" || payload.Text == "" {
		t.Fatalf("notification payload = %#v", payload)
	}
	receipt, err := effect.NewCompletedReceipt(claimed.Leases[0].Intent, map[string]bool{"sent": true})
	if err != nil {
		t.Fatal(err)
	}
	ack := effect.AcknowledgeRequest{Version: effect.OutboxVersionV1, Owner: effectOwner, ConsumerID: "worker-1", LeaseID: claimed.Leases[0].LeaseID, Receipt: receipt}
	raw, _ = msgpack.Marshal(ack)
	response, err = cell.effectsAck(raw)
	if err != nil {
		t.Fatal(err)
	}
	var settled effect.SettlementResult
	if err := msgpack.Unmarshal(response, &settled); err != nil || !settled.Settled {
		t.Fatalf("settled = %#v, %v", settled, err)
	}
	recordsBeforeIdleClaim := len(store.records)
	raw, _ = msgpack.Marshal(claimRequest)
	response, err = cell.effectsClaim(raw)
	if err != nil {
		t.Fatal(err)
	}
	var idle effect.ClaimResult
	if err := msgpack.Unmarshal(response, &idle); err != nil || len(idle.Leases) != 0 {
		t.Fatalf("idle claim = %#v, %v", idle, err)
	}
	if len(store.records) != recordsBeforeIdleClaim {
		t.Fatalf("idle claim persisted a command: before=%d after=%d", recordsBeforeIdleClaim, len(store.records))
	}
	reopened := newTestOwner(t, store)
	if reopened.state.Effects["email"].Receipt == nil || reopened.state.Effects["email"].Status != string(effect.Completed) {
		t.Fatalf("receipt did not survive reopen: %#v", reopened.state.Effects["email"])
	}
}

func TestSessionsEmailVerificationCreatesAndReusesTemporaryIdentity(t *testing.T) {
	store := &memoryEventStore{}
	cell := newTestOwner(t, store)
	issue := EmailVerificationIssueRequest{
		RequestID: "sessions-verify-issue", VerificationID: "verification-1", EffectID: "verification-email-1",
		Email: " Player@Example.Test ", Code: "123456", Now: 100, ExpiresAt: 1900,
	}
	issued := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, issue)
	if !issued.OK || !issued.Value.Accepted || !issued.Value.EffectQueued {
		t.Fatalf("issue = %#v", issued)
	}
	queued := cell.state.Effects[issue.EffectID]
	var encrypted []byte
	if err := msgpack.Unmarshal(queued.Intent.Payload, &encrypted); err != nil {
		t.Fatal(err)
	}
	plain, envelope, err := cell.otpKeys.Open(queued.Intent.ID, encrypted)
	if err != nil || envelope.Recipient != "player@example.test" {
		t.Fatalf("encrypted delivery envelope = %#v %v", envelope, err)
	}
	var email notificationEmailPayload
	if err := msgpack.Unmarshal(plain, &email); err != nil ||
		email.To != "player@example.test" || email.Subject == "" || email.Text == "" {
		t.Fatalf("verification delivery was not bound to the one normalized request email: %#v %v", email, err)
	}
	if got := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, issue); !got.OK || got.Value != issued.Value {
		t.Fatalf("idempotent issue = %#v", got)
	}
	verified := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, EmailVerificationConsumeRequest{
		RequestID: "sessions-verify-consume", AccountID: "temporary-account-1", Email: "player@example.test", Code: "123456", Now: 200,
	})
	if !verified.OK || !verified.Value.Verified || verified.Value.AccountID != "temporary-account-1" {
		t.Fatalf("consume = %#v", verified)
	}
	secondIssue := EmailVerificationIssueRequest{
		RequestID: "sessions-verify-issue-2", VerificationID: "verification-2", EffectID: "verification-email-2",
		Email: "player@example.test", Code: "654321", Now: 300, ExpiresAt: 1900,
	}
	if got := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, secondIssue); !got.OK || !got.Value.Accepted {
		t.Fatalf("second issue = %#v", got)
	}
	reused := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, EmailVerificationConsumeRequest{
		RequestID: "sessions-verify-consume-2", AccountID: "must-not-fork-account", Email: "player@example.test", Code: "654321", Now: 400,
	})
	if !reused.OK || !reused.Value.Verified || reused.Value.AccountID != "temporary-account-1" {
		t.Fatalf("reused identity = %#v", reused)
	}
	if replay := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, EmailVerificationConsumeRequest{
		RequestID: "sessions-verify-consume-3", Email: "player@example.test", Code: "123456", Now: 401,
	}); replay.OK || replay.Error == nil || replay.Error.Code != "invalid_code" {
		t.Fatalf("single-use replay = %#v", replay)
	}
	reopened := newTestOwner(t, store)
	if got := callResult[EmailVerificationConsumeResult](t, reopened.emailVerificationConsume, EmailVerificationConsumeRequest{
		RequestID: "sessions-verify-consume-4", Email: "player@example.test", Code: "123456", Now: 402,
	}); got.OK || got.Error == nil || got.Error.Code != "invalid_code" {
		t.Fatalf("restart replay = %#v", got)
	}
}

func TestSessionsEmailVerificationAcceptsEarlierCodeWhileReplacementIsInFlight(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	for _, issue := range []EmailVerificationIssueRequest{
		{RequestID: "issue-earlier", VerificationID: "verification-earlier", EffectID: "effect-earlier", Email: "player@example.test", Code: "111111", Now: 100, ExpiresAt: 1900},
		{RequestID: "issue-newer", VerificationID: "verification-newer", EffectID: "effect-newer", Email: "player@example.test", Code: "222222", Now: 101, ExpiresAt: 1901},
	} {
		if got := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, issue); !got.OK || !got.Value.Accepted {
			t.Fatalf("issue = %#v", got)
		}
	}
	verified := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, EmailVerificationConsumeRequest{
		RequestID: "consume-earlier", AccountID: "temporary-account", Email: "player@example.test", Code: "111111", Now: 200,
	})
	if !verified.OK || !verified.Value.Verified {
		t.Fatalf("earlier delivered code = %#v", verified)
	}
	if replay := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, EmailVerificationConsumeRequest{
		RequestID: "consume-newer-after-success", Email: "player@example.test", Code: "222222", Now: 201,
	}); replay.OK || replay.Error == nil || replay.Error.Code != "invalid_code" {
		t.Fatalf("outstanding replacement survived successful login: %#v", replay)
	}
}

func TestEmailVerificationIssueIsOwnerThrottledBoundedAndHashed(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	for index := 0; index < emailVerificationOutstanding+1; index++ {
		request := EmailVerificationIssueRequest{
			RequestID: fmt.Sprintf("issue-%d", index), VerificationID: fmt.Sprintf("otp-%d", index),
			EffectID: fmt.Sprintf("effect-%d", index), Email: " Player@Example.Test ", CallerKey: "192.0.2.10",
			Code: fmt.Sprintf("12345%d", index), Now: 100 + int64(index), ExpiresAt: 1000,
		}
		result := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, request)
		if !result.OK || !result.Value.Accepted {
			t.Fatalf("issue %d = %#v", index, result)
		}
		if index < emailVerificationOutstanding && !result.Value.EffectQueued {
			t.Fatalf("issue %d did not queue", index)
		}
		if index == emailVerificationOutstanding && result.Value.EffectQueued {
			t.Fatal("throttled issue queued an effect")
		}
	}
	if len(cell.state.OTPs) != emailVerificationOutstanding || len(cell.state.Effects) != emailVerificationOutstanding {
		t.Fatalf("unbounded verification state: otps=%d effects=%d", len(cell.state.OTPs), len(cell.state.Effects))
	}
	for _, record := range cell.state.OTPs {
		if record.Email != "player@example.test" || record.Code != "" || len(record.CodeHash) != 64 {
			t.Fatalf("OTP material or recipient is not canonical: %#v", record)
		}
	}
	snapshotWire, err := msgpack.Marshal(cell.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("123450"), cell.otpKeys.Current} {
		if bytes.Contains(snapshotWire, forbidden) {
			t.Fatalf("snapshot persisted OTP secret material %q", forbidden)
		}
	}
	if _, exists := cell.state.Rates[rateKey("email_verification_issue_caller", "192.0.2.10")]; exists {
		t.Fatal("raw caller signal was persisted")
	}
}

func TestEmailVerificationIssuePrunesExpiredOTPAndDeliveryEffect(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	first := EmailVerificationIssueRequest{RequestID: "first", VerificationID: "old-otp", EffectID: "old-effect", Email: "player@example.test", Code: "123456", Now: 100, ExpiresAt: 200}
	if got := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, first); !got.OK || !got.Value.EffectQueued {
		t.Fatalf("first issue = %#v", got)
	}
	second := EmailVerificationIssueRequest{RequestID: "second", VerificationID: "new-otp", EffectID: "new-effect", Email: "player@example.test", Code: "654321", Now: 201, ExpiresAt: 400}
	if got := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, second); !got.OK || !got.Value.EffectQueued {
		t.Fatalf("second issue = %#v", got)
	}
	if _, exists := cell.state.OTPs[first.VerificationID]; exists {
		t.Fatal("expired OTP survived issuance pruning")
	}
	if _, exists := cell.state.Effects[first.EffectID]; exists {
		t.Fatal("expired delivery effect survived issuance pruning")
	}
}

func TestEmailVerificationEffectIdentityCannotReuseEncryptionNonce(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	first := EmailVerificationIssueRequest{RequestID: "first-effect", VerificationID: "otp-1", EffectID: "fixed-effect", Email: "one@example.test", Code: "123456", Now: 100, ExpiresAt: 1000}
	if got := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, first); !got.OK {
		t.Fatalf("first=%#v", got)
	}
	second := EmailVerificationIssueRequest{RequestID: "second-effect", VerificationID: "otp-2", EffectID: "fixed-effect", Email: "two@example.test", Code: "654321", Now: 101, ExpiresAt: 1000}
	got := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, second)
	if got.OK || got.Error == nil || got.Error.Code != "idempotency_conflict" {
		t.Fatalf("effect identity reuse=%#v", got)
	}
}

func TestEmailVerificationIssueThrottlesHashedCallerAcrossRecipients(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	for index := 0; index <= emailVerificationCallerMax; index++ {
		request := EmailVerificationIssueRequest{
			RequestID: fmt.Sprintf("caller-issue-%d", index), VerificationID: fmt.Sprintf("caller-otp-%d", index),
			EffectID: fmt.Sprintf("caller-effect-%d", index), Email: fmt.Sprintf("player-%d@example.test", index),
			CallerKey: "198.51.100.4", Code: fmt.Sprintf("%06d", index), Now: 100 + int64(index), ExpiresAt: 1000,
		}
		result := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, request)
		if !result.OK || !result.Value.Accepted {
			t.Fatalf("caller issue %d = %#v", index, result)
		}
		if (index < emailVerificationCallerMax) != result.Value.EffectQueued {
			t.Fatalf("caller issue %d queued=%v", index, result.Value.EffectQueued)
		}
	}
	if len(cell.state.Effects) != emailVerificationCallerMax {
		t.Fatalf("caller throttle effects=%d want=%d", len(cell.state.Effects), emailVerificationCallerMax)
	}
}

func TestEmailVerificationConsumesLegacyPlaintextSnapshotOTP(t *testing.T) {
	state := newSnapshot()
	state.OTPs["legacy"] = otpRecord{ID: "legacy", Email: "player@example.test", Code: "123456", Type: "sessions_email_verification", ExpiresAt: 300}
	store := &memoryEventStore{records: []durableRecord{{
		Receipt:  commandReceipt{Operation: "legacy.seed", RequestID: "legacy", Digest: "legacy", Response: []byte("legacy")},
		Snapshot: state,
	}}}
	cell := newTestOwner(t, store)
	result := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, EmailVerificationConsumeRequest{
		RequestID: "consume-legacy", AccountID: "account", Email: "player@example.test", Code: "123456", Now: 200,
	})
	if !result.OK || !result.Value.Verified {
		t.Fatalf("legacy OTP compatibility = %#v", result)
	}
}

func TestSessionsEmailVerificationReplaysSuccessAfterLostResponse(t *testing.T) {
	cell := newTestOwner(t, &memoryEventStore{})
	issued := callResult[EmailVerificationIssueResult](t, cell.emailVerificationIssue, EmailVerificationIssueRequest{
		RequestID: "issue", VerificationID: "verification", EffectID: "effect", Email: "player@example.test", Code: "123456", Now: 100, ExpiresAt: 1900,
	})
	if !issued.OK {
		t.Fatalf("issue = %#v", issued)
	}
	request := EmailVerificationConsumeRequest{RequestID: "stable-consume", AccountID: "stable-account", Email: "player@example.test", Code: "123456", Now: 200}
	first := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, request)
	request.Now = 201
	replayed := callResult[EmailVerificationConsumeResult](t, cell.emailVerificationConsume, request)
	if !first.OK || !first.Value.Verified || !replayed.OK || !replayed.Value.Verified || replayed.Value.AccountID != first.Value.AccountID {
		t.Fatalf("lost-success replay: first=%#v replay=%#v", first, replayed)
	}
}

func TestSQLiteSnapshotSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	store, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	cell := newTestOwner(t, store)
	request := NativeRegisterRequest{RequestID: "register", AccountID: "account", CredentialID: "credential", Email: "member@example.test", Username: "Member", Password: "password-1", Now: 100}
	if !callResult[AccountProjection](t, cell.nativeRegister, request).OK {
		t.Fatal("register failed")
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	reopened := newTestOwner(t, store)
	login := callResult[AccountProjection](t, reopened.nativeAuthenticate, NativeAuthenticateRequest{Email: request.Email, Password: request.Password})
	if !login.OK || login.Value.AccountID != request.AccountID {
		t.Fatalf("login after restart = %#v", login)
	}
	replay := callResult[AccountProjection](t, reopened.nativeRegister, request)
	if !replay.OK || replay.Value.AccountID != request.AccountID {
		t.Fatalf("replay after restart = %#v", replay)
	}
}

func TestLegacyImportPreservesCredentialAndReplaysAfterOwnerMutation(t *testing.T) {
	store := &memoryEventStore{}
	cell := newTestOwner(t, store)
	passwordHash, err := passwordcrypto.Hash("password-1")
	if err != nil {
		t.Fatal(err)
	}
	request := LegacyImportRequest{
		RequestID: "legacy-import:stable",
		Accounts:  []AccountProjection{{AccountID: "account", CreatedAt: 100}},
		Native: []LegacyNative{{
			ID: "credential", AccountID: "account", Email: "member@example.test",
			Username: "Member", PasswordHash: passwordHash,
			CreatedAt: 100,
		}},
	}
	imported := callResult[LegacyImportResult](t, cell.legacyImport, request)
	if !imported.OK || imported.Value.Native != 1 {
		t.Fatalf("import = %#v", imported)
	}
	loginRaw, err := msgpack.Marshal(NativeAuthenticateRequest{Email: "member@example.test", Password: "password-1"})
	if err != nil {
		t.Fatal(err)
	}
	loginWire, err := cell.nativeAuthenticate(loginRaw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(loginWire, []byte(request.Native[0].PasswordHash)) {
		t.Fatal("password hash leaked through authentication projection")
	}

	changed := callResult[map[string]any](t, cell.passwordChange, PasswordChangeRequest{
		RequestID: "change-after-import", AccountID: "account",
		CurrentPassword: "password-1", NewPassword: "password-2", Now: 110,
	})
	if !changed.OK {
		t.Fatalf("password change = %#v", changed)
	}
	replayed := callResult[LegacyImportResult](t, cell.legacyImport, request)
	if !replayed.OK {
		t.Fatalf("identical bootstrap import did not replay: %#v", replayed)
	}
	if oldLogin := callResult[AccountProjection](t, cell.nativeAuthenticate, NativeAuthenticateRequest{Email: "member@example.test", Password: "password-1"}); oldLogin.OK {
		t.Fatal("bootstrap replay reverted owner-managed password")
	}
	if newLogin := callResult[AccountProjection](t, cell.nativeAuthenticate, NativeAuthenticateRequest{Email: "member@example.test", Password: "password-2"}); !newLogin.OK {
		t.Fatalf("owner-managed password lost after import replay: %#v", newLogin)
	}
}
