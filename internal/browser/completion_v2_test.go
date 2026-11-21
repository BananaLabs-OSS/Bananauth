package browser

import (
	"errors"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/session"
	hostjwt "github.com/bananalabs-oss/bananauth/internal/token"
	"github.com/vmihailenco/msgpack/v5"
	"testing"
	"time"
)

func TestV2SignupCompletesOwnedSessionWithoutLegacyFallback(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	var consumed, created map[string]any
	boundary := emailSessionCompleter{
		now: func() time.Time { return now },
		consumeSignupV2: typedFixture[identity.EmailVerificationConsumeRequest, identity.Result[identity.
			EmailVerificationConsumeResult]](func(wire []byte) ([]byte, error) {
			if err := msgpack.Unmarshal(wire, &consumed); err != nil {
				t.Fatal(err)
			}
			return msgpack.Marshal(map[string]any{"version": identityVersion, "ok": true, "value": map[string]any{"verified": true, "account_id": "account-1", "verified_email": "player@example.com", "email_verified_at_unix_milli": now.UnixMilli(), "email_verification_expires_at_unix_milli": now.Add(time.Minute).UnixMilli(), "verification_request_id": "email-session:v2:signup:identity:123e4567-e89b-12d3-a456-426614174000"}})
		}),
		create: typedFixture[session.CreateEmailVerifiedOwnedRequest, session.Result[session.
			Session]](func(wire []byte) ([]byte, error) {
			if err := msgpack.Unmarshal(wire, &created); err != nil {
				t.Fatal(err)
			}
			return msgpack.Marshal(map[string]any{"version": sessionContractVersion, "ok": true, "value": map[string]any{
				"session_id": created["session_id"], "account_id": "account-1", "expires_at": now.Add(24 * time.Hour).UnixMilli(), "active": true,
				"created_at": now.UnixMilli(), "verified_email": created["verified_email"], "email_verified_at_unix_milli": created["email_verified_at_unix_milli"], "email_verification_expires_at_unix_milli": created["email_verification_expires_at_unix_milli"], "verification_request_id": created["verification_request_id"],
			}})
		}),
		sign: func(request hostjwt.SignRequest) (string, error) {
			if request.AccountID != "account-1" || request.SessionID != created["session_id"] || request.ExpiresAt != now.Add(24*time.Hour).UnixMilli() {
				t.Fatalf("unexpected sign request: %+v", request)
			}
			return "signed-token", nil
		},
	}
	wire, _ := msgpack.Marshal(CompleteEmailVerificationRequestV2{Intent: "signup", Version: ContractVersion, RequestID: "123e4567-e89b-12d3-a456-426614174000", Email: " Player@Example.com ", Code: "123456"})
	response, err := boundary.completeV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	var result CompleteEmailVerificationResult
	if err := msgpack.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.AccessToken != "signed-token" || result.AccountID != "account-1" || result.ExpiresIn != 86400 {
		t.Fatalf("unexpected completion result: %+v", result)
	}
	if consumed["email"] != "player@example.com" || consumed["code"] != "123456" {
		t.Fatalf("unexpected consume request: %#v", consumed)
	}
	if created["request_id"] != "email-session:v2:signup:create:123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("session create is not replay-stable: %#v", created)
	}
}

func TestV2IntentSelectionCannotFallBackToV1(t *testing.T) {
	for _, intent := range []string{"login", "signup", "", "arbitrary"} {
		legacy, login, signup := 0, 0, 0
		c := emailSessionCompleter{now: time.Now, consume: typedFixture[identity.EmailVerificationConsumeRequest, identity.Result[identity.
			EmailVerificationConsumeResult]](func([]byte) ([]byte, error) { legacy++; return nil, nil }), consumeLoginV2: typedFixture[identity.EmailVerificationConsumeRequest, identity.Result[identity.
			EmailVerificationConsumeResult]](func([]byte) ([]byte, error) { login++; return nil, errors.New("test") }), consumeSignupV2: typedFixture[identity.EmailVerificationConsumeRequest, identity.Result[identity.
			EmailVerificationConsumeResult]](func([]byte) ([]byte, error) { signup++; return nil, errors.New("test") }), create: typedFixture[session.CreateEmailVerifiedOwnedRequest, session.Result[session.
			Session]](func([]byte) ([]byte, error) { t.Fatal("unverified create"); return nil, nil }), sign: func(hostjwt.SignRequest) (string, error) { t.Fatal("unverified sign"); return "", nil }}
		wire, _ := msgpack.Marshal(CompleteEmailVerificationRequestV2{Version: ContractVersion, RequestID: "123e4567-e89b-12d3-a456-426614174000", Email: "player@example.test", Code: "123456", Intent: intent})
		raw, err := c.completeV2(wire)
		if err != nil {
			t.Fatal(err)
		}
		var result CompleteEmailVerificationResult
		msgpack.Unmarshal(raw, &result)
		if legacy != 0 || result.OK || ((intent == "login" || intent == "") && login != 1) || (intent == "signup" && signup != 1) || (intent == "arbitrary" && (signup != 0 || login != 0)) {
			t.Fatalf("intent=%q legacy=%d login=%d signup=%d result=%+v", intent, legacy, login, signup, result)
		}
	}
	c := emailSessionCompleter{now: time.Now, consume: typedFixture[identity.EmailVerificationConsumeRequest, identity.Result[identity.
		EmailVerificationConsumeResult]](func([]byte) ([]byte, error) { t.Fatal("legacy fallback"); return nil, nil }), create: typedFixture[session.CreateEmailVerifiedOwnedRequest, session.Result[session.
		Session]](func([]byte) ([]byte, error) { return nil, nil }), sign: func(hostjwt.SignRequest) (string, error) { return "", nil }}
	wire, _ := msgpack.Marshal(CompleteEmailVerificationRequestV2{Version: ContractVersion, RequestID: "123e4567-e89b-12d3-a456-426614174000", Email: "player@example.test", Code: "123456", Intent: "login"})
	raw, _ := c.completeV2(wire)
	var result CompleteEmailVerificationResult
	msgpack.Unmarshal(raw, &result)
	if result.OK || result.Error != "unavailable" {
		t.Fatal(result)
	}
}
