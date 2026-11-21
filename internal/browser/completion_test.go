package browser

import (
	"testing"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/session"
	hostjwt "github.com/bananalabs-oss/bananauth/internal/token"
	"github.com/vmihailenco/msgpack/v5"
)

func TestCompleteEmailVerificationCreatesOwnedSignedSession(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000).UTC()
	var consumed, created map[string]any
	boundary := emailSessionCompleter{
		now: func() time.Time { return now },
		consumeLoginV2: typedFixture[identity.EmailVerificationConsumeRequest, identity.Result[identity.
			EmailVerificationConsumeResult]](func(wire []byte) ([]byte, error) {
			if err := msgpack.Unmarshal(wire, &consumed); err != nil {
				t.Fatal(err)
			}
			return msgpack.Marshal(map[string]any{"version": identityVersion, "ok": true, "value": map[string]any{"verified": true, "account_id": "account-1", "verified_email": "player@example.com", "email_verified_at_unix_milli": now.UnixMilli(), "email_verification_expires_at_unix_milli": now.Add(time.Minute).UnixMilli(), "verification_request_id": "email-session:v2:login:identity:123e4567-e89b-12d3-a456-426614174000"}})
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
	wire, _ := msgpack.Marshal(CompleteEmailVerificationRequest{Version: ContractVersion, RequestID: "123e4567-e89b-12d3-a456-426614174000", Email: " Player@Example.com ", Code: "123456"})
	result := boundary.completeValue(wire)
	if !result.OK || result.AccessToken != "signed-token" || result.AccountID != "account-1" || result.ExpiresIn != 86400 {
		t.Fatalf("unexpected completion result: %+v", result)
	}
	if consumed["email"] != "player@example.com" || consumed["code"] != "123456" {
		t.Fatalf("unexpected consume request: %#v", consumed)
	}
	if created["request_id"] != "email-session:v2:login:create:123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("session create is not replay-stable: %#v", created)
	}
}

func TestCompleteEmailVerificationRejectsMalformedInputBeforeOwnerCalls(t *testing.T) {
	called := false
	boundary := emailSessionCompleter{
		now: time.Now,
		consumeLoginV2: typedFixture[identity.EmailVerificationConsumeRequest, identity.Result[identity.
			EmailVerificationConsumeResult]](func([]byte) ([]byte, error) { called = true; return nil, nil }),
		create: typedFixture[session.CreateEmailVerifiedOwnedRequest, session.Result[session.
			Session]](func([]byte) ([]byte, error) { called = true; return nil, nil }),
		sign: func(hostjwt.SignRequest) (string, error) { called = true; return "", nil },
	}
	wire, _ := msgpack.Marshal(CompleteEmailVerificationRequest{Version: ContractVersion, RequestID: "not a request id", Email: "x", Code: "1"})
	result := boundary.completeValue(wire)
	if result.OK || result.Error != "invalid_request" || called {
		t.Fatalf("malformed request crossed owner boundary: %+v called=%v", result, called)
	}
}
