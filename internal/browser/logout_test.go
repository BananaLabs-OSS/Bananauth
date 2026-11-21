package browser

import (
	"errors"

	"github.com/bananalabs-oss/bananauth/internal/session"
	"github.com/vmihailenco/msgpack/v5"
	"testing"
)

func TestLogoutRevokesOnlyVerifiedSessionAndRejectsReplay(t *testing.T) {
	boundary := validResolver()
	active := true
	calls := 0
	boundary.get = func(request sessionGetRequest) (sessionGetResult, error) {
		return sessionGetResult{Version: sessionContractVersion, OK: true, Value: sessionFact{AccountID: "account_01", SessionID: request.SessionID, Active: active, ExpiresAt: fixedNow.Add(3600000000000).UnixMilli()}}, nil
	}
	revoker := sessionRevoker{resolver: boundary, revoke: typedFixture[session.RevokeOwnedRequest, session.Result[session.
		Session]](func(raw []byte) ([]byte, error) {
		calls++
		var request map[string]string
		if err := msgpack.Unmarshal(raw, &request); err != nil {
			t.Fatal(err)
		}
		if len(request) != 2 || request["session_id"] != "session_01" || request["request_id"] != "browser-logout:session_01" {
			t.Fatalf("wrong target: %#v", request)
		}
		active = false
		return msgpack.Marshal(sessionGetResult{Version: sessionContractVersion, OK: true, Value: sessionFact{AccountID: "account_01", SessionID: "session_01", RevokedAt: fixedNow.UnixMilli()}})
	})}
	invoke := func(request any) logoutResult {
		raw, _ := msgpack.Marshal(request)
		response, err := revoker.logout(raw)
		if err != nil {
			t.Fatal(err)
		}
		var result logoutResult
		if err := msgpack.Unmarshal(response, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	forged := validRequest()
	forged.Credential = "Bearer forged"
	if got := invoke(forged); got.OK || calls != 0 {
		t.Fatal("forged credential mutated session")
	}
	if got := invoke(map[string]any{"version": ContractVersion, "audience": AccountAudience, "credential": "Bearer signed.jwt.value", "session_id": "victim"}); got.OK || calls != 0 {
		t.Fatal("caller selected a victim session")
	}
	if got := invoke(validRequest()); !got.OK || calls != 1 || active {
		t.Fatalf("logout failed: %#v", got)
	}
	if got := invoke(validRequest()); got.OK || got.Error != "unauthorized" || calls != 1 {
		t.Fatalf("replay remained active: %#v", got)
	}
}

func TestLogoutRequiresAuthoritativeRevocationReceipt(t *testing.T) {
	good := sessionGetResult{Version: sessionContractVersion, OK: true, Value: sessionFact{AccountID: "account_01", SessionID: "session_01", RevokedAt: fixedNow.UnixMilli()}}
	for _, kind := range []string{"transport", "malformed", "version", "denied", "active", "wrong_session", "wrong_account", "missing_time"} {
		t.Run(kind, func(t *testing.T) {
			receipt := good
			r := sessionRevoker{resolver: validResolver(), revoke: typedFixture[session.RevokeOwnedRequest, session.Result[session.
				Session]](func([]byte) ([]byte, error) {
				switch kind {
				case "transport":
					return nil, errors.New("private backend detail")
				case "malformed":
					return []byte{0xc1}, nil
				case "version":
					receipt.Version = "unknown"
				case "denied":
					receipt.OK = false
				case "active":
					receipt.Value.Active = true
				case "wrong_session":
					receipt.Value.SessionID = "victim"
				case "wrong_account":
					receipt.Value.AccountID = "victim"
				case "missing_time":
					receipt.Value.RevokedAt = 0
				}
				return msgpack.Marshal(receipt)
			})}
			raw, _ := msgpack.Marshal(validRequest())
			response, err := r.logout(raw)
			if err != nil {
				t.Fatal(err)
			}
			var result logoutResult
			msgpack.Unmarshal(response, &result)
			if result.OK || result.Error != "unavailable" {
				t.Fatalf("invalid receipt accepted: %#v", result)
			}
		})
	}
}
