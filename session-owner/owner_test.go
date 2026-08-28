package main

import (
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func call[T any](t *testing.T, provider func([]byte) ([]byte, error), request any) Result[T] {
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

func TestOwnerSessionLifecycleIsIdempotentAndExpiryAware(t *testing.T) {
	cell := newOwner(newMemoryStore())
	created := call[Session](t, cell.create, CreateRequest{
		RequestID: "create-1", SessionID: "session-1", AccountID: "account-1",
		CreatedAt: 100, ExpiresAt: 200,
	})
	if !created.OK || !created.Value.Active {
		t.Fatalf("create = %#v", created)
	}
	replayed := call[Session](t, cell.create, CreateRequest{
		RequestID: "create-1", SessionID: "session-1", AccountID: "account-1",
		CreatedAt: 100, ExpiresAt: 200,
	})
	if !replayed.OK || replayed.Value != created.Value {
		t.Fatalf("replay = %#v", replayed)
	}
	expired := call[Session](t, cell.get, GetRequest{SessionID: "session-1", Now: 200})
	if !expired.OK || expired.Value.Active {
		t.Fatalf("expired = %#v", expired)
	}
	revoked := call[Session](t, cell.revoke, RevokeRequest{RequestID: "revoke-1", SessionID: "session-1", RevokedAt: 150})
	if !revoked.OK || revoked.Value.Active || revoked.Value.RevokedAt != 150 {
		t.Fatalf("revoke = %#v", revoked)
	}
	replayedRevoke := call[Session](t, cell.revoke, RevokeRequest{RequestID: "revoke-1", SessionID: "session-1", RevokedAt: 999})
	if replayedRevoke.OK || replayedRevoke.Error == nil {
		t.Fatalf("reused revoke request id accepted different payload: %#v", replayedRevoke)
	}
}

func TestOwnerAllowsSameRequestIDAcrossOperationsButBindsPayload(t *testing.T) {
	cell := newOwner(newMemoryStore())
	created := call[Session](t, cell.create, CreateRequest{
		RequestID: "same-id", SessionID: "session-1", AccountID: "account-1",
		CreatedAt: 100, ExpiresAt: 200,
	})
	if !created.OK {
		t.Fatalf("create = %#v", created)
	}
	revoked := call[Session](t, cell.revoke, RevokeRequest{RequestID: "same-id", SessionID: "session-1", RevokedAt: 150})
	if !revoked.OK {
		t.Fatalf("revoke = %#v", revoked)
	}
}
