package main

import (
	"testing"
	"time"

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

func TestOwnerClockCreateReplaysExactReceipt(t *testing.T) {
	clock := time.UnixMilli(1_800_000_000_000)
	cell := newOwner(newMemoryStore())
	cell.now = func() time.Time { return clock }
	request := CreateOwnedRequest{RequestID: "login-1", SessionID: "session-1", AccountID: "account-1", LifetimeMillis: 60_000}
	first := call[Session](t, cell.createOwned, request)
	if !first.OK || first.Value.CreatedAt != clock.UnixMilli() || first.Value.ExpiresAt != clock.Add(time.Minute).UnixMilli() {
		t.Fatalf("first = %#v", first)
	}
	clock = clock.Add(10 * time.Second)
	replay := call[Session](t, cell.createOwned, request)
	if !replay.OK || replay.Value != first.Value {
		t.Fatalf("replay = %#v, want %#v", replay, first)
	}
	changed := request
	changed.AccountID = "attacker"
	conflict := call[Session](t, cell.createOwned, changed)
	if conflict.OK || conflict.Error == nil || conflict.Error.Code != "idempotency_conflict" {
		t.Fatalf("changed request = %#v", conflict)
	}
}

func TestOwnerClockRevokeReplaysExactReceipt(t *testing.T) {
	clock := time.UnixMilli(1_800_000_000_000)
	cell := newOwner(newMemoryStore())
	cell.now = func() time.Time { return clock }
	created := call[Session](t, cell.createOwned, CreateOwnedRequest{RequestID: "create", SessionID: "session", AccountID: "account", LifetimeMillis: 60_000})
	if !created.OK {
		t.Fatalf("create = %#v", created)
	}
	request := RevokeOwnedRequest{RequestID: "logout", SessionID: "session"}
	first := call[Session](t, cell.revokeOwned, request)
	if !first.OK || first.Value.RevokedAt != clock.UnixMilli() || first.Value.Active {
		t.Fatalf("revoke = %#v", first)
	}
	clock = clock.Add(time.Second)
	replay := call[Session](t, cell.revokeOwned, request)
	if !replay.OK || replay.Value != first.Value {
		t.Fatalf("replay = %#v", replay)
	}
	changed := request
	changed.SessionID = "other"
	conflict := call[Session](t, cell.revokeOwned, changed)
	if conflict.OK || conflict.Error == nil || conflict.Error.Code != "idempotency_conflict" {
		t.Fatalf("changed = %#v", conflict)
	}
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
