//go:build !wasip1

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
)

func openReplicaStore(t *testing.T, path string) *sqliteEventStore {
	t.Helper()
	store, err := openSQLite(path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.db.Close() })
	return store
}

func registerRequest(id, account, email string) NativeRegisterRequest {
	return NativeRegisterRequest{
		RequestID: id, AccountID: account, CredentialID: "credential-" + account,
		Email: email, Username: account, Password: "password-1", Now: 100,
	}
}

func TestStaleIdentityOwnersPreserveDistinctCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	first := newTestOwner(t, openReplicaStore(t, path))
	second := newTestOwner(t, openReplicaStore(t, path))

	if got := callResult[AccountProjection](t, first.nativeRegister, registerRequest("first", "account-a", "a@example.test")); !got.OK {
		t.Fatalf("first register = %#v", got)
	}
	if got := callResult[AccountProjection](t, second.nativeRegister, registerRequest("second", "account-b", "b@example.test")); !got.OK {
		t.Fatalf("stale second register = %#v", got)
	}

	restarted := newTestOwner(t, openReplicaStore(t, path))
	for _, email := range []string{"a@example.test", "b@example.test"} {
		if got := callResult[AccountProjection](t, restarted.nativeAuthenticate, NativeAuthenticateRequest{Email: email, Password: "password-1"}); !got.OK {
			t.Fatalf("authenticate %s after restart = %#v", email, got)
		}
	}
}

func TestConcurrentIdentityOwnersReplayOneDurableCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	firstStore := openReplicaStore(t, path)
	secondStore := openReplicaStore(t, path)
	first := newTestOwner(t, firstStore)
	second := newTestOwner(t, secondStore)
	request := registerRequest("same-request", "account", "member@example.test")

	start := make(chan struct{})
	responses := make([][]byte, 2)
	errors := make([]error, 2)
	var wait sync.WaitGroup
	for index, replica := range []*owner{first, second} {
		wait.Add(1)
		go func(index int, replica *owner) {
			defer wait.Done()
			<-start
			wire, _ := encode(request)
			responses[index], errors[index] = replica.nativeRegister(wire)
		}(index, replica)
	}
	close(start)
	wait.Wait()
	for _, err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(responses[0], responses[1]) {
		t.Fatalf("replicas returned different durable responses")
	}
	var commands, revision int64
	if err := firstStore.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM auth_identity_commands`).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	if err := firstStore.db.QueryRowContext(context.Background(), `SELECT revision FROM auth_identity_head WHERE singleton=1`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if commands != 1 || revision != 1 {
		t.Fatalf("commands=%d revision=%d, want 1/1", commands, revision)
	}

	restarted := newTestOwner(t, openReplicaStore(t, path))
	wire, _ := encode(request)
	replayed, err := restarted.nativeRegister(wire)
	if err != nil || !bytes.Equal(replayed, responses[0]) {
		t.Fatalf("restart replay differs: err=%v", err)
	}
	conflict := request
	conflict.Email = "other@example.test"
	got := callResult[AccountProjection](t, restarted.nativeRegister, conflict)
	if got.OK || got.Error == nil || got.Error.Code != "idempotency_conflict" {
		t.Fatalf("conflicting replay = %#v", got)
	}
}
