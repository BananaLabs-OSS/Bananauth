package main

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSQLiteStoreSurvivesRestartAndDeduplicatesCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	open := func() (*sql.DB, *sqliteStore) {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		store, err := newSQLiteStore(db)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		return db, store
	}

	db, store := open()
	created, err := store.Create(CreateRequest{
		RequestID: "create-restart", SessionID: "session-restart", AccountID: "account-restart",
		CreatedAt: 100, ExpiresAt: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, store = open()
	defer db.Close()
	loaded, ok, err := store.Get("session-restart")
	if err != nil || !ok || loaded != created {
		t.Fatalf("loaded after restart = %#v, %v, %v", loaded, ok, err)
	}
	replayed, err := store.Create(CreateRequest{
		RequestID: "create-restart", SessionID: "session-restart", AccountID: "account-restart",
		CreatedAt: 100, ExpiresAt: 300,
	})
	if err != nil || replayed != created {
		t.Fatalf("replayed create = %#v, %v", replayed, err)
	}
	if _, err := store.Create(CreateRequest{
		RequestID: "create-restart", SessionID: "different", AccountID: "different",
		CreatedAt: 999, ExpiresAt: 1000,
	}); err == nil {
		t.Fatal("reused request id accepted a different create payload")
	}
	if _, ok, err := store.Revoke(RevokeRequest{RequestID: "revoke-restart", SessionID: "session-restart", RevokedAt: 200}); err != nil || !ok {
		t.Fatalf("revoke = %v, %v", ok, err)
	}
}

func TestSQLiteStoreCreateAndReceiptRollbackTogether(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "create-crash.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := newSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_create_receipt BEFORE INSERT ON auth_session_commands
		WHEN NEW.operation='create' BEGIN SELECT RAISE(ABORT, 'simulated receipt crash'); END`); err != nil {
		t.Fatal(err)
	}
	request := CreateRequest{RequestID: "atomic-create", SessionID: "atomic-session", AccountID: "atomic-account", CreatedAt: 100, ExpiresAt: 300}
	if _, err = store.Create(request); err == nil {
		t.Fatal("simulated command receipt failure succeeded")
	}
	if _, ok, err := store.Get(request.SessionID); err != nil || ok {
		t.Fatalf("session escaped rolled-back create: ok=%v err=%v", ok, err)
	}
	if _, err = db.Exec(`DROP TRIGGER fail_create_receipt`); err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(request)
	if err != nil || created.SessionID != request.SessionID {
		t.Fatalf("create after rollback = %#v, %v", created, err)
	}
}

func TestSQLiteStoreRevokeAndReceiptRollbackTogether(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "revoke-crash.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := newSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	create := CreateRequest{RequestID: "create", SessionID: "session", AccountID: "account", CreatedAt: 100, ExpiresAt: 300}
	if _, err = store.Create(create); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_revoke_receipt BEFORE INSERT ON auth_session_commands
		WHEN NEW.operation='revoke' BEGIN SELECT RAISE(ABORT, 'simulated receipt crash'); END`); err != nil {
		t.Fatal(err)
	}
	revoke := RevokeRequest{RequestID: "atomic-revoke", SessionID: create.SessionID, RevokedAt: 200}
	if _, _, err = store.Revoke(revoke); err == nil {
		t.Fatal("simulated revoke receipt failure succeeded")
	}
	active, ok, err := store.Get(create.SessionID)
	if err != nil || !ok || active.RevokedAt != 0 {
		t.Fatalf("revoke escaped rolled-back receipt: %#v ok=%v err=%v", active, ok, err)
	}
	if _, err = db.Exec(`DROP TRIGGER fail_revoke_receipt`); err != nil {
		t.Fatal(err)
	}
	settled, ok, err := store.Revoke(revoke)
	if err != nil || !ok || settled.RevokedAt != revoke.RevokedAt {
		t.Fatalf("revoke after rollback = %#v ok=%v err=%v", settled, ok, err)
	}
}

func TestSQLiteStoreConcurrentHandlesRejectCompetingRevokes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	open := func() (*sql.DB, *sqliteStore) {
		db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
		if err != nil {
			t.Fatal(err)
		}
		store, err := newSQLiteStore(db)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		return db, store
	}
	firstDB, first := open()
	defer firstDB.Close()
	secondDB, second := open()
	defer secondDB.Close()
	create := CreateRequest{RequestID: "create", SessionID: "session", AccountID: "account", CreatedAt: 100, ExpiresAt: 400}
	if _, err := first.Create(create); err != nil {
		t.Fatal(err)
	}

	requests := []RevokeRequest{
		{RequestID: "revoke-a", SessionID: create.SessionID, RevokedAt: 200},
		{RequestID: "revoke-b", SessionID: create.SessionID, RevokedAt: 201},
	}
	stores := []*sqliteStore{first, second}
	start := make(chan struct{})
	type outcome struct {
		index int
		ok    bool
		err   error
	}
	outcomes := make(chan outcome, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := range stores {
		go func(i int) {
			ready.Done()
			<-start
			_, ok, err := stores[i].Revoke(requests[i])
			outcomes <- outcome{index: i, ok: ok, err: err}
		}(i)
	}
	ready.Wait()
	close(start)
	winners := 0
	winningIndex := -1
	for range 2 {
		outcome := <-outcomes
		if outcome.err == nil && outcome.ok {
			winners++
			winningIndex = outcome.index
		}
	}
	if winners != 1 {
		t.Fatalf("competing revoke winners = %d, want 1", winners)
	}
	stored, ok, err := first.Get(create.SessionID)
	if err != nil || !ok || stored.RevokedAt != requests[winningIndex].RevokedAt {
		t.Fatalf("winning state = %#v ok=%v err=%v", stored, ok, err)
	}
	loser := 1 - winningIndex
	if _, _, err = stores[loser].Revoke(requests[loser]); err == nil {
		t.Fatal("competing revoke succeeded on retry")
	}
	var revokeReceipts int
	if err = firstDB.QueryRow(`SELECT COUNT(*) FROM auth_session_commands WHERE operation='revoke'`).Scan(&revokeReceipts); err != nil || revokeReceipts != 1 {
		t.Fatalf("revoke receipts = %d, %v", revokeReceipts, err)
	}
}

func TestSQLiteStoreConcurrentCreatesCommitOneStateAndExactReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent-create.db")
	open := func() (*sql.DB, *sqliteStore) {
		db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
		if err != nil {
			t.Fatal(err)
		}
		store, err := newSQLiteStore(db)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		return db, store
	}
	firstDB, first := open()
	defer firstDB.Close()
	secondDB, second := open()
	defer secondDB.Close()
	requests := []CreateRequest{
		{RequestID: "shared-request", SessionID: "session-a", AccountID: "account-a", CreatedAt: 100, ExpiresAt: 400},
		{RequestID: "shared-request", SessionID: "session-b", AccountID: "account-b", CreatedAt: 100, ExpiresAt: 400},
	}
	stores := []*sqliteStore{first, second}
	start := make(chan struct{})
	outcomes := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := range stores {
		go func(i int) {
			ready.Done()
			<-start
			_, err := stores[i].Create(requests[i])
			outcomes <- err
		}(i)
	}
	ready.Wait()
	close(start)
	winners := 0
	for range 2 {
		if err := <-outcomes; err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("competing create winners = %d, want 1", winners)
	}
	var sessions, receipts int
	if err := firstDB.QueryRow(`SELECT COUNT(*) FROM auth_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := firstDB.QueryRow(`SELECT COUNT(*) FROM auth_session_commands WHERE operation='create'`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || receipts != 1 {
		t.Fatalf("committed sessions/receipts = %d/%d, want 1/1", sessions, receipts)
	}
}

func TestSQLiteStoreReplaysExactCreateResultAfterRevokeAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exact-replay.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	request := CreateRequest{RequestID: "create", SessionID: "session", AccountID: "account", CreatedAt: 100, ExpiresAt: 400}
	created, err := store.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	revokeRequest := RevokeRequest{RequestID: "revoke", SessionID: request.SessionID, RevokedAt: 200}
	revoked, _, err := store.Revoke(revokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	restartedDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedDB.Close()
	restarted, err := newSQLiteStore(restartedDB)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Create(request)
	if err != nil || replayed != created || replayed.RevokedAt != 0 {
		t.Fatalf("exact create replay = %#v, %v; want %#v", replayed, err, created)
	}
	replayedRevoke, ok, err := restarted.Revoke(revokeRequest)
	if err != nil || !ok || replayedRevoke != revoked {
		t.Fatalf("exact revoke replay = %#v, %v, %v; want %#v", replayedRevoke, ok, err, revoked)
	}
	changed := revokeRequest
	changed.RevokedAt++
	if _, _, err = restarted.Revoke(changed); err == nil {
		t.Fatal("restarted owner accepted changed revoke payload")
	}
}
