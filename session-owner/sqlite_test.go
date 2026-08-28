package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

type nativeSQLite struct{ db *sql.DB }

func (s nativeSQLite) Exec(query string, args ...any) error {
	_, err := s.db.Exec(query, args...)
	return err
}

func (s nativeSQLite) Query(query string, args ...any) ([][]any, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var result [][]any
	for rows.Next() {
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		result = append(result, values)
	}
	return result, rows.Err()
}

func TestSQLiteStoreSurvivesRestartAndDeduplicatesCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	open := func() (*sql.DB, *sqliteStore) {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		store, err := newSQLiteStore(nativeSQLite{db: db})
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
