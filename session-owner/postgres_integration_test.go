//go:build !wasip1

package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp-ext-postgres/sqlitecompat"
)

var postgresSessionSchema = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// TestSessionOwnerPostgresIntegration proves durable session ownership only.
// It has no notification, email, payment, or external provider dependency.
func TestSessionOwnerPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("EVOLUTION_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("EVOLUTION_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	schema := fmt.Sprintf("session_it_%d", time.Now().UTC().UnixNano())
	if !postgresSessionSchema.MatchString(schema) {
		t.Fatal("generated unsafe schema")
	}
	admin := postgresSessionDB(t, dsn)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, _ = admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	open := func() *sqliteStore {
		db := postgresSessionDB(t, parsed.String())
		t.Cleanup(func() { _ = db.Close() })
		store, err := newSQLiteStore(db)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	first, second := open(), open()
	create := CreateRequest{RequestID: "postgres-create", SessionID: "postgres-session", AccountID: "postgres-account", CreatedAt: 100, ExpiresAt: 400}
	created, err := first.Create(create)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := second.Create(create)
	if err != nil || replayed != created {
		t.Fatalf("create replay = %#v, %v", replayed, err)
	}
	requests := []RevokeRequest{{RequestID: "postgres-revoke-a", SessionID: create.SessionID, RevokedAt: 200}, {RequestID: "postgres-revoke-b", SessionID: create.SessionID, RevokedAt: 201}}
	type outcome struct {
		index int
		value Session
		ok    bool
		err   error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	var wait sync.WaitGroup
	for i, store := range []*sqliteStore{first, second} {
		wait.Add(1)
		go func(i int, store *sqliteStore) {
			defer wait.Done()
			<-start
			value, ok, err := store.Revoke(requests[i])
			outcomes <- outcome{i, value, ok, err}
		}(i, store)
	}
	close(start)
	wait.Wait()
	close(outcomes)
	winners, winner := 0, -1
	for result := range outcomes {
		if result.err == nil && result.ok {
			winners++
			winner = result.index
		}
		if result.err == nil && !result.ok {
			t.Fatalf("revoke %d returned false without conflict", result.index)
		}
	}
	if winners != 1 {
		t.Fatalf("revoke winners = %d, want 1", winners)
	}
	restarted := open()
	settled, ok, err := restarted.Revoke(requests[winner])
	if err != nil || !ok || settled.RevokedAt != requests[winner].RevokedAt {
		t.Fatalf("restart replay = %#v, %v, %v", settled, ok, err)
	}
	var creates, revokes int
	if err := restarted.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_session_commands WHERE operation='create'`).Scan(&creates); err != nil {
		t.Fatal(err)
	}
	if err := restarted.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_session_commands WHERE operation='revoke'`).Scan(&revokes); err != nil {
		t.Fatal(err)
	}
	if creates != 1 || revokes != 1 {
		t.Fatalf("durable command cardinality create=%d revoke=%d, want 1/1", creates, revokes)
	}
}

func postgresSessionDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	connector, err := sqlitecompat.NewPostgresConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(4)
	return db
}
