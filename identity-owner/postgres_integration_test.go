//go:build !wasip1

package main

import (
	"bytes"
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

var postgresIdentitySchema = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// TestIdentityOwnerPostgresIntegration is an opt-in owner-state proof. The
// owner is constructed with test keys and no notification executor; therefore
// this test cannot deliver an OTP or any other outward message.
func TestIdentityOwnerPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("EVOLUTION_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("EVOLUTION_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	schema := fmt.Sprintf("identity_it_%d", time.Now().UTC().UnixNano())
	if !postgresIdentitySchema.MatchString(schema) {
		t.Fatal("generated unsafe schema")
	}
	admin := postgresIdentityDB(t, dsn)
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
	open := func() *sqliteEventStore {
		db := postgresIdentityDB(t, parsed.String())
		t.Cleanup(func() { _ = db.Close() })
		store := &sqliteEventStore{db: db}
		if err := store.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		return store
	}
	firstStore, secondStore := open(), open()
	first, second := newTestOwner(t, firstStore), newTestOwner(t, secondStore)
	request := registerRequest("postgres-same", "postgres-account", "identity@example.test")
	wire, _ := encode(request)
	start := make(chan struct{})
	responses := make([][]byte, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for i, replica := range []*owner{first, second} {
		wait.Add(1)
		go func(i int, replica *owner) {
			defer wait.Done()
			<-start
			responses[i], errs[i] = replica.nativeRegister(wire)
		}(i, replica)
	}
	close(start)
	wait.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(responses[0], responses[1]) {
		t.Fatal("replicas returned different durable responses")
	}
	var commands, revision int64
	if err := firstStore.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_identity_commands`).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	if err := secondStore.db.QueryRowContext(ctx, `SELECT revision FROM auth_identity_head WHERE singleton=1`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if commands != 1 || revision != 1 {
		t.Fatalf("commands=%d revision=%d, want 1/1", commands, revision)
	}
	restarted := newTestOwner(t, open())
	replayed, err := restarted.nativeRegister(wire)
	if err != nil || !bytes.Equal(replayed, responses[0]) {
		t.Fatalf("restart replay differs: %v", err)
	}
	conflict := request
	conflict.Email = "changed@example.test"
	got := callResult[AccountProjection](t, restarted.nativeRegister, conflict)
	if got.OK || got.Error == nil || got.Error.Code != "idempotency_conflict" {
		t.Fatalf("conflicting replay = %#v", got)
	}
}

func postgresIdentityDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	connector, err := sqlitecompat.NewPostgresConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(4)
	return db
}
