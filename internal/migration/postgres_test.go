package migration

import (
	"database/sql"
	"os"
	"testing"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/bananalabs-oss/bananauth/internal/storage"
)

func TestOfflinePostgresConversion(t *testing.T) {
	sourceURL := os.Getenv("BANANAUTH_MIGRATION_TEST_SOURCE")
	targetURL := os.Getenv("BANANAUTH_MIGRATION_TEST_TARGET")
	if sourceURL == "" || targetURL == "" {
		t.Skip("requires two disposable PostgreSQL databases")
	}
	if sourceURL == targetURL {
		t.Fatal("requires separate test databases")
	}
	ctx := t.Context()
	sourcePath, keys, oldLease, registration := fixture(t)
	fixtureDB, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fixtureDB.Close() })
	source, err := storage.Open(sourceURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	target, err := storage.Open(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	if err := identity.InitializeStore(ctx, source); err != nil {
		t.Fatal(err)
	}
	rows, err := fixtureDB.QueryContext(ctx, `SELECT revision,operation,request_id,request_digest,response,snapshot FROM auth_identity_commands ORDER BY revision`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var head int64
	for rows.Next() {
		var operation, id, digest string
		var response, snapshot []byte
		if err := rows.Scan(&head, &operation, &id, &digest, &response, &snapshot); err != nil {
			t.Fatal(err)
		}
		if _, err := source.ExecContext(ctx, `INSERT INTO auth_identity_commands(revision,operation,request_id,request_digest,response,snapshot) VALUES(?,?,?,?,?,?)`, head, operation, id, digest, response, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if _, err := IdentityPostgres(ctx, source, target); err == nil {
		t.Fatal("conversion accepted an inconsistent source head")
	}
	var count int
	if err := target.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_identity_commands`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed conversion published %d rows: %v", count, err)
	}
	if _, err := source.ExecContext(ctx, `UPDATE auth_identity_head SET revision=? WHERE singleton=1`, head); err != nil {
		t.Fatal(err)
	}
	report, err := IdentityPostgres(ctx, source, target)
	if err != nil {
		t.Fatal(err)
	}
	if report.Rows != 3 || report.Messages != 2 || report.Leases != 1 {
		t.Fatalf("unexpected conversion report: %+v", report)
	}
	if _, err := IdentityPostgres(ctx, source, target); err == nil {
		t.Fatal("conversion overwrote a populated target")
	}

	service, closer, err := identity.Open(ctx, targetURL, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	login, err := service.NativeAuthenticate(identity.NativeAuthenticateRequest{Email: registration.Email, Password: registration.Password})
	if err != nil || !login.OK || login.Value.AccountID != registration.AccountID {
		t.Fatalf("migrated credential failed: %v", err)
	}
	permitted, err := service.EffectsCheckDelivery(oldLease)
	if err != nil || !permitted.OK || !permitted.Value {
		t.Fatalf("migrated encrypted lease lost authority: %v", err)
	}
	claim, err := service.EffectsClaim(notification.ClaimRequest{ConsumerID: "new-worker", Limit: 1, LeaseDurationMillis: 1000})
	if err != nil || len(claim.Leases) != 0 {
		t.Fatalf("migrated lease was claimed again: %v", err)
	}
}
