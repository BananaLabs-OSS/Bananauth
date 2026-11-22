package main

import (
	"bytes"
	"database/sql"
	"github.com/vmihailenco/msgpack/v5"
	"os"
	"path/filepath"
	"testing"
)

func oldEmptyFixture(t *testing.T, bad bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE auth_identity_commands(revision INTEGER PRIMARY KEY,operation TEXT,request_id TEXT,request_digest TEXT,response BLOB,snapshot BLOB)`)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := map[string]any{}
	for _, key := range []string{"accounts", "native_by_email", "native_by_account", "usernames", "oauth_states", "oauth_links", "otps", "profiles", "rates", "effects", "retention_leases", "retention_holds", "verification_facts_v2"} {
		snapshot[key] = map[string]any{}
	}
	if bad {
		snapshot["format"] = "unknown"
	}
	raw, _ := msgpack.Marshal(snapshot)
	response, _ := msgpack.Marshal(map[string]any{"version": "auth-identity.v1", "ok": true, "value": true})
	if _, err := db.Exec(`INSERT INTO auth_identity_commands VALUES(1,'fixture','one','digest',?,?)`, response, raw); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestOfflineCommandPublishesOnlyCompletedNewPrivateStore(t *testing.T) {
	source := oldEmptyFixture(t, false)
	before, _ := os.ReadFile(source)
	folder := t.TempDir()
	target := filepath.Join(folder, "native.db")
	var out bytes.Buffer
	if err := run([]string{"-source", source, "-target", target}, &out); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("nonprivate output", err)
	}
	first, _ := os.ReadFile(target)
	if err := run([]string{"-source", source, "-target", target}, &out); err == nil {
		t.Fatal("existing store overwritten")
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(first, after) {
		t.Fatal("rejected rerun changed existing target")
	}
	actual, _ := os.ReadFile(source)
	if !bytes.Equal(before, actual) {
		t.Fatal("source file changed")
	}
	matches, _ := filepath.Glob(filepath.Join(folder, ".bananauth-migrate-*"))
	if len(matches) != 0 {
		t.Fatal("private staging directory remained")
	}
}
func TestOfflineCommandFailureNeverPublishesTarget(t *testing.T) {
	source := oldEmptyFixture(t, true)
	folder := t.TempDir()
	target := filepath.Join(folder, "native.db")
	if err := run([]string{"-source", source, "-target", target}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown format accepted")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("failed conversion published target")
	}
	matches, _ := filepath.Glob(filepath.Join(folder, ".bananauth-migrate-*"))
	if len(matches) != 0 {
		t.Fatal("failed staging remained")
	}
}
