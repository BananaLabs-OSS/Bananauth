package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/bananalabs-oss/bananauth/pkg/passwordcrypto"
	"github.com/vmihailenco/msgpack/v5"
)

func TestImportPreservesCredentialsAndReplaysWithoutRevertingChanges(t *testing.T) {
	t.Setenv("BANANAUTH_OTP_KEY_CURRENT", "fixture-import-key-at-least-32-bytes")
	root := t.TempDir()
	source, database := filepath.Join(root, "export.json"), filepath.Join(root, "identity.db")
	hash, err := passwordcrypto.Hash("fixture-original-password")
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{"request_id": "offline-import-fixture", "accounts": []any{map[string]any{"account_id": "account", "created_at": 123}}, "native": []any{map[string]any{"id": "credential", "account_id": "account", "email": "fixture@example.test", "username": "fixture-user", "password_hash": hash, "created_at": 123}}}
	raw, _ := json.Marshal(document)
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var first bytes.Buffer
	if err := run([]string{"-input", source, "-database", database}, &first); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first.Bytes(), []byte(hash)) || bytes.Contains(first.Bytes(), []byte("fixture@example.test")) {
		t.Fatal("import report leaked credential material")
	}
	keys, _ := otpsecure.Parse(os.Getenv("BANANAUTH_OTP_KEY_CURRENT"), "")
	providers, closeDB, err := identity.Open(t.Context(), database, keys)
	if err != nil {
		t.Fatal(err)
	}
	execute := func(name string, request any) []byte {
		t.Helper()
		input, err := msgpack.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		output, err := providers[name](input)
		if err != nil {
			t.Fatal(err)
		}
		return output
	}
	var login identity.Result[identity.AccountProjection]
	if err := msgpack.Unmarshal(execute(identity.FnNativeAuthenticate, identity.NativeAuthenticateRequest{Email: "fixture@example.test", Password: "fixture-original-password"}), &login); err != nil || !login.OK || login.Value.AccountID != "account" {
		t.Fatalf("imported credential cannot authenticate: %+v %v", login, err)
	}
	var changed identity.Result[map[string]any]
	if err := msgpack.Unmarshal(execute(identity.FnNativePasswordChange, identity.PasswordChangeRequest{RequestID: "change-after-import", AccountID: "account", CurrentPassword: "fixture-original-password", NewPassword: "fixture-replacement-password", Now: 200}), &changed); err != nil || !changed.OK {
		t.Fatalf("password change failed: %+v %v", changed, err)
	}
	closeDB.Close()
	var replay bytes.Buffer
	if err := run([]string{"-input", source, "-database", database}, &replay); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), replay.Bytes()) {
		t.Fatal("import did not replay exact receipt")
	}
	providers, closeDB, err = identity.Open(t.Context(), database, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB.Close()
	if err := msgpack.Unmarshal(execute(identity.FnNativeAuthenticate, identity.NativeAuthenticateRequest{Email: "fixture@example.test", Password: "fixture-replacement-password"}), &login); err != nil || !login.OK {
		t.Fatal("import replay reverted owner-managed password")
	}
	if actual, _ := os.ReadFile(source); !bytes.Equal(actual, raw) {
		t.Fatal("source export changed")
	}
}

func TestImportRejectsUnknownOrInexactInput(t *testing.T) {
	for _, source := range []string{`{"request_id":"x","unknown":true}`, `{"request_id":"x","accounts":[{"account_id":"a","created_at":1.5}]}`, `{"request_id":"x"} {}`, `null`, `{"request_id":"a","request_id":"b"}`, `{"request_id":"x","native":[{"passwordHash":"unexpected"}]}`} {
		if _, err := readImport(strings.NewReader(source)); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}
