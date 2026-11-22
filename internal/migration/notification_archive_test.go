package migration

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestHistoricalNotificationArchive(t *testing.T) {
	archive, err := newNotificationArchive(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"to": "archive-test@example.test", "subject": "test", "text": "historical text"}
	intent := map[string]any{
		"version": "pulp.effect.v1", "kind": "pulp.effect.notification.email.send.v1",
		"id": "message", "idempotency_key": "key", "payload": payload,
	}
	m, err := archive.message(intent)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := m["ciphertext"].([]byte)
	replay, err := archive.message(intent)
	if err != nil || !bytes.Equal(ciphertext, replay["ciphertext"].([]byte)) {
		t.Fatal("historical replay changed the encrypted message", err)
	}
	plain, envelope, err := archive.key.Open("message", ciphertext)
	want, encodeErr := encoded(payload)
	if err != nil || encodeErr != nil || !bytes.Equal(plain, want) || envelope.ExpiresAt != 1 {
		t.Fatal("archive encryption did not preserve the payload with a past expiry", err, encodeErr)
	}
	payload["text"] = "conflicting text"
	if _, err := archive.message(intent); err == nil {
		t.Fatal("accepted a different plaintext for the same historical identifier")
	}

	sourcePath, _, _, _ := fixture(t)
	db, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.checkHead(t.Context(), tx); err == nil {
		t.Fatal("archived a notification still present in the current snapshot")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	raw, err := msgpack.Marshal(map[string]any{"effects": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE auth_identity_commands SET snapshot=? WHERE revision=3`, raw); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := archive.checkHead(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
}
