package migration

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/vmihailenco/msgpack/v5"
	_ "modernc.org/sqlite"
)

func oldMessage(v any) map[string]any {
	m := v.(map[string]any)
	return map[string]any{"version": "pulp.effect.v1", "kind": "pulp.effect.notification.email.send.v1", "id": m["id"], "idempotency_key": m["idempotency_key"], "payload": m["ciphertext"]}
}
func fixture(t *testing.T) (string, otpsecure.Keyring, notification.Lease, identity.NativeRegisterRequest) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "historical.db")
	keys, _ := otpsecure.Parse(strings.Repeat("k", 32), "")
	service, closeDB, err := identity.Open(t.Context(), path, keys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	registration := identity.NativeRegisterRequest{RequestID: "register", AccountID: "account", CredentialID: "credential", Email: "member@example.test", Username: "member", Password: "fixture-password", Now: now - 1000}
	registered, err := service.NativeRegister(registration)
	if err != nil || !registered.OK {
		t.Fatal(registered, err)
	}
	issued, err := service.EmailLoginIssueV2(identity.EmailVerificationIssueRequest{RequestID: "issue", VerificationID: "verification", EffectID: "message", Email: registration.Email, Code: "ABC123", Now: now, ExpiresAt: now + 600000})
	if err != nil || !issued.OK || !issued.Value.EffectQueued {
		t.Fatal(issued, err)
	}
	claim, err := service.EffectsClaim(notification.ClaimRequest{ConsumerID: "old-worker", Limit: 1, LeaseDurationMillis: 60000})
	if err != nil || len(claim.Leases) != 1 {
		t.Fatal(claim, err)
	}
	closeDB.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT revision,operation,response,snapshot FROM auth_identity_commands ORDER BY revision`)
	if err != nil {
		t.Fatal(err)
	}
	type change struct {
		revision           int64
		operation          string
		response, snapshot []byte
	}
	var changes []change
	for rows.Next() {
		var c change
		if err := rows.Scan(&c.revision, &c.operation, &c.response, &c.snapshot); err != nil {
			t.Fatal(err)
		}
		var state map[string]any
		if err := msgpack.Unmarshal(c.snapshot, &state); err != nil {
			t.Fatal(err)
		}
		delete(state, "format")
		effects, _ := object(state["effects"])
		for _, v := range effects {
			row := v.(map[string]any)
			row["intent"] = oldMessage(row["message"])
			delete(row, "message")
			if l, ok := row["lease"].(map[string]any); ok {
				l["version"] = "pulp.effect.outbox.v1"
				l["owner"] = "auth-identity"
				l["intent"] = oldMessage(l["message"])
				delete(l, "message")
			}
		}
		facts, _ := object(state["verification_facts_v2"])
		for _, v := range facts {
			f := v.(map[string]any)["fact"].(map[string]any)
			f["intent_version"] = "pulp.effect.v1"
			f["intent_kind"] = "pulp.effect.notification.email.send.v1"
			f["intent_idempotency_key"] = f["message_idempotency_key"]
			delete(f, "message_idempotency_key")
		}
		if c.operation == identity.FnEffectsClaim {
			c.operation = "auth.identity.effects.v1.claim"
			var response map[string]any
			if msgpack.Unmarshal(c.response, &response) != nil {
				t.Fatal("claim response")
			}
			response["version"] = "pulp.effect.outbox.v1"
			response["owner"] = "auth-identity"
			for _, v := range response["leases"].([]any) {
				l := v.(map[string]any)
				l["version"] = "pulp.effect.outbox.v1"
				l["owner"] = "auth-identity"
				l["intent"] = oldMessage(l["message"])
				delete(l, "message")
			}
			c.response, _ = encoded(response)
		}
		c.snapshot, _ = encoded(state)
		changes = append(changes, c)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if _, err := db.Exec(`UPDATE auth_identity_commands SET operation=?,response=?,snapshot=? WHERE revision=?`, c.operation, c.response, c.snapshot, c.revision); err != nil {
			t.Fatal(err)
		}
	}
	return path, keys, claim.Leases[0], registration
}

func TestOfflineConversionPreservesCiphertextLeasesReceiptsAndIdentity(t *testing.T) {
	sourcePath, keys, oldLease, registration := fixture(t)
	if service, closer, err := identity.Open(t.Context(), sourcePath, keys); err == nil {
		closer.Close()
		t.Fatalf("runtime silently accepted historical protocol: %v", service)
	}
	before, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := sql.Open("sqlite", "file:"+sourcePath+"?mode=ro")
	defer source.Close()
	targetPath := filepath.Join(t.TempDir(), "native.db")
	target, _ := sql.Open("sqlite", targetPath)
	report, err := Identity(context.Background(), source, target)
	if err != nil {
		t.Fatal(err)
	}
	target.Close()
	if report.Rows != 3 || report.Leases != 1 || report.Messages != 2 || len(report.SourceSHA256) != 64 || len(report.DestinationSHA256) != 64 {
		t.Fatalf("incomplete conversion receipt: %+v", report)
	}
	after, _ := os.ReadFile(sourcePath)
	if !bytes.Equal(before, after) {
		t.Fatal("read-only source changed")
	}
	service, closer, err := identity.Open(t.Context(), targetPath, keys)
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.NativeAuthenticate(identity.NativeAuthenticateRequest{Email: registration.Email, Password: registration.Password})
	if err != nil || !login.OK || login.Value.AccountID != registration.AccountID {
		t.Fatal("account or credential changed", err)
	}
	replay, err := service.NativeRegister(registration)
	if err != nil || !replay.OK || replay.Value != login.Value {
		t.Fatal("original receipt did not replay", err)
	}
	claim, err := service.EffectsClaim(notification.ClaimRequest{ConsumerID: "new-worker", Limit: 1, LeaseDurationMillis: 1000})
	if err != nil || len(claim.Leases) != 0 {
		t.Fatal("converted outstanding lease was stolen", err)
	}
	permitted, err := service.EffectsCheckDelivery(oldLease)
	if err != nil || !permitted.OK || !permitted.Value {
		t.Fatal("exact converted lease/ciphertext lost authority", err)
	}
	plain, envelope, err := keys.Open(oldLease.Message.ID, oldLease.Message.Ciphertext)
	if err != nil || envelope.Recipient != registration.Email || !bytes.Contains(plain, []byte("ABC123")) {
		t.Fatal("ciphertext/AAD changed", err)
	}
	fact, err := service.EmailVerificationFactGetV2(identity.EmailVerificationFactRequestV2{EffectID: "message", Email: registration.Email, Now: time.Now().UnixMilli()})
	if err != nil || !fact.OK || !fact.Value.Active || fact.Value.MessageIdempotencyKey != oldLease.Message.IdempotencyKey {
		t.Fatal("verification message evidence changed", err)
	}
	consumed, err := service.EmailLoginConsumeV2(identity.EmailVerificationConsumeRequest{RequestID: "consume", AccountID: "candidate", Email: registration.Email, Code: "ABC123", Now: time.Now().UnixMilli()})
	if err != nil || !consumed.OK || !consumed.Value.Verified || consumed.Value.AccountID != registration.AccountID {
		t.Fatal("preserved OTP did not consume", err)
	}
	permitted, err = service.EffectsCheckDelivery(oldLease)
	if err != nil || !permitted.OK || permitted.Value {
		t.Fatal("consumed OTP retained delivery authority", err)
	}
	closer.Close()
	service, closer, err = identity.Open(t.Context(), targetPath, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	login, err = service.NativeAuthenticate(identity.NativeAuthenticateRequest{Email: registration.Email, Password: registration.Password})
	if err != nil || !login.OK {
		t.Fatal("physical reopen lost credential", err)
	}
}

func TestOfflineConversionRejectsUnsupportedDataWithoutPartialRows(t *testing.T) {
	path, _, _, _ := fixture(t)
	source, _ := sql.Open("sqlite", path)
	defer source.Close()
	var raw []byte
	if err := source.QueryRow(`SELECT snapshot FROM auth_identity_commands WHERE revision=3`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	msgpack.Unmarshal(raw, &state)
	effects, _ := object(state["effects"])
	effects["message"].(map[string]any)["intent"].(map[string]any)["kind"] = "unsupported"
	raw, _ = encoded(state)
	source.Exec(`UPDATE auth_identity_commands SET snapshot=? WHERE revision=3`, raw)
	target, _ := sql.Open("sqlite", filepath.Join(t.TempDir(), "target.db"))
	defer target.Close()
	if _, err := Identity(t.Context(), source, target); err == nil {
		t.Fatal("unsupported historical kind accepted")
	}
	var count int
	if err := target.QueryRow(`SELECT COUNT(*) FROM auth_identity_commands`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed conversion published rows", count, err)
	}
}

func TestOfflineConversionHoldsUnboundLiveLegacyVerification(t *testing.T) {
	path, _, _, _ := fixture(t)
	source, _ := sql.Open("sqlite", path)
	defer source.Close()
	var raw []byte
	if err := source.QueryRow(`SELECT snapshot FROM auth_identity_commands WHERE revision=3`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if msgpack.Unmarshal(raw, &state) != nil {
		t.Fatal("fixture snapshot")
	}
	otps, _ := object(state["otps"])
	otps["unbound"] = map[string]any{"id": "unbound", "email": "unbound@example.test", "type": "sessions_email_verification", "code": "ABC123", "expires_at": time.Now().Add(time.Hour).UnixMilli()}
	raw, _ = encoded(state)
	if _, err := source.Exec(`UPDATE auth_identity_commands SET snapshot=? WHERE revision=3`, raw); err != nil {
		t.Fatal(err)
	}
	target, _ := sql.Open("sqlite", filepath.Join(t.TempDir(), "target.db"))
	defer target.Close()
	if _, err := Identity(t.Context(), source, target); err == nil || !strings.Contains(err.Error(), "offline intent reconciliation") {
		t.Fatal("unbound live verification silently converted", err)
	}
	var count int
	if err := target.QueryRow(`SELECT COUNT(*) FROM auth_identity_commands`).Scan(&count); err != nil || count != 0 {
		t.Fatal("held source published target rows", count, err)
	}
}
