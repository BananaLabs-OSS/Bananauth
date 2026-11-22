// Package migration performs explicit offline data conversions. The HTTP
// service never accepts the retired provider protocol or invokes this decoder.
package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/internal/notification"
	"github.com/vmihailenco/msgpack/v5"
)

type Report struct {
	Rows              int64  `json:"rows"`
	Messages          int64  `json:"message_versions"`
	ArchivedPlaintext int    `json:"archived_plaintext_messages,omitempty"`
	Leases            int64  `json:"lease_versions"`
	SourceSHA256      string `json:"source_rows_sha256"`
	DestinationSHA256 string `json:"destination_rows_sha256"`
}

func object(v any) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("unsupported stored object")
	}
	return m, nil
}
func encoded(v any) ([]byte, error) {
	var b bytes.Buffer
	e := msgpack.NewEncoder(&b)
	e.SetSortMapKeys(true)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func (archive *notificationArchive) message(v any) (map[string]any, error) {
	old, err := object(v)
	if err != nil {
		return nil, err
	}
	if old["version"] != "pulp.effect.v1" || old["kind"] != "pulp.effect.notification.email.send.v1" {
		return nil, errors.New("unsupported historical notification format")
	}
	id, _ := old["id"].(string)
	key, _ := old["idempotency_key"].(string)
	ciphertext, ok := old["payload"].([]byte)
	if !ok {
		if archive == nil {
			return nil, errors.New("historical notification is not encrypted; explicit reconciliation required")
		}
		ciphertext, err = archive.seal(id, old["payload"])
		if err != nil {
			return nil, err
		}
	}
	value := notification.Message{ID: id, IdempotencyKey: key, Ciphertext: ciphertext}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "idempotency_key": key, "ciphertext": ciphertext}, nil
}
func (archive *notificationArchive) lease(v any) (map[string]any, error) {
	old, err := object(v)
	if err != nil {
		return nil, err
	}
	m, err := archive.message(old["intent"])
	if err != nil {
		return nil, err
	}
	delete(old, "version")
	delete(old, "owner")
	delete(old, "intent")
	old["message"] = m
	raw, err := encoded(old)
	if err != nil {
		return nil, err
	}
	var decoded notification.Lease
	if msgpack.Unmarshal(raw, &decoded) != nil || decoded.Validate() != nil {
		return nil, errors.New("invalid historical notification lease")
	}
	return old, nil
}
func receipt(v any) (map[string]any, error) {
	old, err := object(v)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"message_id": old["intent_id"], "idempotency_key": old["idempotency_key"], "status": old["status"]}
	if failure := old["failure"]; failure != nil {
		out["failure"] = failure
	}
	if result, ok := old["result"].(map[string]any); ok {
		if id, ok := result["message_id"].(string); ok {
			out["provider_message_id"] = id
		}
	}
	raw, err := encoded(out)
	if err != nil {
		return nil, err
	}
	var decoded notification.Receipt
	if msgpack.Unmarshal(raw, &decoded) != nil || decoded.Validate() != nil {
		return nil, errors.New("invalid historical notification receipt")
	}
	return out, nil
}
func fact(m map[string]any) {
	delete(m, "intent_version")
	delete(m, "intent_kind")
	if v, ok := m["intent_idempotency_key"]; ok {
		m["message_idempotency_key"] = v
		delete(m, "intent_idempotency_key")
	}
}
func (archive *notificationArchive) convertSnapshot(raw []byte, report *Report) ([]byte, error) {
	var snapshot map[string]any
	if err := msgpack.Unmarshal(raw, &snapshot); err != nil {
		return nil, errors.New("invalid identity snapshot")
	}
	if snapshot["format"] != nil {
		return nil, errors.New("source is not the historical identity format")
	}
	effects, err := object(snapshot["effects"])
	if err != nil {
		return nil, err
	}
	for _, v := range effects {
		row, err := object(v)
		if err != nil {
			return nil, err
		}
		m, err := archive.message(row["intent"])
		if err != nil {
			return nil, err
		}
		row["message"] = m
		delete(row, "intent")
		report.Messages++
		if v := row["lease"]; v != nil {
			l, err := archive.lease(v)
			if err != nil {
				return nil, err
			}
			row["lease"] = l
			report.Leases++
		}
		if v := row["receipt"]; v != nil {
			r, err := receipt(v)
			if err != nil {
				return nil, err
			}
			row["receipt"] = r
		}
	}
	facts, err := object(snapshot["verification_facts_v2"])
	if err != nil {
		return nil, err
	}
	for _, v := range facts {
		state, err := object(v)
		if err != nil {
			return nil, err
		}
		f, err := object(state["fact"])
		if err != nil {
			return nil, err
		}
		fact(f)
	}
	snapshot["format"] = "bananauth.identity.v2"
	result, err := encoded(snapshot)
	if err != nil {
		return nil, err
	}
	if err := identity.ValidateMigratedSnapshot(result); err != nil {
		return nil, err
	}
	return result, nil
}
func (archive *notificationArchive) convertResponse(operation string, raw []byte) ([]byte, error) {
	switch operation {
	case "auth.identity.effects.v1.claim":
		var result map[string]any
		if msgpack.Unmarshal(raw, &result) != nil {
			return nil, errors.New("invalid historical claim receipt")
		}
		delete(result, "version")
		delete(result, "owner")
		if leases, ok := result["leases"].([]any); ok {
			for i, v := range leases {
				l, err := archive.lease(v)
				if err != nil {
					return nil, err
				}
				leases[i] = l
			}
		}
		return encoded(result)
	case "auth.identity.effects.v1.acknowledge", "auth.identity.effects.v1.retry":
		var result map[string]any
		if msgpack.Unmarshal(raw, &result) != nil {
			return nil, errors.New("invalid historical settlement receipt")
		}
		delete(result, "version")
		delete(result, "owner")
		return encoded(result)
	default:
		return append([]byte(nil), raw...), nil
	}
}
func hashRow(h hash.Hash, revision int64, operation, id, digest string, response, snapshot []byte) {
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%d\x00", revision, operation, id, digest, len(response))
	h.Write(response)
	fmt.Fprintf(h, "\x00%d\x00", len(snapshot))
	h.Write(snapshot)
}

// Identity copies every command and full snapshot into an empty target in one
// transaction. Source and target must be separate private databases. Failure
// leaves the target without any published owner rows.
func Identity(ctx context.Context, source, target *sql.DB) (Report, error) {
	return migrateIdentity(ctx, source, target, false, nil)
}

// IdentityPostgres migrates between separate offline PostgreSQL databases.
func IdentityPostgres(ctx context.Context, source, target *sql.DB) (Report, error) {
	return migrateIdentity(ctx, source, target, true, nil)
}

// IdentityPostgresWithArchive seals plaintext messages that occur only in
// historical revisions. The separate archive key must never be a delivery key.
func IdentityPostgresWithArchive(ctx context.Context, source, target *sql.DB, key string) (Report, error) {
	archive, err := newNotificationArchive(key)
	if err != nil {
		return Report{}, err
	}
	return migrateIdentity(ctx, source, target, true, archive)
}

func migrateIdentity(ctx context.Context, source, target *sql.DB, postgres bool, archive *notificationArchive) (Report, error) {
	var report Report
	if source == nil || target == nil || source == target {
		return report, errors.New("separate source and target databases required")
	}
	if err := identity.InitializeStore(ctx, target); err != nil {
		return report, err
	}
	tx, err := target.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	readOptions := sql.TxOptions{ReadOnly: true}
	if postgres {
		readOptions.Isolation = sql.LevelRepeatableRead
		if _, err := tx.ExecContext(ctx, `LOCK TABLE auth_identity_commands, auth_identity_head IN ACCESS EXCLUSIVE MODE`); err != nil {
			return report, err
		}
	}
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_identity_commands`).Scan(&count); err != nil || count != 0 {
		return report, errors.New("empty target store required")
	}
	read, err := source.BeginTx(ctx, &readOptions)
	if err != nil {
		return report, err
	}
	defer read.Rollback()
	if err := rejectUnboundLiveVerification(ctx, read, time.Now().UnixMilli()); err != nil {
		return report, err
	}
	rows, err := read.QueryContext(ctx, `SELECT revision,operation,request_id,request_digest,response,snapshot FROM auth_identity_commands ORDER BY revision`)
	if err != nil {
		return report, err
	}
	defer rows.Close()
	before, after := sha256.New(), sha256.New()
	var highest int64
	for rows.Next() {
		var revision int64
		var operation, id, digest string
		var response, snapshot []byte
		if err := rows.Scan(&revision, &operation, &id, &digest, &response, &snapshot); err != nil {
			return report, err
		}
		if revision <= highest {
			return report, errors.New("invalid identity revision order")
		}
		highest = revision
		converted, err := archive.convertSnapshot(snapshot, &report)
		if err != nil {
			return report, fmt.Errorf("convert identity revision %d: %w", revision, err)
		}
		convertedResponse, err := archive.convertResponse(operation, response)
		if err != nil {
			return report, err
		}
		hashRow(before, revision, operation, id, digest, response, snapshot)
		hashRow(after, revision, operation, id, digest, convertedResponse, converted)
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_identity_commands(revision,operation,request_id,request_digest,response,snapshot) VALUES(?,?,?,?,?,?)`, revision, operation, id, digest, convertedResponse, converted); err != nil {
			return report, err
		}
		report.Rows++
	}
	if err := rows.Err(); err != nil {
		return report, err
	}
	if err := rows.Close(); err != nil {
		return report, err
	}
	if postgres {
		var head int64
		if err := read.QueryRowContext(ctx, `SELECT revision FROM auth_identity_head WHERE singleton=1`).Scan(&head); err != nil {
			return report, err
		}
		if head != highest {
			return report, errors.New("source identity head does not match its command history")
		}
		if archive != nil && len(archive.messages) > 0 {
			if err := archive.checkHead(ctx, read); err != nil {
				return report, err
			}
			report.ArchivedPlaintext = len(archive.messages)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_identity_head SET revision=? WHERE singleton=1`, highest); err != nil {
		return report, err
	}
	if err := tx.Commit(); err != nil {
		return report, err
	}
	report.SourceSHA256 = hex.EncodeToString(before.Sum(nil))
	report.DestinationSHA256 = hex.EncodeToString(after.Sum(nil))
	return report, nil
}

func rejectUnboundLiveVerification(ctx context.Context, tx *sql.Tx, now int64) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT snapshot FROM auth_identity_commands ORDER BY revision DESC LIMIT 1`).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	var state map[string]any
	if msgpack.Unmarshal(raw, &state) != nil {
		return errors.New("invalid identity snapshot")
	}
	otps, err := object(state["otps"])
	if err != nil {
		return err
	}
	for _, value := range otps {
		otp, err := object(value)
		if err != nil {
			return err
		}
		if otp["type"] != "sessions_email_verification" {
			continue
		}
		var expires int64
		switch n := otp["expires_at"].(type) {
		case int64:
			expires = n
		case uint64:
			if n > 1<<63-1 {
				return errors.New("invalid historical expiry")
			}
			expires = int64(n)
		case int8:
			expires = int64(n)
		case int16:
			expires = int64(n)
		case int32:
			expires = int64(n)
		case uint8:
			expires = int64(n)
		case uint16:
			expires = int64(n)
		case uint32:
			expires = int64(n)
		default:
			return errors.New("invalid historical expiry")
		}
		if expires > now {
			return errors.New("unbound pending verification requires explicit offline intent reconciliation")
		}
	}
	return nil
}
