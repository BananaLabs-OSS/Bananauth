package main

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/vmihailenco/msgpack/v5"
)

type commandReceipt struct {
	Operation string `msgpack:"operation"`
	RequestID string `msgpack:"request_id"`
	Digest    string `msgpack:"digest"`
	Response  []byte `msgpack:"response"`
}

type durableRecord struct {
	Receipt  commandReceipt `msgpack:"receipt"`
	Snapshot snapshot       `msgpack:"snapshot"`
}

type eventStore interface {
	Migrate(context.Context) error
	Load(context.Context) (snapshot, map[string]commandReceipt, error)
	LoadCommand(context.Context, string, string) (int64, snapshot, *commandReceipt, error)
	AppendCAS(context.Context, int64, durableRecord) (bool, error)
}

type sqliteEventStore struct{ db *sql.DB }

func (s *sqliteEventStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_identity_commands (
		revision INTEGER PRIMARY KEY AUTOINCREMENT,
		operation TEXT NOT NULL,
		request_id TEXT NOT NULL,
		request_digest TEXT NOT NULL,
		response BLOB NOT NULL,
		snapshot BLOB NOT NULL,
		UNIQUE(operation, request_id)
	)`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_identity_head (
		singleton INTEGER PRIMARY KEY,
		revision BIGINT NOT NULL
	)`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO auth_identity_head(singleton,revision)
		SELECT 1,COALESCE(MAX(revision),0) FROM auth_identity_commands WHERE 1=1
		ON CONFLICT(singleton) DO NOTHING`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE auth_identity_head SET revision=(SELECT COALESCE(MAX(revision),0) FROM auth_identity_commands)
		WHERE singleton=1 AND revision < (SELECT COALESCE(MAX(revision),0) FROM auth_identity_commands)`)
	return err
}

func (s *sqliteEventStore) Load(ctx context.Context) (snapshot, map[string]commandReceipt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT operation, request_id, request_digest, response, snapshot
		FROM auth_identity_commands ORDER BY revision ASC`)
	if err != nil {
		return snapshot{}, nil, err
	}
	defer rows.Close()
	current := newSnapshot()
	receipts := map[string]commandReceipt{}
	for rows.Next() {
		var operation, requestID, digest string
		var response, rawSnapshot []byte
		if err := rows.Scan(&operation, &requestID, &digest, &response, &rawSnapshot); err != nil {
			return snapshot{}, nil, err
		}
		if err := msgpack.Unmarshal(rawSnapshot, &current); err != nil {
			return snapshot{}, nil, fmt.Errorf("decode identity snapshot: %w", err)
		}
		receipt := commandReceipt{Operation: operation, RequestID: requestID, Digest: digest, Response: response}
		receipts[operation+":"+requestID] = receipt
	}
	return current, receipts, rows.Err()
}

func (s *sqliteEventStore) LoadCommand(ctx context.Context, operation, requestID string) (int64, snapshot, *commandReceipt, error) {
	current := newSnapshot()
	var revision int64
	var rawSnapshot []byte
	err := s.db.QueryRowContext(ctx, `SELECT revision,snapshot FROM auth_identity_commands ORDER BY revision DESC LIMIT 1`).Scan(&revision, &rawSnapshot)
	if err != nil && err != sql.ErrNoRows {
		return 0, snapshot{}, nil, err
	}
	if err == nil {
		if err := msgpack.Unmarshal(rawSnapshot, &current); err != nil {
			return 0, snapshot{}, nil, fmt.Errorf("decode current identity snapshot: %w", err)
		}
	}
	if operation == "" || requestID == "" {
		return revision, current, nil, nil
	}
	var receipt commandReceipt
	err = s.db.QueryRowContext(ctx, `SELECT operation,request_id,request_digest,response FROM auth_identity_commands WHERE operation=? AND request_id=?`, operation, requestID).
		Scan(&receipt.Operation, &receipt.RequestID, &receipt.Digest, &receipt.Response)
	if err == sql.ErrNoRows {
		return revision, current, nil, nil
	}
	if err != nil {
		return 0, snapshot{}, nil, err
	}
	return revision, current, &receipt, nil
}

func (s *sqliteEventStore) AppendCAS(ctx context.Context, expectedRevision int64, record durableRecord) (bool, error) {
	rawSnapshot, err := msgpack.Marshal(record.Snapshot)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE auth_identity_head SET revision=revision+1 WHERE singleton=1 AND revision=?`, expectedRevision)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if changed != 1 {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_identity_commands(revision,operation,request_id,request_digest,response,snapshot)
		VALUES (?,?,?,?,?,?)`, expectedRevision+1, record.Receipt.Operation, record.Receipt.RequestID, record.Receipt.Digest, record.Receipt.Response, rawSnapshot); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

type memoryEventStore struct {
	mu      sync.Mutex
	records []durableRecord
}

func (s *memoryEventStore) Migrate(context.Context) error { return nil }
func (s *memoryEventStore) Load(context.Context) (snapshot, map[string]commandReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := newSnapshot()
	receipts := map[string]commandReceipt{}
	for _, record := range s.records {
		current = record.Snapshot.clone()
		receipts[record.Receipt.Operation+":"+record.Receipt.RequestID] = record.Receipt
	}
	return current, receipts, nil
}
func (s *memoryEventStore) LoadCommand(_ context.Context, operation, requestID string) (int64, snapshot, *commandReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := newSnapshot()
	var receipt *commandReceipt
	for _, record := range s.records {
		current = record.Snapshot.clone()
		if record.Receipt.Operation == operation && record.Receipt.RequestID == requestID {
			copy := record.Receipt
			receipt = &copy
		}
	}
	return int64(len(s.records)), current, receipt, nil
}
func (s *memoryEventStore) AppendCAS(_ context.Context, expectedRevision int64, record durableRecord) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int64(len(s.records)) != expectedRevision {
		return false, nil
	}
	s.records = append(s.records, durableRecord{Receipt: record.Receipt, Snapshot: record.Snapshot.clone()})
	return true, nil
}
