package main

import (
	"context"
	"database/sql"
	"fmt"

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
	Append(context.Context, durableRecord) error
}

type sqliteEventStore struct{ db *sql.DB }

func (s *sqliteEventStore) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_identity_commands (
		revision INTEGER PRIMARY KEY AUTOINCREMENT,
		operation TEXT NOT NULL,
		request_id TEXT NOT NULL,
		request_digest TEXT NOT NULL,
		response BLOB NOT NULL,
		snapshot BLOB NOT NULL,
		UNIQUE(operation, request_id)
	)`)
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

func (s *sqliteEventStore) Append(ctx context.Context, record durableRecord) error {
	rawSnapshot, err := msgpack.Marshal(record.Snapshot)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_identity_commands(operation, request_id, request_digest, response, snapshot)
		VALUES (?, ?, ?, ?, ?)`, record.Receipt.Operation, record.Receipt.RequestID, record.Receipt.Digest, record.Receipt.Response, rawSnapshot)
	return err
}

type memoryEventStore struct{ records []durableRecord }

func (s *memoryEventStore) Migrate(context.Context) error { return nil }
func (s *memoryEventStore) Load(context.Context) (snapshot, map[string]commandReceipt, error) {
	current := newSnapshot()
	receipts := map[string]commandReceipt{}
	for _, record := range s.records {
		current = record.Snapshot.clone()
		receipts[record.Receipt.Operation+":"+record.Receipt.RequestID] = record.Receipt
	}
	return current, receipts, nil
}
func (s *memoryEventStore) Append(_ context.Context, record durableRecord) error {
	s.records = append(s.records, durableRecord{Receipt: record.Receipt, Snapshot: record.Snapshot.clone()})
	return nil
}
