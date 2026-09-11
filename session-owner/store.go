package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type sessionStore interface {
	Create(CreateRequest) (Session, error)
	CreateOwned(CreateOwnedRequest, int64) (Session, error)
	Get(string) (Session, bool, error)
	Revoke(RevokeRequest) (Session, bool, error)
	RevokeOwned(RevokeOwnedRequest, int64) (Session, bool, error)
}

type memoryStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	requests map[string]commandReceipt
}

type commandReceipt struct {
	Digest  string
	Session Session
}

type requestConflictError struct{ operation string }

func (e requestConflictError) Error() string {
	return fmt.Sprintf("request id was reused with a different %s payload", e.operation)
}

type sessionMutationConflictError struct{ operation string }

func (e sessionMutationConflictError) Error() string {
	return fmt.Sprintf("session already owns a competing %s result", e.operation)
}

func newMemoryStore() *memoryStore {
	return &memoryStore{sessions: map[string]Session{}, requests: map[string]commandReceipt{}}
}

func (s *memoryStore) Create(req CreateRequest) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, digest := "create:"+req.RequestID, createDigest(req)
	if prior, ok := s.requests[key]; ok {
		if prior.Digest != digest {
			return Session{}, requestConflictError{operation: "create"}
		}
		return prior.Session, nil
	}
	if prior, ok := s.sessions[req.SessionID]; ok {
		if prior.AccountID != req.AccountID || prior.CreatedAt != req.CreatedAt || prior.ExpiresAt != req.ExpiresAt {
			return Session{}, fmt.Errorf("session id already belongs to a different session")
		}
		s.requests[key] = commandReceipt{Digest: digest, Session: prior}
		return prior, nil
	}
	value := Session{SessionID: req.SessionID, AccountID: req.AccountID, CreatedAt: req.CreatedAt, ExpiresAt: req.ExpiresAt, Active: true}
	s.sessions[value.SessionID] = value
	s.requests[key] = commandReceipt{Digest: digest, Session: value}
	return value, nil
}

func (s *memoryStore) CreateOwned(req CreateOwnedRequest, now int64) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, logicalDigest := "create-owned:"+req.RequestID, createOwnedDigest(req)
	if prior, ok := s.requests[key]; ok {
		if prior.Digest != logicalDigest {
			return Session{}, requestConflictError{operation: "create-owned"}
		}
		return prior.Session, nil
	}
	if _, exists := s.sessions[req.SessionID]; exists {
		return Session{}, fmt.Errorf("session id already belongs to a different session")
	}
	value := Session{SessionID: req.SessionID, AccountID: req.AccountID, CreatedAt: now, ExpiresAt: now + req.LifetimeMillis, Active: true}
	s.sessions[value.SessionID] = value
	s.requests[key] = commandReceipt{Digest: logicalDigest, Session: value}
	return value, nil
}

func (s *memoryStore) Get(id string) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[id]
	return value, ok, nil
}

func (s *memoryStore) Revoke(req RevokeRequest) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, digest := "revoke:"+req.RequestID, revokeDigest(req)
	if prior, ok := s.requests[key]; ok {
		if prior.Digest != digest {
			return Session{}, false, requestConflictError{operation: "revoke"}
		}
		return prior.Session, true, nil
	}
	value, ok := s.sessions[req.SessionID]
	if !ok {
		return Session{}, false, nil
	}
	if value.RevokedAt != 0 {
		return Session{}, false, sessionMutationConflictError{operation: "revoke"}
	}
	value.RevokedAt = req.RevokedAt
	value.Active = false
	s.sessions[value.SessionID] = value
	s.requests[key] = commandReceipt{Digest: digest, Session: value}
	return value, true, nil
}

func (s *memoryStore) RevokeOwned(req RevokeOwnedRequest, now int64) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, logicalDigest := "revoke-owned:"+req.RequestID, revokeOwnedDigest(req)
	if prior, ok := s.requests[key]; ok {
		if prior.Digest != logicalDigest {
			return Session{}, false, requestConflictError{operation: "revoke-owned"}
		}
		return prior.Session, true, nil
	}
	value, ok := s.sessions[req.SessionID]
	if !ok {
		return Session{}, false, nil
	}
	if value.RevokedAt != 0 {
		return Session{}, false, sessionMutationConflictError{operation: "revoke-owned"}
	}
	value.RevokedAt, value.Active = now, false
	s.sessions[value.SessionID] = value
	s.requests[key] = commandReceipt{Digest: logicalDigest, Session: value}
	return value, true, nil
}

type sqliteStore struct{ db *sql.DB }

func newSQLiteStore(db *sql.DB) (*sqliteStore, error) {
	if db == nil {
		return nil, errors.New("auth session database is required")
	}
	s := &sqliteStore{db: db}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			session_id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS auth_session_commands (
			operation TEXT NOT NULL,
			request_id TEXT NOT NULL,
			request_digest TEXT NOT NULL,
			session_id TEXT NOT NULL,
			account_id TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL DEFAULT 0,
			expires_at INTEGER NOT NULL DEFAULT 0,
			revoked_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(operation, request_id)
		)`,
	} {
		if _, err := s.db.Exec(statement); err != nil {
			return nil, fmt.Errorf("migrate auth session owner: %w", err)
		}
	}
	for _, statement := range []string{
		`ALTER TABLE auth_sessions ADD COLUMN version INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE auth_session_commands ADD COLUMN account_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE auth_session_commands ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE auth_session_commands ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE auth_session_commands ADD COLUMN revoked_at INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(statement); err != nil && !duplicateColumn(err) {
			return nil, fmt.Errorf("migrate auth session owner: %w", err)
		}
	}
	// Old command rows did not store immutable result snapshots. Preserve their
	// replay behavior with the best durable state available at migration time;
	// every new command records its exact result in the creating transaction.
	if _, err := s.db.Exec(`UPDATE auth_session_commands SET
		account_id=COALESCE((SELECT account_id FROM auth_sessions WHERE auth_sessions.session_id=auth_session_commands.session_id), account_id),
		created_at=COALESCE((SELECT created_at FROM auth_sessions WHERE auth_sessions.session_id=auth_session_commands.session_id), created_at),
		expires_at=COALESCE((SELECT expires_at FROM auth_sessions WHERE auth_sessions.session_id=auth_session_commands.session_id), expires_at),
		revoked_at=COALESCE((SELECT revoked_at FROM auth_sessions WHERE auth_sessions.session_id=auth_session_commands.session_id), revoked_at)
		WHERE account_id=''`); err != nil {
		return nil, fmt.Errorf("migrate auth session command results: %w", err)
	}
	return s, nil
}

func duplicateColumn(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "duplicate column") || strings.Contains(message, "already exists")
}

func (s *sqliteStore) Create(req CreateRequest) (Session, error) {
	digest := createDigest(req)
	tx, err := s.db.Begin()
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	if prior, ok, err := byRequest(tx, "create", req.RequestID, digest); err != nil {
		return Session{}, err
	} else if ok {
		return prior, nil
	}
	result, err := tx.Exec(`INSERT INTO auth_sessions(session_id, account_id, created_at, expires_at, revoked_at, version)
		VALUES (?, ?, ?, ?, 0, 1) ON CONFLICT(session_id) DO NOTHING`, req.SessionID, req.AccountID, req.CreatedAt, req.ExpiresAt)
	if err != nil {
		return Session{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Session{}, err
	}
	value, version, ok, err := getSession(tx, req.SessionID)
	if err != nil || !ok {
		return Session{}, fmt.Errorf("load created auth session: %w", err)
	}
	if inserted == 0 && (value.AccountID != req.AccountID || value.CreatedAt != req.CreatedAt || value.ExpiresAt != req.ExpiresAt || value.RevokedAt != 0 || version < 1) {
		return Session{}, fmt.Errorf("session id already belongs to a different session")
	}
	if err = insertCommand(tx, "create", req.RequestID, digest, value); err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	return value, nil
}

func (s *sqliteStore) CreateOwned(req CreateOwnedRequest, now int64) (Session, error) {
	digest := createOwnedDigest(req)
	tx, err := s.db.Begin()
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	if prior, ok, err := byRequest(tx, "create-owned", req.RequestID, digest); err != nil {
		return Session{}, err
	} else if ok {
		return prior, nil
	}
	value := Session{SessionID: req.SessionID, AccountID: req.AccountID, CreatedAt: now, ExpiresAt: now + req.LifetimeMillis, Active: true}
	result, err := tx.Exec(`INSERT INTO auth_sessions(session_id, account_id, created_at, expires_at, revoked_at, version)
		VALUES (?, ?, ?, ?, 0, 1) ON CONFLICT(session_id) DO NOTHING`, value.SessionID, value.AccountID, value.CreatedAt, value.ExpiresAt)
	if err != nil {
		return Session{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Session{}, err
	}
	if inserted != 1 {
		return Session{}, fmt.Errorf("session id already belongs to a different session")
	}
	if err = insertCommand(tx, "create-owned", req.RequestID, digest, value); err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	return value, nil
}

func (s *sqliteStore) Get(id string) (Session, bool, error) {
	value, _, ok, err := getSession(s.db, id)
	return value, ok, err
}

func (s *sqliteStore) Revoke(req RevokeRequest) (Session, bool, error) {
	digest := revokeDigest(req)
	tx, err := s.db.Begin()
	if err != nil {
		return Session{}, false, err
	}
	defer tx.Rollback()
	if prior, ok, err := byRequest(tx, "revoke", req.RequestID, digest); err != nil {
		return Session{}, false, err
	} else if ok {
		return prior, true, nil
	}
	value, version, ok, err := getSession(tx, req.SessionID)
	if err != nil || !ok {
		return value, ok, err
	}
	if value.RevokedAt != 0 {
		return Session{}, false, sessionMutationConflictError{operation: "revoke"}
	}
	result, err := tx.Exec(`UPDATE auth_sessions SET revoked_at=?, version=version+1 WHERE session_id=? AND revoked_at=0 AND version=?`, req.RevokedAt, req.SessionID, version)
	if err != nil {
		return Session{}, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Session{}, false, err
	}
	if changed != 1 {
		return Session{}, false, sessionMutationConflictError{operation: "revoke"}
	}
	value.RevokedAt = req.RevokedAt
	value.Active = false
	if err = insertCommand(tx, "revoke", req.RequestID, digest, value); err != nil {
		return Session{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, false, err
	}
	return value, true, nil
}

func (s *sqliteStore) RevokeOwned(req RevokeOwnedRequest, now int64) (Session, bool, error) {
	digest := revokeOwnedDigest(req)
	tx, err := s.db.Begin()
	if err != nil {
		return Session{}, false, err
	}
	defer tx.Rollback()
	if prior, ok, err := byRequest(tx, "revoke-owned", req.RequestID, digest); err != nil {
		return Session{}, false, err
	} else if ok {
		return prior, true, nil
	}
	value, version, ok, err := getSession(tx, req.SessionID)
	if err != nil || !ok {
		return value, ok, err
	}
	if value.RevokedAt != 0 {
		return Session{}, false, sessionMutationConflictError{operation: "revoke-owned"}
	}
	result, err := tx.Exec(`UPDATE auth_sessions SET revoked_at=?, version=version+1 WHERE session_id=? AND revoked_at=0 AND version=?`, now, req.SessionID, version)
	if err != nil {
		return Session{}, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Session{}, false, err
	}
	if changed != 1 {
		return Session{}, false, sessionMutationConflictError{operation: "revoke-owned"}
	}
	value.RevokedAt, value.Active = now, false
	if err = insertCommand(tx, "revoke-owned", req.RequestID, digest, value); err != nil {
		return Session{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, false, err
	}
	return value, true, nil
}

func (s *sqliteStore) byRequest(operation, requestID, digest string) (Session, bool, error) {
	return byRequest(s.db, operation, requestID, digest)
}

type sqlQuerier interface {
	QueryRow(string, ...any) *sql.Row
}

func byRequest(db sqlQuerier, operation, requestID, digest string) (Session, bool, error) {
	var value Session
	var storedDigest string
	err := db.QueryRow(`SELECT session_id, account_id, created_at, expires_at, revoked_at, request_digest
		FROM auth_session_commands WHERE operation=? AND request_id=?`, operation, requestID).
		Scan(&value.SessionID, &value.AccountID, &value.CreatedAt, &value.ExpiresAt, &value.RevokedAt, &storedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	if storedDigest != digest {
		return Session{}, false, requestConflictError{operation: operation}
	}
	value.Active = value.RevokedAt == 0
	return value, true, nil
}

func getSession(db sqlQuerier, id string) (Session, int64, bool, error) {
	var value Session
	var version int64
	err := db.QueryRow(`SELECT session_id, account_id, created_at, expires_at, revoked_at, version FROM auth_sessions WHERE session_id=?`, id).
		Scan(&value.SessionID, &value.AccountID, &value.CreatedAt, &value.ExpiresAt, &value.RevokedAt, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, 0, false, nil
	}
	if err != nil {
		return Session{}, 0, false, err
	}
	value.Active = value.RevokedAt == 0
	return value, version, true, nil
}

func insertCommand(tx *sql.Tx, operation, requestID, digest string, value Session) error {
	result, err := tx.Exec(`INSERT INTO auth_session_commands(operation,request_id,request_digest,session_id,account_id,created_at,expires_at,revoked_at)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(operation,request_id) DO NOTHING`, operation, requestID, digest, value.SessionID, value.AccountID, value.CreatedAt, value.ExpiresAt, value.RevokedAt)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		prior, ok, replayErr := byRequest(tx, operation, requestID, digest)
		if replayErr != nil {
			return replayErr
		}
		if !ok || prior != value {
			return requestConflictError{operation: operation}
		}
	}
	return nil
}

func createDigest(req CreateRequest) string {
	return digest(fmt.Sprintf("%s\x00%s\x00%d\x00%d", req.SessionID, req.AccountID, req.CreatedAt, req.ExpiresAt))
}

func createOwnedDigest(req CreateOwnedRequest) string {
	return digest(fmt.Sprintf("%s\x00%s\x00%d", req.SessionID, req.AccountID, req.LifetimeMillis))
}

func revokeDigest(req RevokeRequest) string {
	return digest(fmt.Sprintf("%s\x00%d", req.SessionID, req.RevokedAt))
}

func revokeOwnedDigest(req RevokeOwnedRequest) string { return digest(req.SessionID) }

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func blank(value string) bool { return strings.TrimSpace(value) == "" }
