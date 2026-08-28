package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type sessionStore interface {
	Create(CreateRequest) (Session, error)
	Get(string) (Session, bool, error)
	Revoke(RevokeRequest) (Session, bool, error)
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
	if value.RevokedAt == 0 {
		value.RevokedAt = req.RevokedAt
		value.Active = false
		s.sessions[value.SessionID] = value
	}
	s.requests[key] = commandReceipt{Digest: digest, Session: value}
	return value, true, nil
}

type sqlGuest interface {
	Exec(string, ...any) error
	Query(string, ...any) ([][]any, error)
}

type sqliteStore struct{ db sqlGuest }

func newSQLiteStore(db sqlGuest) (*sqliteStore, error) {
	s := &sqliteStore{db: db}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			session_id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS auth_session_commands (
			operation TEXT NOT NULL,
			request_id TEXT NOT NULL,
			request_digest TEXT NOT NULL,
			session_id TEXT NOT NULL,
			PRIMARY KEY(operation, request_id)
		)`,
	} {
		if err := s.db.Exec(statement); err != nil {
			return nil, fmt.Errorf("migrate auth session owner: %w", err)
		}
	}
	return s, nil
}

func (s *sqliteStore) Create(req CreateRequest) (Session, error) {
	digest := createDigest(req)
	if prior, ok, err := s.byRequest("create", req.RequestID, digest); err != nil {
		return Session{}, err
	} else if ok {
		return prior, nil
	}
	if prior, ok, err := s.Get(req.SessionID); err != nil {
		return Session{}, err
	} else if ok {
		if prior.AccountID != req.AccountID || prior.CreatedAt != req.CreatedAt || prior.ExpiresAt != req.ExpiresAt {
			return Session{}, fmt.Errorf("session id already belongs to a different session")
		}
		if err := s.db.Exec(`INSERT INTO auth_session_commands(operation, request_id, request_digest, session_id) VALUES (?, ?, ?, ?)`, "create", req.RequestID, digest, req.SessionID); err != nil {
			return Session{}, err
		}
		return prior, nil
	}
	if err := s.db.Exec(`INSERT INTO auth_sessions(session_id, account_id, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, 0)`,
		req.SessionID, req.AccountID, req.CreatedAt, req.ExpiresAt); err != nil {
		return Session{}, err
	}
	if err := s.db.Exec(`INSERT INTO auth_session_commands(operation, request_id, request_digest, session_id) VALUES (?, ?, ?, ?)`, "create", req.RequestID, digest, req.SessionID); err != nil {
		return Session{}, err
	}
	value, _, err := s.Get(req.SessionID)
	return value, err
}

func (s *sqliteStore) Get(id string) (Session, bool, error) {
	rows, err := s.db.Query(`SELECT session_id, account_id, created_at, expires_at, revoked_at FROM auth_sessions WHERE session_id = ?`, id)
	if err != nil {
		return Session{}, false, err
	}
	if len(rows) == 0 {
		return Session{}, false, nil
	}
	if len(rows) != 1 || len(rows[0]) != 5 {
		return Session{}, false, fmt.Errorf("invalid auth session row")
	}
	value, err := scanSession(rows[0])
	return value, err == nil, err
}

func (s *sqliteStore) Revoke(req RevokeRequest) (Session, bool, error) {
	digest := revokeDigest(req)
	if prior, ok, err := s.byRequest("revoke", req.RequestID, digest); err != nil {
		return Session{}, false, err
	} else if ok {
		return prior, true, nil
	}
	value, ok, err := s.Get(req.SessionID)
	if err != nil || !ok {
		return value, ok, err
	}
	if value.RevokedAt == 0 {
		if err := s.db.Exec(`UPDATE auth_sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at = 0`, req.RevokedAt, req.SessionID); err != nil {
			return Session{}, false, err
		}
	}
	if err := s.db.Exec(`INSERT INTO auth_session_commands(operation, request_id, request_digest, session_id) VALUES (?, ?, ?, ?)`, "revoke", req.RequestID, digest, req.SessionID); err != nil {
		return Session{}, false, err
	}
	value, _, err = s.Get(req.SessionID)
	return value, err == nil, err
}

func (s *sqliteStore) byRequest(operation, requestID, digest string) (Session, bool, error) {
	rows, err := s.db.Query(`SELECT s.session_id, s.account_id, s.created_at, s.expires_at, s.revoked_at, c.request_digest
		FROM auth_session_commands c JOIN auth_sessions s ON s.session_id = c.session_id
		WHERE c.operation = ? AND c.request_id = ?`, operation, requestID)
	if err != nil {
		return Session{}, false, err
	}
	if len(rows) == 0 {
		return Session{}, false, nil
	}
	if len(rows[0]) != 6 {
		return Session{}, false, fmt.Errorf("invalid auth session command row")
	}
	if stringValue(rows[0][5]) != digest {
		return Session{}, false, requestConflictError{operation: operation}
	}
	value, err := scanSession(rows[0][:5])
	return value, err == nil, err
}

func createDigest(req CreateRequest) string {
	return digest(fmt.Sprintf("%s\x00%s\x00%d\x00%d", req.SessionID, req.AccountID, req.CreatedAt, req.ExpiresAt))
}

func revokeDigest(req RevokeRequest) string {
	return digest(fmt.Sprintf("%s\x00%d", req.SessionID, req.RevokedAt))
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func scanSession(row []any) (Session, error) {
	if len(row) != 5 {
		return Session{}, fmt.Errorf("invalid auth session row")
	}
	created, err := int64Value(row[2])
	if err != nil {
		return Session{}, err
	}
	expires, err := int64Value(row[3])
	if err != nil {
		return Session{}, err
	}
	revoked, err := int64Value(row[4])
	if err != nil {
		return Session{}, err
	}
	value := Session{
		SessionID: stringValue(row[0]), AccountID: stringValue(row[1]),
		CreatedAt: created, ExpiresAt: expires, RevokedAt: revoked,
	}
	value.Active = value.RevokedAt == 0
	return value, nil
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(value)
	}
}

func int64Value(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case uint64:
		return int64(typed), nil
	case []byte:
		return strconv.ParseInt(string(typed), 10, 64)
	case string:
		return strconv.ParseInt(typed, 10, 64)
	default:
		return 0, fmt.Errorf("invalid integer value %T", value)
	}
}

func blank(value string) bool { return strings.TrimSpace(value) == "" }
