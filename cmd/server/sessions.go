package main

import (
	"fmt"
	"github.com/bananalabs-oss/bananauth/internal/token"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	sessionCreatedEvent      = "bananauth.session.created.v1"
	sessionCreatedOwnedEvent = "bananauth.session.created-owned.v1"
	sessionVerifiedEvent     = "bananauth.session.verified.v1"
	sessionRevokedEvent      = "bananauth.session.revoked.v1"
	sessionRevokedOwnedEvent = "bananauth.session.revoked-owned.v1"
)

type sessionDispatcher func(string, []byte) ([]byte, error)

type SessionManager struct {
	key          token.Key
	expiry       time.Duration
	dispatch     sessionDispatcher
	newSessionID func() string
}

func (m *SessionManager) check(accountID, sessionID string) (bool, error) {
	var result sessionWorkflowResult
	if err := m.call(sessionVerifiedEvent, map[string]any{"session_id": sessionID, "now": time.Now().UTC().UnixMilli()}, &result); err != nil {
		return false, err
	}
	return result.OK && result.Value.Active && result.Value.SessionID == sessionID && result.Value.AccountID == accountID, nil
}

func (m *SessionManager) Create(accountID uuid.UUID) (string, int, error) {
	now := time.Now().UTC()
	sessionID := m.newSessionID()
	return m.createAt(accountID, "session:create:"+sessionID, sessionID, now)
}

// CreateForRequest creates exactly one durable session for a stable BFF login
// attempt. The identifiers and timestamps are replayed unchanged, so a retry
// after OTP consumption, owner commit, or response loss resumes rather than
// creating a second session.
func (m *SessionManager) CreateForRequest(accountID uuid.UUID, requestID, sessionID string) (string, int, int64, error) {
	if requestID == "" || sessionID == "" {
		return "", 0, 0, fmt.Errorf("stable session request is incomplete")
	}
	if m.dispatch == nil {
		return "", 0, 0, fmt.Errorf("stable session requests require the durable session owner")
	}
	var result sessionWorkflowResult
	if err := m.call(sessionCreatedOwnedEvent, map[string]any{
		"request_id": requestID, "session_id": sessionID, "account_id": accountID.String(),
		"lifetime_millis": m.expiry.Milliseconds(),
	}, &result); err != nil {
		return "", 0, 0, fmt.Errorf("persist session: %w", err)
	}
	if !result.OK || !result.Value.Active || result.Value.SessionID != sessionID || result.Value.AccountID != accountID.String() || result.Value.ExpiresAt <= result.Value.CreatedAt || result.Value.RevokedAt != 0 {
		return "", 0, 0, fmt.Errorf("persist session: owner returned an invalid receipt")
	}
	expiresAt := time.UnixMilli(result.Value.ExpiresAt).UTC()
	signed, err := m.key.Sign(token.SignRequest{AccountID: accountID.String(), SessionID: sessionID, ExpiresAt: result.Value.ExpiresAt})
	if err != nil {
		return "", 0, 0, fmt.Errorf("sign token: %w", err)
	}
	seconds := int(time.Until(expiresAt).Seconds())
	if seconds <= 0 {
		return "", 0, 0, fmt.Errorf("persist session: owner receipt already expired")
	}
	return signed, seconds, result.Value.ExpiresAt, nil
}

func (m *SessionManager) createAt(accountID uuid.UUID, requestID, sessionID string, now time.Time) (string, int, error) {
	expiresAt := now.Add(m.expiry)
	var result sessionWorkflowResult
	if err := m.call(sessionCreatedEvent, map[string]any{
		"request_id": requestID,
		"session_id": sessionID,
		"account_id": accountID.String(),
		"created_at": now.UnixMilli(),
		"expires_at": expiresAt.UnixMilli(),
	}, &result); err != nil {
		return "", 0, fmt.Errorf("persist session: %w", err)
	}
	if !result.OK || !result.Value.Active {
		return "", 0, fmt.Errorf("persist session: owner rejected session")
	}
	if result.Value.SessionID != sessionID || result.Value.AccountID != accountID.String() || result.Value.CreatedAt != now.UnixMilli() || result.Value.ExpiresAt != expiresAt.UnixMilli() || result.Value.RevokedAt != 0 {
		return "", 0, fmt.Errorf("persist session: owner returned a mismatched receipt")
	}
	signed, err := m.key.Sign(token.SignRequest{AccountID: accountID.String(), SessionID: sessionID, ExpiresAt: expiresAt.UnixMilli()})
	if err != nil {
		return "", 0, fmt.Errorf("sign token: %w", err)
	}
	return signed, int(m.expiry.Seconds()), nil
}

func (m *SessionManager) RevokeChecked(sessionID string) error {
	var result sessionWorkflowResult
	if err := m.call(sessionRevokedOwnedEvent, map[string]any{
		"request_id": "session:logout:" + sessionID, "session_id": sessionID,
	}, &result); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if !result.OK || result.Value.SessionID != sessionID || result.Value.Active || result.Value.RevokedAt <= 0 {
		return fmt.Errorf("revoke session: owner rejected revocation")
	}
	return nil
}

type sessionWorkflowResult struct {
	Version string                 `msgpack:"version"`
	OK      bool                   `msgpack:"ok"`
	Value   sessionWorkflowSession `msgpack:"value"`
	Error   *sessionWorkflowError  `msgpack:"error,omitempty"`
}

type sessionWorkflowSession struct {
	SessionID string `msgpack:"session_id"`
	AccountID string `msgpack:"account_id"`
	CreatedAt int64  `msgpack:"created_at"`
	ExpiresAt int64  `msgpack:"expires_at"`
	RevokedAt int64  `msgpack:"revoked_at"`
	Active    bool   `msgpack:"active"`
}

type sessionWorkflowError struct {
	Code    string `msgpack:"code"`
	Message string `msgpack:"message"`
}

func (m *SessionManager) call(event string, request any, response *sessionWorkflowResult) error {
	if m.dispatch == nil {
		return fmt.Errorf("session workflow dispatcher is nil")
	}
	requestWire, err := msgpack.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode %s request: %w", event, err)
	}
	responseWire, err := m.dispatch(event, requestWire)
	if err != nil {
		return err
	}
	if err := msgpack.Unmarshal(responseWire, response); err != nil {
		return fmt.Errorf("decode %s response: %w", event, err)
	}
	if response.Version != "auth-session.v1" {
		return fmt.Errorf("%s returned contract %q", event, response.Version)
	}
	return nil
}
