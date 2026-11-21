package main

import (
	"fmt"
	"github.com/bananalabs-oss/bananauth/internal/token"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/session"
	"github.com/google/uuid"
)

type SessionManager struct {
	key          token.Key
	expiry       time.Duration
	service      *session.Service
	newSessionID func() string
}

func (m *SessionManager) check(accountID, sessionID string) (bool, error) {
	result, err := m.service.Get(session.GetRequest{SessionID: sessionID, Now: time.Now().UTC().UnixMilli()})
	if err != nil {
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
	if m.service == nil {
		return "", 0, 0, fmt.Errorf("stable session requests require the durable session owner")
	}
	result, err := m.service.CreateOwned(session.CreateOwnedRequest{
		RequestID: requestID, SessionID: sessionID, AccountID: accountID.String(),
		LifetimeMillis: m.expiry.Milliseconds(),
	})
	if err != nil {
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
	result, err := m.service.Create(session.CreateRequest{
		RequestID: requestID,
		SessionID: sessionID,
		AccountID: accountID.String(),
		CreatedAt: now.UnixMilli(),
		ExpiresAt: expiresAt.UnixMilli(),
	})
	if err != nil {
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
	result, err := m.service.RevokeOwned(session.RevokeOwnedRequest{
		RequestID: "session:logout:" + sessionID, SessionID: sessionID,
	})
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if !result.OK || result.Value.SessionID != sessionID || result.Value.Active || result.Value.RevokedAt <= 0 {
		return fmt.Errorf("revoke session: owner rejected revocation")
	}
	return nil
}
