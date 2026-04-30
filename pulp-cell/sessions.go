package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// sessionClaims mirror the JWT shape every BananaKit service expects.
type sessionClaims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	SessionID string `json:"session_id"`
}

type sessionEntry struct {
	AccountID string
	CreatedAt time.Time
}

// SessionManager is Bananauth's per-process session revocation store
// layered on top of JWT. A valid token must both parse+verify AND
// still exist in this map; Revoke deletes the entry so the token
// stops being accepted.
type SessionManager struct {
	mu        sync.RWMutex
	sessions  map[string]sessionEntry
	jwtSecret []byte
	expiry    time.Duration
}

func NewSessionManager(jwtSecret string, expiry time.Duration) *SessionManager {
	return &SessionManager{
		sessions:  map[string]sessionEntry{},
		jwtSecret: []byte(jwtSecret),
		expiry:    expiry,
	}
}

func (m *SessionManager) Secret() []byte { return m.jwtSecret }

func (m *SessionManager) Exists(sessionID string) bool {
	m.mu.RLock()
	_, exists := m.sessions[sessionID]
	m.mu.RUnlock()
	return exists
}

func (m *SessionManager) Create(accountID uuid.UUID) (string, int, error) {
	sessionID := uuid.New().String()
	now := time.Now().UTC()
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        sessionID,
		},
		AccountID: accountID.String(),
		SessionID: sessionID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.jwtSecret)
	if err != nil {
		return "", 0, fmt.Errorf("sign token: %w", err)
	}
	m.mu.Lock()
	m.sessions[sessionID] = sessionEntry{AccountID: accountID.String(), CreatedAt: now}
	m.mu.Unlock()
	return signed, int(m.expiry.Seconds()), nil
}

func (m *SessionManager) Revoke(sessionID string) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}
