package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/google/uuid"
)

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
	signed, err := authcrypto.MintJWT(m.jwtSecret, accountID, sessionID, m.expiry)
	if err != nil {
		return "", 0, fmt.Errorf("sign token: %w", err)
	}
	m.mu.Lock()
	m.sessions[sessionID] = sessionEntry{AccountID: accountID.String(), CreatedAt: time.Now().UTC()}
	m.mu.Unlock()
	return signed, int(m.expiry.Seconds()), nil
}

func (m *SessionManager) Revoke(sessionID string) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}
