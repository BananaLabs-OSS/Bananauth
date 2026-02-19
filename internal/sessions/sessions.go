package sessions

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	SessionID string `json:"session_id"`
}

type session struct {
	AccountID string
	CreatedAt time.Time
}

type Manager struct {
	mu        sync.RWMutex
	sessions  map[string]session // sessionID -> session
	jwtSecret []byte
	expiry    time.Duration
}

func NewManager(jwtSecret string, expiry time.Duration) *Manager {
	return &Manager{
		sessions:  make(map[string]session),
		jwtSecret: []byte(jwtSecret),
		expiry:    expiry,
	}
}

// Secret returns the JWT signing key.
// Used by BananAuth's middleware to pass to Potassium's ParseToken.
func (m *Manager) Secret() []byte {
	return m.jwtSecret
}

// Exists checks if a session has not been revoked.
// Used by BananAuth's middleware after Potassium validates the JWT.
func (m *Manager) Exists(sessionID string) bool {
	m.mu.RLock()
	_, exists := m.sessions[sessionID]
	m.mu.RUnlock()
	return exists
}

func (m *Manager) Create(accountID uuid.UUID) (string, int, error) {
	sessionID := uuid.New().String()

	now := time.Now().UTC()
	claims := Claims{
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
		return "", 0, fmt.Errorf("failed to sign token: %w", err)
	}

	m.mu.Lock()
	m.sessions[sessionID] = session{
		AccountID: accountID.String(),
		CreatedAt: now,
	}
	m.mu.Unlock()

	return signed, int(m.expiry.Seconds()), nil
}

func (m *Manager) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check session still exists (not revoked)
	m.mu.RLock()
	_, exists := m.sessions[claims.SessionID]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session revoked")
	}

	return claims, nil
}

func (m *Manager) Revoke(sessionID string) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}
