package main

import (
	"fmt"
	"sync"
	"time"

	hostjwt "github.com/BananaLabs-OSS/Fiber/pulp/jwt"
	"github.com/BananaLabs-OSS/Fiber/pulp/workflow"
	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	sessionCreatedEvent  = "bananauth.session.created.v1"
	sessionVerifiedEvent = "bananauth.session.verified.v1"
	sessionRevokedEvent  = "bananauth.session.revoked.v1"
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
	mu           sync.RWMutex
	sessions     map[string]sessionEntry
	jwtSecret    []byte
	expiry       time.Duration
	dispatch     sessionDispatcher
	newSessionID func() string
	hostJWT      bool
}

type sessionDispatcher interface {
	Dispatch(workflow.DispatchRequest) (workflow.DispatchResult, error)
}

func NewSessionManager(jwtSecret string, expiry time.Duration) *SessionManager {
	return &SessionManager{
		sessions:     map[string]sessionEntry{},
		jwtSecret:    []byte(jwtSecret),
		expiry:       expiry,
		newSessionID: uuid.NewString,
	}
}

func NewComposedSessionManager(jwtSecret string, expiry time.Duration, dispatch sessionDispatcher) *SessionManager {
	return &SessionManager{jwtSecret: []byte(jwtSecret), expiry: expiry, dispatch: dispatch, newSessionID: uuid.NewString, hostJWT: jwtSecret == ""}
}

func (m *SessionManager) Secret() []byte { return m.jwtSecret }

type sessionClaims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	SessionID string `json:"session_id"`
}

func (m *SessionManager) Verify(token string) (accountID, sessionID string, err error) {
	if m.hostJWT {
		claims, err := hostjwt.Verify(token)
		if err != nil {
			return "", "", err
		}
		return claims.AccountID, claims.SessionID, nil
	}
	var claims sessionClaims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return m.jwtSecret, nil
	})
	if err != nil || parsed == nil || !parsed.Valid || claims.AccountID == "" || claims.SessionID == "" {
		if err == nil {
			err = fmt.Errorf("invalid token claims")
		}
		return "", "", err
	}
	return claims.AccountID, claims.SessionID, nil
}

func (m *SessionManager) Exists(sessionID string) bool {
	if m.dispatch != nil {
		var result sessionWorkflowResult
		if err := m.call(sessionVerifiedEvent, map[string]any{
			"session_id": sessionID,
			"now":        time.Now().UTC().UnixMilli(),
		}, &result); err != nil {
			return false
		}
		return result.OK && result.Value.Active
	}
	m.mu.RLock()
	_, exists := m.sessions[sessionID]
	m.mu.RUnlock()
	return exists
}

func (m *SessionManager) Create(accountID uuid.UUID) (string, int, error) {
	sessionID := m.newSessionID()
	var signed string
	var err error
	if m.hostJWT {
		signed, err = hostjwt.Sign(hostjwt.SignRequest{AccountID: accountID.String(), SessionID: sessionID, ExpiresAt: time.Now().UTC().Add(m.expiry).UnixMilli()})
	} else {
		signed, err = authcrypto.MintJWT(m.jwtSecret, accountID, sessionID, m.expiry)
	}
	if err != nil {
		return "", 0, fmt.Errorf("sign token: %w", err)
	}
	now := time.Now().UTC()
	if m.dispatch != nil {
		var result sessionWorkflowResult
		if err := m.call(sessionCreatedEvent, map[string]any{
			"request_id": "session:create:" + sessionID,
			"session_id": sessionID,
			"account_id": accountID.String(),
			"created_at": now.UnixMilli(),
			"expires_at": now.Add(m.expiry).UnixMilli(),
		}, &result); err != nil {
			return "", 0, fmt.Errorf("persist session: %w", err)
		}
		if !result.OK || !result.Value.Active {
			return "", 0, fmt.Errorf("persist session: owner rejected session")
		}
	} else {
		m.mu.Lock()
		m.sessions[sessionID] = sessionEntry{AccountID: accountID.String(), CreatedAt: now}
		m.mu.Unlock()
	}
	return signed, int(m.expiry.Seconds()), nil
}

func (m *SessionManager) Revoke(sessionID string) {
	if m.dispatch != nil {
		var result sessionWorkflowResult
		_ = m.call(sessionRevokedEvent, map[string]any{
			"request_id": "session:revoke:" + sessionID,
			"session_id": sessionID,
			"revoked_at": time.Now().UTC().UnixMilli(),
		}, &result)
		return
	}
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
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
	result, err := m.dispatch.Dispatch(workflow.DispatchRequest{
		Event: event,
		Payload: map[string]any{
			"request_msgpack": requestWire,
		},
	})
	if err != nil {
		return err
	}
	responseWire, err := workflow.DecodeValue[[]byte](result)
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
