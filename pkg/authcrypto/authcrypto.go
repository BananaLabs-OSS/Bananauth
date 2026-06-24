// Package authcrypto holds the pure cryptographic primitives shared between
// the native server (internal/*) and the WASM cell (pulp-cell/*). It has no
// platform-specific imports — only stdlib — so both build targets compile it
// unchanged.
package authcrypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// authClaims is the private JWT claims type used only by MintJWT.
// It is not exported because callers validate tokens through their own
// respective Claims types (which share the same JSON field names so tokens
// are interoperable).
type authClaims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	SessionID string `json:"session_id"`
}

// GenerateOTP returns a 6-character OTP drawn from [A-Z0-9] using
// crypto/rand. Used for password-reset codes.
func GenerateOTP() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 6)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b)
}

// GenerateState returns a 32-byte cryptographically random value encoded as
// URL-safe base64. Used as the CSRF state token in OAuth flows.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// MintJWT signs a new HS256 JWT for the given account/session and returns
// the signed token string. The returned token encodes both account_id and
// session_id claims so consumers can check session revocation after
// signature verification.
func MintJWT(secret []byte, accountID uuid.UUID, sessionID string, expiry time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := authClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        sessionID,
		},
		AccountID: accountID.String(),
		SessionID: sessionID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}
