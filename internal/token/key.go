package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// These values are part of the existing browser token contract.
const issuer = "github.com/BananaLabs-OSS/Pulp-ext-jwt"
const audience = "identity.jwt.hs256"

type Key []byte

type Claims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	SessionID string `json:"session_id"`
}

func (key Key) Sign(request SignRequest) (string, error) {
	if len(key) < 32 || request.AccountID == "" || request.SessionID == "" || request.ExpiresAt <= time.Now().UnixMilli() {
		return "", errors.New("invalid signing configuration or claims")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Audience: jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.UnixMilli(request.ExpiresAt)),
		},
		AccountID: request.AccountID, SessionID: request.SessionID,
	}).SignedString([]byte(key))
}

func (key Key) Verify(proof string) (Claims, error) {
	var claims Claims
	if len(key) < 32 {
		return claims, errors.New("invalid signing key")
	}
	_, err := jwt.ParseWithClaims(proof, &claims, func(*jwt.Token) (any, error) {
		return []byte(key), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(),
		jwt.WithIssuer(issuer), jwt.WithAudience(audience))
	if err != nil || claims.AccountID == "" || claims.SessionID == "" {
		return Claims{}, errors.New("invalid token")
	}
	return claims, nil
}
