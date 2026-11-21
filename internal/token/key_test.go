package token

import (
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"testing"
	"time"
)

func TestCanonicalIssuerIsRequiredWithoutLegacyFallback(t *testing.T) {
	key := Key(strings.Repeat("k", 32))
	proof, err := key.Sign(SignRequest{AccountID: "account", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := key.Verify(proof)
	if err != nil || claims.Issuer != "bananauth" || claims.AccountID != "account" || claims.SessionID != "session" {
		t.Fatal("canonical token rejected", err)
	}
	for _, issuer := range []string{"retired-issuer", "", "other-application"} {
		forged := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Audience: jwt.ClaimStrings{audience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, AccountID: "account", SessionID: "session"}
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, forged).SignedString([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := key.Verify(signed); err == nil {
			t.Fatalf("unexpected issuer accepted: %q", issuer)
		}
	}
}
