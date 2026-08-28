package otpscope

import (
	"testing"
	"time"
)

func TestOTPMatchesExactIdentityTypeCodeAndExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	row := StoredOTP{Email: "member@example.test", Code: "ABC123", Type: "password_reset", ExpiresAt: now.Add(time.Minute)}
	if !OTPMatches(row, "abc123", " MEMBER@example.test ", now) {
		t.Fatal("valid normalized OTP did not match")
	}
	if OTPMatches(row, "ABC123", "other@example.test", now) ||
		OTPMatches(row, "ABC123", row.Email, row.ExpiresAt) {
		t.Fatal("OTP escaped email or expiry scope")
	}
}
