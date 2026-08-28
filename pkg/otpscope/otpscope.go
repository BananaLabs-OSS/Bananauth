// Package otpscope defines the pure, reusable OTP identity and expiry rules.
package otpscope

import (
	"strings"
	"time"
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

type StoredOTP struct {
	Email     string
	Code      string
	Type      string
	ExpiresAt time.Time
}

func OTPMatches(row StoredOTP, requestCode, requestEmail string, now time.Time) bool {
	return row.Type == "password_reset" &&
		row.Email == NormalizeEmail(requestEmail) &&
		row.Code == strings.ToUpper(requestCode) &&
		row.ExpiresAt.After(now)
}
