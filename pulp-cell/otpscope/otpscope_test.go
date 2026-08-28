// PERMANENT regression pin for the Bananauth password-reset OTP CRITICAL
// (AUTH-M2 global-unscoped-reset-OTP → unauthenticated account takeover) and
// its email-normalization dependency. The fix added `AND email = ?` to the
// reset-OTP lookup; this table proves a code can ONLY be consumed against the
// email it was issued for, that the type/expiry scopes hold, and that the
// email match is normalization-insensitive (so a case variant can't dodge it).
package otpscope

import (
	"testing"
	"time"
)

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"User@Example.COM":    "user@example.com",
		"  pad@example.com  ": "pad@example.com",
		"already@lower.case":  "already@lower.case",
		"\tTAB@Example.com\n": "tab@example.com",
		"":                    "",
		"   ":                 "",
	}
	for in, want := range cases {
		if got := NormalizeEmail(in); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOTPMatches(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	future := now.Add(10 * time.Minute)
	past := now.Add(-1 * time.Minute)

	// The row as the handler stores it: normalized email, UPPER code,
	// password_reset type, 10-min expiry.
	victimRow := StoredOTP{
		Email:     "victim@example.com",
		Code:      "ABC123",
		Type:      "password_reset",
		ExpiresAt: future,
	}

	cases := []struct {
		name     string
		row      StoredOTP
		reqCode  string
		reqEmail string
		now      time.Time
		want     bool
	}{
		// ---- legitimate owner consuming their own code ----
		{"exact match", victimRow, "ABC123", "victim@example.com", now, true},
		{"code lowercased in request", victimRow, "abc123", "victim@example.com", now, true},
		{"email upper in request", victimRow, "ABC123", "VICTIM@EXAMPLE.COM", now, true},
		{"email padded in request", victimRow, "ABC123", "  victim@example.com ", now, true},

		// ---- THE CRITICAL: a stranger must not consume the victim's code ----
		{"different email rejected (global-lookup IDOR)", victimRow, "ABC123", "attacker@evil.com", now, false},
		{"same domain different user rejected", victimRow, "ABC123", "other@example.com", now, false},
		{"empty request email rejected", victimRow, "ABC123", "", now, false},

		// ---- type scope ----
		{"wrong type rejected", StoredOTP{Email: "victim@example.com", Code: "ABC123", Type: "email_verify", ExpiresAt: future}, "ABC123", "victim@example.com", now, false},

		// ---- code scope ----
		{"wrong code rejected", victimRow, "ZZZ999", "victim@example.com", now, false},
		{"empty code rejected", victimRow, "", "victim@example.com", now, false},

		// ---- expiry scope ----
		{"expired code rejected", StoredOTP{Email: "victim@example.com", Code: "ABC123", Type: "password_reset", ExpiresAt: past}, "ABC123", "victim@example.com", now, false},
		{"exactly-at-expiry rejected", StoredOTP{Email: "victim@example.com", Code: "ABC123", Type: "password_reset", ExpiresAt: now}, "ABC123", "victim@example.com", now, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := OTPMatches(c.row, c.reqCode, c.reqEmail, c.now); got != c.want {
				t.Errorf("OTPMatches = %v, want %v (row=%+v reqCode=%q reqEmail=%q)",
					got, c.want, c.row, c.reqCode, c.reqEmail)
			}
		})
	}
}
