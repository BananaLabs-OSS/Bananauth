// Package otpscope is the pure predicate kernel for Bananauth's
// password-reset OTP lookup, split into its own subpackage so it is
// host-buildable (and thus unit-testable) — the parent `package main` of
// pulp-cell only builds for GOOS=wasip1 GOARCH=wasm because Pulp/Fiber
// capabilities use //go:wasmimport.
//
// These mirror the two security-load-bearing pure pieces of auth.go:
//
//   - NormalizeEmail canonicalizes the email for storage and lookup
//     (lowercase + trim): the canonical form so case/whitespace variants
//     collide instead of bypassing the per-email scope. auth.go calls
//     this directly — NormalizeEmail is the single source of truth.
//
//   - OTPMatches encodes the WHERE clause of the AUTH-M2 / AUTH-M3 fix:
//     `code = UPPER(?) AND type = ? AND email = ? AND expires_at > now`.
//     The CRITICAL fix was adding `AND email = ?` so a reset code can no
//     longer be looked up GLOBALLY and consumed against ANOTHER user's
//     account (unauthenticated account-takeover primitive). This function
//     pins that the email scope, the type scope, the case-insensitive code
//     compare, and the expiry are all part of the match — keep it identical
//     to the query in auth.go ResetPassword.
package otpscope

import (
	"strings"
	"time"
)

// NormalizeEmail canonicalizes an email for storage and lookup.
// auth.go calls this directly — do not inline a duplicate.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// StoredOTP is the subset of the auth_otp_codes row the match predicate reads.
// Mirrors the relevant fields of models.go OTPCode without depending on bun.
type StoredOTP struct {
	Email     string
	Code      string // as stored (the cell stores the already-upper code)
	Type      string
	ExpiresAt time.Time
}

// OTPMatches reports whether a stored reset OTP row satisfies a reset attempt.
// It is the pure-Go twin of the ResetPassword SELECT's WHERE clause:
//
//	code = UPPER(reqCode) AND type = "password_reset"
//	  AND email = NormalizeEmail(reqEmail) AND expires_at > now
//
// reqEmail is normalized here exactly as the handler normalizes it before the
// query, so a case/whitespace variant cannot dodge the per-email scope.
//
// MUST stay behaviour-identical to the query in ../auth.go ResetPassword.
func OTPMatches(row StoredOTP, reqCode, reqEmail string, now time.Time) bool {
	if row.Type != "password_reset" {
		return false
	}
	if row.Email != NormalizeEmail(reqEmail) {
		return false // AUTH-M2: email scope — no global lookup
	}
	if row.Code != strings.ToUpper(reqCode) {
		return false
	}
	if !row.ExpiresAt.After(now) {
		return false // expired (or exactly-at-expiry) codes never match
	}
	return true
}
