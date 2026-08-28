// Package otpscope retains the historical import path as a compatibility
// facade over Bananauth's stateless reusable OTP library.
package otpscope

import (
	"time"

	root "github.com/bananalabs-oss/bananauth/pkg/otpscope"
)

type StoredOTP = root.StoredOTP

func NormalizeEmail(email string) string {
	return root.NormalizeEmail(email)
}

func OTPMatches(row StoredOTP, requestCode, requestEmail string, now time.Time) bool {
	return root.OTPMatches(row, requestCode, requestEmail, now)
}
