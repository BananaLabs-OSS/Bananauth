package main

import (
	"crypto/subtle"
	"io"
	"net/http"

	"github.com/bananalabs-oss/bananauth/internal/browser"
	"github.com/bananalabs-oss/bananauth/internal/identity"
)

func registerIdentityRoutes(mux *http.ServeMux, handlers map[string]func([]byte) ([]byte, error), token string) {
	registerOwnerRoutes(mux, token, map[string]func([]byte) ([]byte, error){
		"/internal/identity/accounts/lookup":       handlers[identity.FnAccountGet],
		"/internal/identity/holds/acquire":         handlers[identity.FnRetentionHoldAcquire],
		"/internal/identity/holds/release":         handlers[identity.FnRetentionHoldRelease],
		"/internal/identity/leases/create":         handlers[identity.FnRetentionLeaseCreate],
		"/internal/identity/leases/renew":          handlers[identity.FnRetentionLeaseRenew],
		"/internal/identity/leases/release":        handlers[identity.FnRetentionLeaseRelease],
		"/internal/identity/retention/eligibility": handlers[identity.FnRetentionEligibility],
	})
}

func registerOwnerRoutes(mux *http.ServeMux, token string, routes map[string]func([]byte) ([]byte, error)) {
	for path, action := range routes {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			if len(token) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
				http.Error(w, "service authorization required", http.StatusUnauthorized)
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
			if err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			result, err := action(raw)
			if err != nil {
				http.Error(w, "identity operation unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/msgpack")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(result)
		})
	}
}

func registerBrowserWorkflowRoutes(mux *http.ServeMux, identities, sessions map[string]func([]byte) ([]byte, error), token string) {
	registerOwnerRoutes(mux, token, map[string]func([]byte) ([]byte, error){
		"/internal/browser/session/resolve":      sessions[browser.ProviderResolve],
		"/internal/browser/session/logout":       sessions[browser.ProviderLogout],
		"/internal/browser/email/complete":       sessions[browser.ProviderCompleteEmailVerification],
		"/internal/browser/email/v2/complete":    sessions[browser.ProviderCompleteEmailVerificationV2],
		"/internal/browser/email/issue":          identities[identity.FnEmailVerificationIssue],
		"/internal/browser/email/consume":        identities[identity.FnEmailVerificationConsume],
		"/internal/browser/email/login/issue":    identities[identity.FnEmailLoginIssueV2],
		"/internal/browser/email/login/consume":  identities[identity.FnEmailLoginConsumeV2],
		"/internal/browser/email/signup/issue":   identities[identity.FnEmailSignupIssueV2],
		"/internal/browser/email/signup/consume": identities[identity.FnEmailSignupConsumeV2],
		"/internal/browser/email/fact":           identities[identity.FnEmailVerificationFactGetV2],
	})
}

func registerAccountErasureRoutes(mux *http.ServeMux, identities map[string]func([]byte) ([]byte, error), token string) {
	registerOwnerRoutes(mux, token, map[string]func([]byte) ([]byte, error){
		"/internal/erasure/accounts/lookup":       identities[identity.FnAccountGet],
		"/internal/erasure/retention/eligibility": identities[identity.FnRetentionEligibility],
		"/internal/erasure/accounts/delete":       identities[identity.FnAccountDelete],
		"/internal/erasure/accounts/erase":        identities[identity.FnAccountErase],
		"/internal/erasure/receipts/lookup":       identities[identity.FnAccountErasureGetV1],
	})
}
