package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/bananalabs-oss/bananauth/internal/browser"
	"github.com/bananalabs-oss/bananauth/internal/identity"

	"io"
	"net/http"
)

// registerOwnerRoute is the authenticated HTTP codec boundary. Application
// services receive concrete Go values, never a provider name or byte message.
func registerOwnerRoute[Q, R any](mux *http.ServeMux, path, token string, action func(Q) (identity.Result[R], error)) {
	mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
		if !serviceAuthorized(w, r, token) {
			return
		}
		var request Q
		if err := readPrivateJSON(w, r, &request); err != nil {
			writeJSON(w, 400, errorResponse{Error: "invalid_request"})
			return
		}
		result, err := action(request)
		if err != nil {
			writeJSON(w, 503, errorResponse{Error: "identity_unavailable"})
			return
		}
		if !result.OK {
			code, message := "identity_error", "Identity operation failed"
			if result.Error != nil {
				code, message = result.Error.Code, result.Error.Message
			}
			status := 400
			switch code {
			case "not_found":
				status = 404
			case "conflict", "idempotency_conflict", "email_taken", "username_taken":
				status = 409
			case "invalid_credentials", "invalid_password", "invalid_code":
				status = 401
			case "unavailable":
				status = 503
			}
			writeJSON(w, status, errorResponse{Error: code, Message: message})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, result.Value)
	})
}
func serviceAuthorized(w http.ResponseWriter, r *http.Request, token string) bool {
	w.Header().Set("Cache-Control", "no-store")
	if len(token) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
		writeJSON(w, 401, errorResponse{Error: "unauthorized"})
		return false
	}
	return true
}

// Private requests are a bounded single JSON value with no duplicate keys.
func readPrivateJSON(w http.ResponseWriter, r *http.Request, value any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("JSON object required")
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	if err := rejectDuplicateJSON(tokens); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return fmt.Errorf("trailing request data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
func rejectDuplicateJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate request field")
			}
			seen[name] = true
			if err := rejectDuplicateJSON(d); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for d.More() {
			if err := rejectDuplicateJSON(d); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("invalid request shape")
	}
	_, err = d.Token()
	return err
}
func registerIdentityRoutes(mux *http.ServeMux, service *identity.Service, token string) {
	registerOwnerRoute(mux, "/internal/identity/accounts/lookup", token, service.AccountGet)
	registerOwnerRoute(mux, "/internal/identity/holds/acquire", token, service.RetentionHoldAcquire)
	registerOwnerRoute(mux, "/internal/identity/holds/release", token, service.RetentionHoldRelease)
	registerOwnerRoute(mux, "/internal/identity/leases/create", token, service.RetentionLeaseCreate)
	registerOwnerRoute(mux, "/internal/identity/leases/renew", token, service.RetentionLeaseRenew)
	registerOwnerRoute(mux, "/internal/identity/leases/release", token, service.RetentionLeaseRelease)
	registerOwnerRoute(mux, "/internal/identity/retention/eligibility", token, service.RetentionEligibility)
}
func registerBrowserWorkflowRoutes(mux *http.ServeMux, identities *identity.Service, browserService *browser.Service, token string) {
	mux.HandleFunc("POST /internal/browser/session/resolve", func(w http.ResponseWriter, r *http.Request) {
		if !serviceAuthorized(w, r, token) {
			return
		}
		var request struct {
			Credential string `json:"credential"`
		}
		if readPrivateJSON(w, r, &request) != nil {
			writeJSON(w, 400, errorResponse{Error: "invalid_request"})
			return
		}
		result := browserService.Resolve(browser.ResolveRequest{Version: browser.ContractVersion, Audience: browser.AccountAudience, Credential: request.Credential})
		if !result.OK {
			status := 401
			if result.Error == "unavailable" {
				status = 503
			}
			writeJSON(w, status, errorResponse{Error: result.Error})
			return
		}
		writeJSON(w, 200, struct {
			AccountID     string `json:"account_id"`
			SessionID     string `json:"session_id"`
			ExpiresAt     int64  `json:"expires_at_unix_milli"`
			Email         string `json:"email"`
			VerifiedEmail string `json:"verified_email"`
			EmailVerified bool   `json:"email_verified"`
		}{result.AccountID, result.SessionID, result.ExpiresAtUnixMilli, result.Email, result.VerifiedEmail, result.EmailVerified})
	})
	mux.HandleFunc("POST /internal/browser/session/logout", func(w http.ResponseWriter, r *http.Request) {
		if !serviceAuthorized(w, r, token) {
			return
		}
		var request struct {
			Credential string `json:"credential"`
		}
		if readPrivateJSON(w, r, &request) != nil {
			writeJSON(w, 400, errorResponse{Error: "invalid_request"})
			return
		}
		result := browserService.Logout(browser.ResolveRequest{Version: browser.ContractVersion, Audience: browser.AccountAudience, Credential: request.Credential})
		if !result.OK {
			status := 401
			if result.Error == "unavailable" {
				status = 503
			}
			writeJSON(w, status, errorResponse{Error: result.Error})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /internal/browser/email/complete", func(w http.ResponseWriter, r *http.Request) {
		if !serviceAuthorized(w, r, token) {
			return
		}
		var request struct {
			RequestID string `json:"request_id"`
			Email     string `json:"email"`
			Code      string `json:"code"`
			Intent    string `json:"intent"`
		}
		if readPrivateJSON(w, r, &request) != nil {
			writeJSON(w, 400, errorResponse{Error: "invalid_request"})
			return
		}
		result := browserService.CompleteEmailVerification(browser.CompleteEmailVerificationRequestV2{Version: browser.ContractVersion, RequestID: request.RequestID, Email: request.Email, Code: request.Code, Intent: request.Intent})
		if !result.OK {
			status := 400
			if result.Error == "unavailable" || result.Error == "identity_unavailable" || result.Error == "session_unavailable" {
				status = 503
			}
			writeJSON(w, status, errorResponse{Error: result.Error})
			return
		}
		writeJSON(w, 200, struct {
			AccessToken string `json:"access_token"`
			AccountID   string `json:"account_id"`
			SessionID   string `json:"session_id"`
			ExpiresIn   int64  `json:"expires_in"`
			ExpiresAt   int64  `json:"expires_at_unix_milli"`
		}{result.AccessToken, result.AccountID, result.SessionID, result.ExpiresIn, result.ExpiresAtUnixMilli})
	})
	registerOwnerRoute(mux, "/internal/browser/email/login/issue", token, identities.EmailLoginIssueV2)
	registerOwnerRoute(mux, "/internal/browser/email/login/consume", token, identities.EmailLoginConsumeV2)
	registerOwnerRoute(mux, "/internal/browser/email/signup/issue", token, identities.EmailSignupIssueV2)
	registerOwnerRoute(mux, "/internal/browser/email/signup/consume", token, identities.EmailSignupConsumeV2)
	registerOwnerRoute(mux, "/internal/browser/email/fact", token, identities.EmailVerificationFactGetV2)
}
func registerAccountErasureRoutes(mux *http.ServeMux, identities *identity.Service, token string) {
	registerOwnerRoute(mux, "/internal/erasure/accounts/lookup", token, identities.AccountGet)
	registerOwnerRoute(mux, "/internal/erasure/retention/eligibility", token, identities.RetentionEligibility)
	registerOwnerRoute(mux, "/internal/erasure/accounts/delete", token, identities.AccountDelete)
	registerOwnerRoute(mux, "/internal/erasure/accounts/erase", token, identities.AccountErase)
	registerOwnerRoute(mux, "/internal/erasure/receipts/lookup", token, identities.AccountErasureGetV1)
}
