package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/browser"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/bananalabs-oss/bananauth/pkg/otpscope"
	"github.com/google/uuid"
)

func verificationConsumeIDs(key []byte, email, code string) (string, string) {
	digest := func(purpose, value string) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(purpose + "\x00" + value))
		return mac.Sum(nil)
	}
	request := digest("sessions-email-verification-consume", email+"\x00"+code)
	var account uuid.UUID
	copy(account[:], digest("sessions-email-account", email))
	account[6] = (account[6] & 0x0f) | 0x40
	account[8] = (account[8] & 0x3f) | 0x80
	return "verification-submit:" + hex.EncodeToString(request) + ":bananauth-consume", account.String()
}

type EmailVerificationIssueRequestV2 struct {
	Email  string `json:"email" binding:"required,email"`
	Intent string `json:"intent"`
}
type EmailVerificationConsumeRequestV2 struct {
	Email  string `json:"email" binding:"required,email"`
	Code   string `json:"code" binding:"required"`
	Intent string `json:"intent"`
}
type EmailVerificationSessionRequestV2 struct {
	Email     string `json:"email" binding:"required,email"`
	Code      string `json:"code" binding:"required"`
	RequestID string `json:"request_id" binding:"required"`
	Intent    string `json:"intent"`
}

func (h *AuthHandler) IssueEmailVerificationV2(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{Error: "composed_identity_required"})
		return
	}
	var req EmailVerificationIssueRequestV2
	if readJSON(w, r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	execute := h.identity.EmailLoginIssueV2
	if req.Intent == "signup" {
		execute = h.identity.EmailSignupIssueV2
	}
	ok := req.Intent == "" || req.Intent == "login" || req.Intent == "signup"
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	now := time.Now().UTC()
	issued, err := execute(identity.EmailVerificationIssueRequest{RequestID: identityRequestID("email-verification-v2-issue"), VerificationID: uuid.NewString(), EffectID: uuid.NewString(), Email: otpscope.NormalizeEmail(req.Email), CallerKey: clientIP(r), Code: authcrypto.GenerateOTP(), Now: now.UnixMilli(), ExpiresAt: now.Add(10 * time.Minute).UnixMilli()})
	if err != nil || !issued.OK || !issued.Value.Accepted {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: "identity_unavailable"})
		return
	}
	// Identical acknowledgment for existing/unknown/throttled; never falsely
	// claims sent, enumerates membership or labels a nonmember as rate-limited.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
}
func (h *AuthHandler) ConsumeEmailVerificationV2(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{Error: "composed_identity_required"})
		return
	}
	var req EmailVerificationConsumeRequestV2
	if readJSON(w, r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	execute := h.identity.EmailLoginConsumeV2
	if req.Intent == "signup" {
		execute = h.identity.EmailSignupConsumeV2
	}
	ok := req.Intent == "" || req.Intent == "login" || req.Intent == "signup"
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	email := otpscope.NormalizeEmail(req.Email)
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	requestID, account := verificationConsumeIDs(h.verificationReplayKey, email, code)
	now := time.Now().UTC().UnixMilli()
	verified, err := execute(identity.EmailVerificationConsumeRequest{
		RequestID: requestID, AccountID: account, Email: email, Code: code, Now: now,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: "identity_unavailable"})
		return
	}
	result := verified.Value
	if !verified.OK || !result.Verified || result.AccountID == "" || result.VerifiedEmail != email ||
		result.VerificationRequestID != requestID || result.EmailVerifiedAtUnixMilli <= 0 ||
		result.EmailVerifiedAtUnixMilli > now || result.EmailVerificationExpiresAtUnixMilli <= now {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_code"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"verified": true, "account_id": verified.Value.AccountID})
}
func (h *AuthHandler) CompleteEmailVerificationSessionV2(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeJSON(w, http.StatusNotImplemented, errorResponse{Error: "composed_identity_required"})
		return
	}
	var req EmailVerificationSessionRequestV2
	if readJSON(w, r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	ok := req.Intent == "" || req.Intent == "login" || req.Intent == "signup"
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	if req.Intent == "" {
		req.Intent = "login"
	}
	completed := h.completeV2(browser.CompleteEmailVerificationRequestV2{Version: browser.ContractVersion, RequestID: req.RequestID, Email: req.Email, Code: req.Code, Intent: req.Intent})
	if completed.Version != browser.ContractVersion || !completed.OK || completed.AccessToken == "" || completed.AccountID == "" || completed.SessionID == "" || completed.ExpiresAtUnixMilli <= time.Now().UTC().UnixMilli() {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_code"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, StorefrontSessionResponse{AccessToken: completed.AccessToken, ExpiresIn: int(completed.ExpiresIn), AccountID: completed.AccountID, SessionID: completed.SessionID, ExpiresAt: completed.ExpiresAtUnixMilli})
}
