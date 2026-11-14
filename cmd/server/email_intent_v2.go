package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/bananalabs-oss/bananauth/pkg/otpscope"
	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
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

func emailIntentEventsV2(intent string) (string, string, bool) {
	switch intent {
	case "", "login":
		return "bananauth.identity.email-login.issue.v2", "bananauth.identity.email-login.consume.v2", true
	case "signup":
		return "bananauth.identity.email-signup.issue.v2", "bananauth.identity.email-signup.consume.v2", true
	default:
		return "", "", false
	}
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
	event, _, ok := emailIntentEventsV2(req.Intent)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	now := time.Now().UTC()
	issued, err := callIdentity[emailVerificationIssueResult](h.identity, event, map[string]any{"request_id": identityRequestID("email-verification-v2-issue"), "verification_id": uuid.NewString(), "effect_id": uuid.NewString(), "email": otpscope.NormalizeEmail(req.Email), "caller_key": clientIP(r), "code": authcrypto.GenerateOTP(), "now": now.UnixMilli(), "expires_at": now.Add(10 * time.Minute).UnixMilli()})
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
	_, event, ok := emailIntentEventsV2(req.Intent)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	email := otpscope.NormalizeEmail(req.Email)
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	requestID, account := verificationConsumeIDs(h.verificationReplayKey, email, code)
	now := time.Now().UTC().UnixMilli()
	verified, err := callIdentity[identity.EmailVerificationConsumeResult](h.identity, event, identity.EmailVerificationConsumeRequest{
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
	_, _, ok := emailIntentEventsV2(req.Intent)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request"})
		return
	}
	if req.Intent == "" {
		req.Intent = "login"
	}
	request, err := msgpack.Marshal(map[string]any{"version": "auth.browser-session.v1", "request_id": req.RequestID, "email": req.Email, "code": req.Code, "intent": req.Intent})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: "identity_unavailable"})
		return
	}
	wire, err := h.completeV2(request)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: "identity_unavailable"})
		return
	}
	var completed struct {
		Version     string `msgpack:"version"`
		OK          bool   `msgpack:"ok"`
		AccessToken string `msgpack:"access_token"`
		AccountID   string `msgpack:"account_id"`
		SessionID   string `msgpack:"session_id"`
		ExpiresIn   int    `msgpack:"expires_in"`
		ExpiresAt   int64  `msgpack:"expires_at_unix_milli"`
	}
	if err != nil || msgpack.Unmarshal(wire, &completed) != nil || completed.Version != "auth.browser-session.v1" || !completed.OK || completed.AccessToken == "" || completed.AccountID == "" || completed.SessionID == "" || completed.ExpiresAt <= time.Now().UTC().UnixMilli() {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_code"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, StorefrontSessionResponse{AccessToken: completed.AccessToken, ExpiresIn: completed.ExpiresIn, AccountID: completed.AccountID, SessionID: completed.SessionID, ExpiresAt: completed.ExpiresAt})
}
