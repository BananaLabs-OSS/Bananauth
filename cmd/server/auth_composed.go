package main

import (
	"net/http"
	"strings"
	"time"

	identitysvc "github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/bananalabs-oss/bananauth/pkg/otpscope"
	"github.com/google/uuid"
)

type identityAccount struct {
	AccountID string `msgpack:"account_id"`
	Email     string `msgpack:"email"`
	Username  string `msgpack:"username"`
	CreatedAt int64  `msgpack:"created_at"`
}

type resetIssueResult struct {
	Accepted     bool `msgpack:"accepted"`
	EffectQueued bool `msgpack:"effect_queued"`
}

type rateDecision struct {
	Allowed          bool  `msgpack:"allowed"`
	Count            int   `msgpack:"count"`
	RetryAfterMillis int64 `msgpack:"retry_after_millis"`
}

type emailVerificationIssueResult struct {
	Accepted     bool `msgpack:"accepted"`
	EffectQueued bool `msgpack:"effect_queued"`
}

type emailVerificationConsumeResult struct {
	Verified  bool   `msgpack:"verified"`
	AccountID string `msgpack:"account_id"`
}

func identityFailure(w http.ResponseWriter, r *http.Request, resultError *identityError, fallbackStatus int) {
	if resultError == nil {
		writeJSON(w, fallbackStatus, errorResponse{Error: "identity_error"})
		return
	}
	status := fallbackStatus
	switch resultError.Code {
	case "email_taken", "username_taken", "profile_exists", "native_exists":
		status = http.StatusConflict
	case "invalid_credentials", "invalid_password", "invalid_email", "invalid_code":
		status = http.StatusUnauthorized
	case "not_found":
		status = http.StatusNotFound
	case "rate_limited", "too_many_attempts":
		status = http.StatusTooManyRequests
	case "invalid_request":
		status = http.StatusBadRequest
	}
	writeJSON(w, status, errorResponse{Error: resultError.Code, Message: resultError.Message})
}

func (h *AuthHandler) registerComposed(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	now := time.Now().UTC()
	accountID, credentialID := uuid.NewString(), uuid.NewString()
	result, err := h.identity.NativeRegister(identitysvc.NativeRegisterRequest{RequestID: identityRequestID("native-register"), AccountID: accountID, CredentialID: credentialID, Email: otpscope.NormalizeEmail(req.Email), Username: req.Username, Password: req.Password, Now: now.UnixMilli()})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "creation_failed", Message: "Failed to create account"})
		return
	}
	if !result.OK {
		identityFailure(w, r, result.Error, http.StatusInternalServerError)
		return
	}
	parsed, err := uuid.Parse(result.Value.AccountID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "creation_failed"})
		return
	}
	token, expires, err := h.sessions.Create(parsed)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "session_error"})
		return
	}
	writeJSON(w, http.StatusCreated, TokenResponse{AccessToken: token, ExpiresIn: expires, AccountID: result.Value.AccountID})
}

func (h *AuthHandler) loginComposed(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	result, err := h.identity.NativeAuthenticate(identitysvc.NativeAuthenticateRequest{Email: otpscope.NormalizeEmail(req.Email), Password: req.Password})
	if err != nil || !result.OK {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_credentials", Message: "Invalid email or password"})
		return
	}
	accountID, err := uuid.Parse(result.Value.AccountID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "session_error"})
		return
	}
	token, expires, err := h.sessions.Create(accountID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "session_error"})
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{AccessToken: token, ExpiresIn: expires, AccountID: result.Value.AccountID})
}

func (h *AuthHandler) changePasswordComposed(w http.ResponseWriter, r *http.Request) {
	var req PasswordChangeRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID := accountID(r)
	result, err := h.identity.PasswordChange(identitysvc.PasswordChangeRequest{RequestID: identityRequestID("password-change"), AccountID: accountID, CurrentPassword: req.CurrentPassword, NewPassword: req.NewPassword, Now: time.Now().UTC().UnixMilli()})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "update_error"})
		return
	}
	if !result.OK {
		identityFailure(w, r, result.Error, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "password changed"})
}

func (h *AuthHandler) attachNativeCredentialComposed(w http.ResponseWriter, r *http.Request) {
	var req AttachNativeCredentialRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID := accountID(r)
	result, err := h.identity.NativeCredentialAttach(identitysvc.NativeCredentialAttachRequest{RequestID: identityRequestID("native-attach"), AccountID: accountID, CredentialID: uuid.NewString(), Email: otpscope.NormalizeEmail(req.Email), Username: req.Username, Password: req.Password, Now: time.Now().UTC().UnixMilli()})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "identity_error"})
		return
	}
	if !result.OK {
		identityFailure(w, r, result.Error, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"account_id": result.Value.AccountID, "native_attached": true})
}

func (h *AuthHandler) forgotPasswordComposed(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	now := time.Now().UTC()
	_, _ = h.identity.PasswordResetIssue(identitysvc.PasswordResetIssueRequest{RequestID: identityRequestID("password-reset-issue"), OTPID: uuid.NewString(), EffectID: uuid.NewString(), Email: otpscope.NormalizeEmail(req.Email), Code: authcrypto.GenerateOTP(), Now: now.UnixMilli(), ExpiresAt: now.Add(10 * time.Minute).UnixMilli()})
	writeJSON(w, http.StatusOK, map[string]any{"message": "if an account exists, a reset code has been sent"})
}

func (h *AuthHandler) resetPasswordComposed(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	now := time.Now().UTC()
	ipDecision, err := h.identity.RateCheck(identitysvc.RateCheckRequest{RequestID: identityRequestID("reset-ip"), Scope: "password_reset_ip", Key: clientIP(r), Now: now.UnixMilli(), WindowMillis: resetPwWindow.Milliseconds(), MaxAttempts: 1})
	if err != nil || !ipDecision.OK {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "identity_error"})
		return
	}
	if !ipDecision.Value.Allowed {
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate_limited", Message: "Please wait before trying again"})
		return
	}
	email := otpscope.NormalizeEmail(req.Email)
	reset, err := h.identity.PasswordResetConsume(identitysvc.PasswordResetConsumeRequest{RequestID: identityRequestID("password-reset-consume"), Email: email, Code: strings.ToUpper(req.Code), NewPassword: req.NewPassword, Now: now.UnixMilli()})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "update_error"})
		return
	}
	if !reset.OK {
		failures, failureErr := h.identity.RateCheck(identitysvc.RateCheckRequest{RequestID: identityRequestID("reset-email"), Scope: "password_reset_email", Key: email, Now: now.UnixMilli(), WindowMillis: int64((24 * time.Hour).Milliseconds()), MaxAttempts: resetPwMaxTry})
		if failureErr == nil && failures.OK && !failures.Value.Allowed {
			writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "too_many_attempts", Message: "Too many invalid attempts; request a new code"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid_code", Message: "Invalid or expired reset code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "password reset successful"})
}

func (h *AuthHandler) deleteAccountComposed(w http.ResponseWriter, r *http.Request) {
	var req DeleteAccountRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID := accountID(r)
	result, err := h.identity.AccountDelete(identitysvc.AccountDeleteRequest{RequestID: identityRequestID("account-delete"), AccountID: accountID, Password: req.Password, Email: req.Email, Now: time.Now().UTC().UnixMilli()})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "deletion_failed"})
		return
	}
	if !result.OK {
		identityFailure(w, r, result.Error, http.StatusInternalServerError)
		return
	}
	if sessionID := authentication(r).session; sessionID != "" {
		_ = h.sessions.RevokeChecked(sessionID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "account deleted"})
}
