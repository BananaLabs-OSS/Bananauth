package main

import (
	"net/http"
	"strings"
	"time"

	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	"github.com/BananaLabs-OSS/Fiber/pulp/gin/middleware"
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

func identityFailure(c *pulpgin.Context, resultError *identityError, fallbackStatus int) {
	if resultError == nil {
		c.JSON(fallbackStatus, middleware.ErrorResponse{Error: "identity_error"})
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
	c.JSON(status, middleware.ErrorResponse{Error: resultError.Code, Message: resultError.Message})
}

func (h *AuthHandler) registerComposed(c *pulpgin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	now := time.Now().UTC()
	accountID, credentialID := uuid.NewString(), uuid.NewString()
	result, err := callIdentity[identityAccount](h.identity, identityNativeRegisterEvent, map[string]any{
		"request_id": identityRequestID("native-register"), "account_id": accountID,
		"credential_id": credentialID, "email": otpscope.NormalizeEmail(req.Email),
		"username": req.Username, "password": req.Password, "now": now.UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "creation_failed", Message: "Failed to create account"})
		return
	}
	if !result.OK {
		identityFailure(c, result.Error, http.StatusInternalServerError)
		return
	}
	parsed, err := uuid.Parse(result.Value.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "creation_failed"})
		return
	}
	token, expires, err := h.sessions.Create(parsed)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}
	c.JSON(http.StatusCreated, TokenResponse{AccessToken: token, ExpiresIn: expires, AccountID: result.Value.AccountID})
}

func (h *AuthHandler) loginComposed(c *pulpgin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	result, err := callIdentity[identityAccount](h.identity, identityNativeAuthenticateEvent, map[string]any{
		"email": otpscope.NormalizeEmail(req.Email), "password": req.Password,
	})
	if err != nil || !result.OK {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_credentials", Message: "Invalid email or password"})
		return
	}
	accountID, err := uuid.Parse(result.Value.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}
	token, expires, err := h.sessions.Create(accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}
	c.JSON(http.StatusOK, TokenResponse{AccessToken: token, ExpiresIn: expires, AccountID: result.Value.AccountID})
}

func (h *AuthHandler) changePasswordComposed(c *pulpgin.Context) {
	var req PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID, _ := c.Get("account_id")
	result, err := callIdentity[map[string]any](h.identity, identityPasswordChangeEvent, map[string]any{
		"request_id": identityRequestID("password-change"), "account_id": accountID,
		"current_password": req.CurrentPassword, "new_password": req.NewPassword,
		"now": time.Now().UTC().UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_error"})
		return
	}
	if !result.OK {
		identityFailure(c, result.Error, http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, pulpgin.H{"message": "password changed"})
}

func (h *AuthHandler) attachNativeCredentialComposed(c *pulpgin.Context) {
	var req AttachNativeCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID, _ := c.Get("account_id")
	result, err := callIdentity[identityAccount](h.identity, identityNativeAttachEvent, map[string]any{
		"request_id": identityRequestID("native-attach"), "account_id": accountID, "credential_id": uuid.NewString(),
		"email": otpscope.NormalizeEmail(req.Email), "username": req.Username, "password": req.Password, "now": time.Now().UTC().UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "identity_error"})
		return
	}
	if !result.OK {
		identityFailure(c, result.Error, http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusCreated, pulpgin.H{"account_id": result.Value.AccountID, "native_attached": true})
}

func (h *AuthHandler) forgotPasswordComposed(c *pulpgin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	now := time.Now().UTC()
	_, _ = callIdentity[resetIssueResult](h.identity, identityPasswordResetIssueEvent, map[string]any{
		"request_id": identityRequestID("password-reset-issue"), "otp_id": uuid.NewString(),
		"effect_id": uuid.NewString(), "email": otpscope.NormalizeEmail(req.Email),
		"code": authcrypto.GenerateOTP(), "now": now.UnixMilli(), "expires_at": now.Add(10 * time.Minute).UnixMilli(),
	})
	c.JSON(http.StatusOK, pulpgin.H{"message": "if an account exists, a reset code has been sent"})
}

func (h *AuthHandler) resetPasswordComposed(c *pulpgin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	now := time.Now().UTC()
	ipDecision, err := callIdentity[rateDecision](h.identity, identityRateCheckEvent, map[string]any{
		"request_id": identityRequestID("reset-ip"), "scope": "password_reset_ip", "key": c.ClientIP(),
		"now": now.UnixMilli(), "window_millis": resetPwWindow.Milliseconds(), "max_attempts": 1,
	})
	if err != nil || !ipDecision.OK {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "identity_error"})
		return
	}
	if !ipDecision.Value.Allowed {
		c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "rate_limited", Message: "Please wait before trying again"})
		return
	}
	email := otpscope.NormalizeEmail(req.Email)
	reset, err := callIdentity[map[string]any](h.identity, identityPasswordResetConsumeEvent, map[string]any{
		"request_id": identityRequestID("password-reset-consume"), "email": email,
		"code": strings.ToUpper(req.Code), "new_password": req.NewPassword, "now": now.UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_error"})
		return
	}
	if !reset.OK {
		failures, failureErr := callIdentity[rateDecision](h.identity, identityRateCheckEvent, map[string]any{
			"request_id": identityRequestID("reset-email"), "scope": "password_reset_email", "key": email,
			"now": now.UnixMilli(), "window_millis": int64((24 * time.Hour).Milliseconds()), "max_attempts": resetPwMaxTry,
		})
		if failureErr == nil && failures.OK && !failures.Value.Allowed {
			c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "too_many_attempts", Message: "Too many invalid attempts; request a new code"})
			return
		}
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_code", Message: "Invalid or expired reset code"})
		return
	}
	c.JSON(http.StatusOK, pulpgin.H{"message": "password reset successful"})
}

func (h *AuthHandler) issueEmailVerificationComposed(c *pulpgin.Context) {
	var req EmailVerificationIssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	now := time.Now().UTC()
	issued, err := callIdentity[emailVerificationIssueResult](h.identity, identityEmailVerificationIssueEvent, map[string]any{
		"request_id":      identityRequestID("email-verification-issue"),
		"verification_id": uuid.NewString(),
		"effect_id":       uuid.NewString(),
		"email":           otpscope.NormalizeEmail(req.Email),
		"code":            authcrypto.GenerateOTP(),
		"now":             now.UnixMilli(),
		"expires_at":      now.Add(10 * time.Minute).UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, middleware.ErrorResponse{Error: "identity_unavailable"})
		return
	}
	if !issued.OK || !issued.Value.Accepted {
		identityFailure(c, issued.Error, http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, pulpgin.H{"sent": true})
}

func (h *AuthHandler) consumeEmailVerificationComposed(c *pulpgin.Context) {
	var req EmailVerificationConsumeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	verified, err := callIdentity[emailVerificationConsumeResult](h.identity, identityEmailVerificationConsumeEvent, map[string]any{
		"request_id": identityRequestID("email-verification-consume"),
		"account_id": uuid.NewString(),
		"email":      otpscope.NormalizeEmail(req.Email),
		"code":       strings.ToUpper(req.Code),
		"now":        time.Now().UTC().UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, middleware.ErrorResponse{Error: "identity_unavailable"})
		return
	}
	if !verified.OK || !verified.Value.Verified || verified.Value.AccountID == "" {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_code", Message: "Invalid or expired verification code"})
		return
	}
	// AccountID was created or resolved only by the composed identity owner.
	// It is returned over the configured Bananauth service response, never
	// accepted from an inbound Sessions/browser header.
	c.JSON(http.StatusOK, pulpgin.H{"verified": true, "account_id": verified.Value.AccountID})
}

func (h *AuthHandler) deleteAccountComposed(c *pulpgin.Context) {
	var req DeleteAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	accountID, _ := c.Get("account_id")
	result, err := callIdentity[identityAccount](h.identity, identityAccountDeleteEvent, map[string]any{
		"request_id": identityRequestID("account-delete"), "account_id": accountID,
		"password": req.Password, "email": req.Email, "now": time.Now().UTC().UnixMilli(),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "deletion_failed"})
		return
	}
	if !result.OK {
		identityFailure(c, result.Error, http.StatusInternalServerError)
		return
	}
	if sessionID, ok := c.Get("session_id"); ok {
		if value, ok := sessionID.(string); ok {
			h.sessions.Revoke(value)
		}
	}
	c.JSON(http.StatusOK, pulpgin.H{"message": "account deleted"})
}
