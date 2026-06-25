package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	"github.com/BananaLabs-OSS/Fiber/pulp/gin/middleware"
	"github.com/bananalabs-oss/bananauth/pkg/authcrypto"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// normalizeEmail canonicalizes an email for storage and lookup so that
// case/whitespace variants of the same address collide on the unique
// index instead of creating duplicate accounts. Mirrors native
// Bananauth/internal/handlers/auth.go.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Per-IP reset throttle + per-email bad-attempt cap for the
// password-reset OTP path. The cell runtime is step-driven (single
// goroutine), but a sync.Map keeps this safe regardless and matches the
// native per-IP limiter (AUTH-H1). Entries are lazily overwritten; the
// map is bounded by the active attacker IP / target email set and reset
// on cell restart.
var (
	resetPwRL     sync.Map // ip -> time.Time (last reset attempt)
	resetPwFails  sync.Map // normalized email -> failCount
	resetPwWindow = 10 * time.Second
	resetPwMaxTry = 5
)

type AuthHandler struct {
	db        *bun.DB
	sessions  *SessionManager
	sendEmail func(to, code string) error
}

func NewAuthHandler(db *bun.DB, sm *SessionManager, sendEmail func(string, string) error) *AuthHandler {
	return &AuthHandler{db: db, sessions: sm, sendEmail: sendEmail}
}

func (h *AuthHandler) Register(c *pulpgin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	req.Email = normalizeEmail(req.Email)

	ctx := c.Ctx()

	exists, err := h.db.NewSelect().Model((*NativeAccount)(nil)).Where("email = ?", req.Email).Exists(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "database_error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, middleware.ErrorResponse{Error: "email_taken", Message: "An account with this email already exists"})
		return
	}

	exists, err = h.db.NewSelect().Model((*NativeAccount)(nil)).Where("username = ?", req.Username).Exists(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "database_error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, middleware.ErrorResponse{Error: "username_taken", Message: "This username is already taken"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "hash_error"})
		return
	}

	var account Account
	err = h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		account = Account{
			ID:        uuid.New(),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		if _, err := tx.NewInsert().Model(&account).Exec(ctx); err != nil {
			return err
		}
		native := NativeAccount{
			ID:           uuid.New(),
			AccountID:    account.ID,
			Email:        req.Email,
			Username:     req.Username,
			PasswordHash: string(hash),
			CreatedAt:    time.Now().UTC(),
		}
		if _, err := tx.NewInsert().Model(&native).Exec(ctx); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "creation_failed", Message: "Failed to create account"})
		return
	}

	token, expiresIn, err := h.sessions.Create(account.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{
		AccessToken: token,
		ExpiresIn:   expiresIn,
		AccountID:   account.ID.String(),
	})
}

func (h *AuthHandler) Login(c *pulpgin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	req.Email = normalizeEmail(req.Email)

	ctx := c.Ctx()

	var native NativeAccount
	err := h.db.NewSelect().Model(&native).Where("email = ?", req.Email).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_credentials", Message: "Invalid email or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(native.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_credentials", Message: "Invalid email or password"})
		return
	}

	token, expiresIn, err := h.sessions.Create(native.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: token,
		ExpiresIn:   expiresIn,
		AccountID:   native.AccountID.String(),
	})
}

func (h *AuthHandler) Logout(c *pulpgin.Context) {
	sessionID, _ := c.Get("session_id")
	if sid, ok := sessionID.(string); ok {
		h.sessions.Revoke(sid)
	}
	c.JSON(http.StatusOK, pulpgin.H{"message": "logged out"})
}

func (h *AuthHandler) Session(c *pulpgin.Context) {
	accountID, _ := c.Get("account_id")
	c.JSON(http.StatusOK, pulpgin.H{
		"account_id": accountID,
		"valid":      true,
	})
}

func (h *AuthHandler) ChangePassword(c *pulpgin.Context) {
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
	ctx := c.Ctx()

	var native NativeAccount
	err := h.db.NewSelect().Model(&native).Where("account_id = ?", accountID).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusNotFound, middleware.ErrorResponse{Error: "not_found", Message: "No native account found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(native.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_password", Message: "Current password is incorrect"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "hash_error"})
		return
	}

	_, err = h.db.NewUpdate().Model(&native).Set("password_hash = ?", string(hash)).Where("id = ?", native.ID).Exec(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_error"})
		return
	}

	c.JSON(http.StatusOK, pulpgin.H{"message": "password changed"})
}

func (h *AuthHandler) ForgotPassword(c *pulpgin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	req.Email = normalizeEmail(req.Email)

	ctx := c.Ctx()
	successResponse := pulpgin.H{"message": "if an account exists, a reset code has been sent"}

	var native NativeAccount
	err := h.db.NewSelect().Model(&native).Where("email = ?", req.Email).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusOK, successResponse)
		return
	}

	_, _ = h.db.NewDelete().Model((*OTPCode)(nil)).Where("email = ? AND type = ?", req.Email, "password_reset").Exec(ctx)

	code := authcrypto.GenerateOTP()
	now := time.Now().UTC()
	otp := OTPCode{
		ID:        uuid.New(),
		Email:     req.Email,
		Code:      code,
		Type:      "password_reset",
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
		Metadata:  native.AccountID.String(),
	}
	if _, err := h.db.NewInsert().Model(&otp).Exec(ctx); err != nil {
		c.JSON(http.StatusOK, successResponse)
		return
	}

	_ = h.sendEmail(req.Email, code)

	c.JSON(http.StatusOK, successResponse)
}

func (h *AuthHandler) ResetPassword(c *pulpgin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_request", Message: err.Error()})
		return
	}

	// Per-IP throttle (AUTH-H1 parity): blunt the brute-force rate.
	ip := c.ClientIP()
	if last, ok := resetPwRL.Load(ip); ok && time.Since(last.(time.Time)) < resetPwWindow {
		c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "rate_limited", Message: "Please wait before trying again"})
		return
	}
	resetPwRL.Store(ip, time.Now())

	req.Email = normalizeEmail(req.Email)

	// Per-email bad-attempt cap: after too many wrong codes, lock the
	// target out of further guesses until a new code is requested.
	if n, ok := resetPwFails.Load(req.Email); ok && n.(int) >= resetPwMaxTry {
		c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "too_many_attempts", Message: "Too many invalid attempts; request a new code"})
		return
	}

	ctx := c.Ctx()

	// Atomically SELECT + DELETE the OTP within one transaction so a
	// code is single-use even under concurrency (AUTH-M3 TOCTOU fix),
	// and scope the lookup to the requesting email so a code cannot
	// match another user's account globally (AUTH-M2).
	var otp OTPCode
	err := h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := tx.NewSelect().Model(&otp).
			Where("code = ? AND type = ? AND email = ? AND expires_at > ?",
				strings.ToUpper(req.Code), "password_reset", req.Email, time.Now().UTC()).
			Scan(ctx); err != nil {
			return err
		}
		_, err := tx.NewDelete().Model((*OTPCode)(nil)).Where("id = ?", otp.ID).Exec(ctx)
		return err
	})
	if err != nil {
		// Count the failed guess against the target email.
		cur, _ := resetPwFails.LoadOrStore(req.Email, 0)
		resetPwFails.Store(req.Email, cur.(int)+1)
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_code", Message: "Invalid or expired reset code"})
		return
	}

	// Successful consume — clear the bad-attempt counter for this email.
	resetPwFails.Delete(req.Email)

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "hash_error"})
		return
	}

	_, err = h.db.NewUpdate().Model((*NativeAccount)(nil)).Set("password_hash = ?", string(hash)).Where("account_id = ?", otp.Metadata).Exec(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_error"})
		return
	}

	c.JSON(http.StatusOK, pulpgin.H{"message": "password reset successful"})
}

func (h *AuthHandler) DeleteAccount(c *pulpgin.Context) {
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
	sessionID, _ := c.Get("session_id")
	ctx := c.Ctx()

	var native NativeAccount
	err := h.db.NewSelect().Model(&native).Where("account_id = ?", accountID).Scan(ctx)
	if err == nil {
		// Native account — verify the password.
		if err := bcrypt.CompareHashAndPassword([]byte(native.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_password", Message: "Password is incorrect"})
			return
		}
	} else {
		// OAuth-only account — verify ownership by matching the
		// provider email (AUTH-M4 parity). Never allow deletion with
		// no credential proof.
		var oauthLink OAuthLink
		oauthErr := h.db.NewSelect().Model(&oauthLink).Where("account_id = ?", accountID).Limit(1).Scan(ctx)
		if oauthErr != nil {
			c.JSON(http.StatusNotFound, middleware.ErrorResponse{Error: "not_found", Message: "No account found"})
			return
		}
		if req.Email == "" || !strings.EqualFold(oauthLink.ProviderEmail, normalizeEmail(req.Email)) {
			c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{Error: "invalid_email", Message: "Email does not match account"})
			return
		}
	}

	err = h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, _ = tx.NewDelete().Model((*Profile)(nil)).Where("account_id = ?", accountID).Exec(ctx)
		if native.Email != "" {
			_, _ = tx.NewDelete().Model((*OTPCode)(nil)).Where("email = ?", native.Email).Exec(ctx)
		}
		_, _ = tx.NewDelete().Model((*OAuthLink)(nil)).Where("account_id = ?", accountID).Exec(ctx)
		_, _ = tx.NewDelete().Model((*NativeAccount)(nil)).Where("account_id = ?", accountID).Exec(ctx)
		_, err := tx.NewDelete().Model((*Account)(nil)).Where("id = ?", accountID).Exec(ctx)
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "deletion_failed"})
		return
	}

	if sid, ok := sessionID.(string); ok {
		h.sessions.Revoke(sid)
	}

	c.JSON(http.StatusOK, pulpgin.H{"message": "account deleted"})
}

