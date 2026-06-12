package handlers

import (
	"context"
	"crypto/rand"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/models"
	"github.com/bananalabs-oss/bananauth/internal/sessions"
	"github.com/bananalabs-oss/potassium/middleware"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// Rate limiters — per-IP sync.Map storing last request time.
var (
	registerRL       sync.Map // ip -> time.Time
	loginRL          sync.Map // ip -> time.Time
	forgotPwRL       sync.Map // ip -> time.Time
	resetPwRL        sync.Map // ip -> time.Time
)

type AuthHandler struct {
	db        *bun.DB
	sessions  *sessions.Manager
	sendEmail func(string, string) error
}

func NewAuthHandler(db *bun.DB, sm *sessions.Manager, sendEmail func(string, string) error) *AuthHandler {
	h := &AuthHandler{
		db:        db,
		sessions:  sm,
		sendEmail: sendEmail,
	}

	// Periodically clean up expired OTP codes
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			h.db.NewDelete().Model((*models.OTPCode)(nil)).
				Where("expires_at < ?", time.Now().UTC()).
				Exec(context.Background())
		}
	}()

	return h
}

func (h *AuthHandler) Register(c *gin.Context) {
	ip := c.ClientIP()
	if last, ok := registerRL.Load(ip); ok && time.Since(last.(time.Time)) < 60*time.Second {
		c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "rate_limited", Message: "Please wait before registering again"})
		return
	}
	registerRL.Store(ip, time.Now())

	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	ctx := c.Request.Context()

	// Check if email already exists
	exists, err := h.db.NewSelect().
		Model((*models.NativeAccount)(nil)).
		Where("email = ?", req.Email).
		Exists(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "database_error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, middleware.ErrorResponse{
			Error:   "email_taken",
			Message: "An account with this email already exists",
		})
		return
	}

	// Check if username already exists
	exists, err = h.db.NewSelect().
		Model((*models.NativeAccount)(nil)).
		Where("username = ?", req.Username).
		Exists(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "database_error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, middleware.ErrorResponse{
			Error:   "username_taken",
			Message: "This username is already taken",
		})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "hash_error"})
		return
	}

	// Create account + native auth in a transaction
	var account models.Account
	err = h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		account = models.Account{
			ID:        uuid.New(),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		if _, err := tx.NewInsert().Model(&account).Exec(ctx); err != nil {
			return err
		}

		native := models.NativeAccount{
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
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{
			Error:   "creation_failed",
			Message: "Failed to create account",
		})
		return
	}

	// Create session
	token, expiresIn, err := h.sessions.Create(account.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}

	c.JSON(http.StatusCreated, models.TokenResponse{
		AccessToken: token,
		ExpiresIn:   expiresIn,
		AccountID:   account.ID.String(),
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	ip := c.ClientIP()
	if last, ok := loginRL.Load(ip); ok && time.Since(last.(time.Time)) < 10*time.Second {
		c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "rate_limited", Message: "Please wait before trying again"})
		return
	}
	loginRL.Store(ip, time.Now())

	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	ctx := c.Request.Context()

	var native models.NativeAccount
	err := h.db.NewSelect().
		Model(&native).
		Where("email = ?", req.Email).
		Scan(ctx)
	if err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid email or password",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(native.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid email or password",
		})
		return
	}

	token, expiresIn, err := h.sessions.Create(native.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}

	c.JSON(http.StatusOK, models.TokenResponse{
		AccessToken: token,
		ExpiresIn:   expiresIn,
		AccountID:   native.AccountID.String(),
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	sessionID, _ := c.Get("session_id")

	h.sessions.Revoke(sessionID.(string))

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func (h *AuthHandler) Session(c *gin.Context) {
	accountID, _ := c.Get("account_id")

	c.JSON(http.StatusOK, gin.H{
		"account_id": accountID,
		"valid":      true,
	})
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req models.PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	accountID, _ := c.Get("account_id")
	ctx := c.Request.Context()

	// Get current native account
	var native models.NativeAccount
	err := h.db.NewSelect().
		Model(&native).
		Where("account_id = ?", accountID).
		Scan(ctx)
	if err != nil {
		c.JSON(http.StatusNotFound, middleware.ErrorResponse{
			Error:   "not_found",
			Message: "No native account found",
		})
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(native.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{
			Error:   "invalid_password",
			Message: "Current password is incorrect",
		})
		return
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "hash_error"})
		return
	}

	// Update
	_, err = h.db.NewUpdate().
		Model(&native).
		Set("password_hash = ?", string(hash)).
		Where("id = ?", native.ID).
		Exec(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password changed"})
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	ip := c.ClientIP()
	if last, ok := forgotPwRL.Load(ip); ok && time.Since(last.(time.Time)) < 60*time.Second {
		c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "rate_limited", Message: "Please wait before requesting another code"})
		return
	}
	forgotPwRL.Store(ip, time.Now())

	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	ctx := c.Request.Context()
	successResponse := gin.H{"message": "if an account exists, a reset code has been sent"}

	var native models.NativeAccount
	err := h.db.NewSelect().
		Model(&native).
		Where("email = ?", req.Email).
		Scan(ctx)
	if err != nil {
		c.JSON(http.StatusOK, successResponse)
		return
	}

	// Delete existing reset codes for this email
	_, _ = h.db.NewDelete().
		Model((*models.OTPCode)(nil)).
		Where("email = ? AND type = ?", req.Email, "password_reset").
		Exec(ctx)

	code := generateOTP()
	now := time.Now().UTC()

	otp := models.OTPCode{
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

	if h.sendEmail != nil {
		_ = h.sendEmail(req.Email, code)
	} else if os.Getenv("DEV_MODE") == "true" {
		log.Printf("Password reset OTP for %s: %s", req.Email, code)
	}

	c.JSON(http.StatusOK, successResponse)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	ip := c.ClientIP()
	if last, ok := resetPwRL.Load(ip); ok && time.Since(last.(time.Time)) < 10*time.Second {
		c.JSON(http.StatusTooManyRequests, middleware.ErrorResponse{Error: "rate_limited", Message: "Please wait before trying again"})
		return
	}
	resetPwRL.Store(ip, time.Now())

	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	ctx := c.Request.Context()

	// Use a transaction to atomically SELECT + DELETE the OTP (TOCTOU fix)
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "database_error"})
		return
	}
	defer tx.Rollback()

	var otp models.OTPCode
	err = tx.NewSelect().
		Model(&otp).
		Where("code = ? AND type = ? AND expires_at > ? AND email = ?",
			strings.ToUpper(req.Code), "password_reset", time.Now().UTC(), req.Email).
		Scan(ctx)
	if err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{
			Error:   "invalid_code",
			Message: "Invalid or expired reset code",
		})
		return
	}

	// Delete used OTP within the same transaction
	_, _ = tx.NewDelete().
		Model((*models.OTPCode)(nil)).
		Where("id = ?", otp.ID).
		Exec(ctx)

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "database_error"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "hash_error"})
		return
	}

	_, err = h.db.NewUpdate().
		Model((*models.NativeAccount)(nil)).
		Set("password_hash = ?", string(hash)).
		Where("account_id = ?", otp.Metadata).
		Exec(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "update_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset successful"})
}

func (h *AuthHandler) DeleteAccount(c *gin.Context) {
	var req models.DeleteAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	accountID, _ := c.Get("account_id")
	sessionID, _ := c.Get("session_id")
	ctx := c.Request.Context()

	// Verify password if native account exists
	var native models.NativeAccount
	err := h.db.NewSelect().
		Model(&native).
		Where("account_id = ?", accountID).
		Scan(ctx)

	if err == nil {
		// Has native account — verify password
		if err := bcrypt.CompareHashAndPassword([]byte(native.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{
				Error:   "invalid_password",
				Message: "Password is incorrect",
			})
			return
		}
	} else {
		// OAuth-only account — verify by email match
		var oauthLink models.OAuthLink
		oauthErr := h.db.NewSelect().
			Model(&oauthLink).
			Where("account_id = ?", accountID).
			Limit(1).
			Scan(ctx)
		if oauthErr != nil {
			c.JSON(http.StatusNotFound, middleware.ErrorResponse{
				Error:   "not_found",
				Message: "No account found",
			})
			return
		}
		if req.Email == "" || !strings.EqualFold(oauthLink.ProviderEmail, req.Email) {
			c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{
				Error:   "invalid_email",
				Message: "Email does not match account",
			})
			return
		}
	}

	// Delete everything in a transaction
	err = h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Profile
		_, _ = tx.NewDelete().Model((*models.Profile)(nil)).Where("account_id = ?", accountID).Exec(ctx)

		// OTP codes (use native.Email if available, otherwise skip — OAuth-only accounts have no OTP codes)
		if native.Email != "" {
			_, _ = tx.NewDelete().Model((*models.OTPCode)(nil)).Where("email = ?", native.Email).Exec(ctx)
		}

		// OAuth links
		_, _ = tx.NewDelete().Model((*models.OAuthLink)(nil)).Where("account_id = ?", accountID).Exec(ctx)

		// Native account
		_, _ = tx.NewDelete().Model((*models.NativeAccount)(nil)).Where("account_id = ?", accountID).Exec(ctx)

		// Account
		_, err := tx.NewDelete().Model((*models.Account)(nil)).Where("id = ?", accountID).Exec(ctx)
		return err
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "deletion_failed"})
		return
	}

	// Revoke current session
	if sid, ok := sessionID.(string); ok {
		h.sessions.Revoke(sid)
	}

	c.JSON(http.StatusOK, gin.H{"message": "account deleted"})
}

func generateOTP() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 6)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b)
}
