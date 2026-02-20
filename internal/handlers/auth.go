package handlers

import (
	"context"
	"crypto/rand"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/models"
	"github.com/bananalabs-oss/bananauth/internal/sessions"
	"github.com/bananalabs-oss/potassium/middleware"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	db        *bun.DB
	sessions  *sessions.Manager
	sendEmail func(string, string) error
}

func NewAuthHandler(db *bun.DB, sm *sessions.Manager, sendEmail func(string, string) error) *AuthHandler {
	return &AuthHandler{
		db:        db,
		sessions:  sm,
		sendEmail: sendEmail,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

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
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

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
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

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
	} else {
		log.Printf("Password reset OTP for %s: %s", req.Email, code)
	}

	c.JSON(http.StatusOK, successResponse)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	var otp models.OTPCode
	err := h.db.NewSelect().
		Model(&otp).
		Where("code = ? AND type = ? AND expires_at > ?", strings.ToUpper(req.Code), "password_reset", time.Now().UTC()).
		Scan(ctx)
	if err != nil {
		c.JSON(http.StatusUnauthorized, middleware.ErrorResponse{
			Error:   "invalid_code",
			Message: "Invalid or expired reset code",
		})
		return
	}

	// Delete used OTP
	_, _ = h.db.NewDelete().
		Model((*models.OTPCode)(nil)).
		Where("id = ?", otp.ID).
		Exec(ctx)

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
	}

	// Delete everything in a transaction
	err = h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Profile
		_, _ = tx.NewDelete().Model((*models.Profile)(nil)).Where("account_id = ?", accountID).Exec(ctx)

		// OTP codes
		_, _ = tx.NewDelete().Model((*models.OTPCode)(nil)).Where("email = ?", native.Email).Exec(ctx)

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
	h.sessions.Revoke(sessionID.(string))

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
