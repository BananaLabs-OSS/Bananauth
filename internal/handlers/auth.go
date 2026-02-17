package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/models"
	"github.com/bananalabs-oss/bananauth/internal/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	db       *bun.DB
	sessions *sessions.Manager
}

func NewAuthHandler(db *bun.DB, sm *sessions.Manager) *AuthHandler {
	return &AuthHandler{
		db:       db,
		sessions: sm,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "database_error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, models.ErrorResponse{
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "database_error"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, models.ErrorResponse{
			Error:   "username_taken",
			Message: "This username is already taken",
		})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "hash_error"})
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "creation_failed",
			Message: "Failed to create account",
		})
		return
	}

	// Create session
	token, expiresIn, err := h.sessions.Create(account.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "session_error"})
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
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
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid email or password",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(native.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid email or password",
		})
		return
	}

	token, expiresIn, err := h.sessions.Create(native.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "session_error"})
		return
	}

	c.JSON(http.StatusOK, models.TokenResponse{
		AccessToken: token,
		ExpiresIn:   expiresIn,
		AccountID:   native.AccountID.String(),
	})
}
