package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/models"
	"github.com/bananalabs-oss/bananauth/internal/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"golang.org/x/oauth2"
)

type OAuthHandler struct {
	db       *bun.DB
	sessions *sessions.Manager
	discord  *oauth2.Config

	// In-memory state store (replace with Redis later)
	mu     sync.RWMutex
	states map[string]time.Time // state -> expiry
}

type DiscordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func NewOAuthHandler(db *bun.DB, sm *sessions.Manager, discord *oauth2.Config) *OAuthHandler {
	h := &OAuthHandler{
		db:       db,
		sessions: sm,
		discord:  discord,
		states:   make(map[string]time.Time),
	}

	// Clean expired states every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			h.mu.Lock()
			now := time.Now()
			for state, expiry := range h.states {
				if now.After(expiry) {
					delete(h.states, state)
				}
			}
			h.mu.Unlock()
		}
	}()

	return h
}

func (h *OAuthHandler) DiscordAuthorize(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "state_error"})
		return
	}

	// Store state with 10 minute expiry
	h.mu.Lock()
	h.states[state] = time.Now().Add(10 * time.Minute)
	h.mu.Unlock()

	url := h.discord.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *OAuthHandler) DiscordCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	// Validate state
	h.mu.Lock()
	expiry, exists := h.states[state]
	if exists {
		delete(h.states, state)
	}
	h.mu.Unlock()

	if !exists || time.Now().After(expiry) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_state",
			Message: "OAuth state mismatch or expired",
		})
		return
	}

	ctx := c.Request.Context()

	// Exchange code for token
	token, err := h.discord.Exchange(ctx, code)
	if err != nil {
		log.Printf("OAuth exchange error: %v", err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "exchange_failed",
			Message: "Failed to exchange OAuth code",
		})
		return
	}

	// Fetch Discord user info
	discordUser, err := fetchDiscordUser(ctx, token.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "provider_error",
			Message: "Failed to fetch user info from Discord",
		})
		return
	}

	// Check if this Discord account is already linked
	var existingLink models.OAuthLink
	err = h.db.NewSelect().
		Model(&existingLink).
		Where("provider = ? AND provider_id = ?", "discord", discordUser.ID).
		Scan(ctx)

	// Case 1: Existing link — log them in
	if err == nil {
		sessionToken, expiresIn, err := h.sessions.Create(existingLink.AccountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "session_error"})
			return
		}

		c.JSON(http.StatusOK, models.TokenResponse{
			AccessToken: sessionToken,
			ExpiresIn:   expiresIn,
			AccountID:   existingLink.AccountID.String(),
		})
		return
	}

	// Case 2: New account via Discord
	var account models.Account
	err = h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		now := time.Now().UTC()

		account = models.Account{
			ID:        uuid.New(),
			CreatedAt: now,
			UpdatedAt: now,
		}
		if _, err := tx.NewInsert().Model(&account).Exec(ctx); err != nil {
			return err
		}

		link := models.OAuthLink{
			ID:            uuid.New(),
			AccountID:     account.ID,
			Provider:      "discord",
			ProviderID:    discordUser.ID,
			ProviderEmail: discordUser.Email,
			CreatedAt:     now,
		}
		if _, err := tx.NewInsert().Model(&link).Exec(ctx); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "creation_failed"})
		return
	}

	sessionToken, expiresIn, err := h.sessions.Create(account.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "session_error"})
		return
	}

	c.JSON(http.StatusCreated, models.TokenResponse{
		AccessToken: sessionToken,
		ExpiresIn:   expiresIn,
		AccountID:   account.ID.String(),
	})
}

func fetchDiscordUser(ctx context.Context, accessToken string) (*DiscordUser, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord API error: %s", string(body))
	}

	var user DiscordUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
