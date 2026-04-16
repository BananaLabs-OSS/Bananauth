package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp"
	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	"github.com/BananaLabs-OSS/Fiber/pulp/gin/middleware"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// DiscordOAuthConfig holds the per-plugin Discord OAuth credentials.
// Set via manifest [config] — empty ClientID/Secret disables the flow.
type DiscordOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

const (
	discordAuthURL     = "https://discord.com/api/oauth2/authorize"
	discordTokenURL    = "https://discord.com/api/oauth2/token"
	discordUserInfoURL = "https://discord.com/api/users/@me"
	discordScopes      = "identify email"
)

type OAuthHandler struct {
	db       *bun.DB
	sessions *SessionManager
	discord  DiscordOAuthConfig

	mu     sync.Mutex
	states map[string]time.Time
}

func NewOAuthHandler(db *bun.DB, sm *SessionManager, discord DiscordOAuthConfig) *OAuthHandler {
	return &OAuthHandler{
		db:       db,
		sessions: sm,
		discord:  discord,
		states:   map[string]time.Time{},
	}
}

// pruneStates removes expired OAuth state entries. Called lazily at
// the start of Authorize / Callback so we do not need a background
// goroutine (plugin runtime is step-driven, not concurrent).
func (h *OAuthHandler) pruneStates() {
	now := time.Now()
	h.mu.Lock()
	for s, expiry := range h.states {
		if now.After(expiry) {
			delete(h.states, s)
		}
	}
	h.mu.Unlock()
}

func (h *OAuthHandler) DiscordAuthorize(c *pulpgin.Context) {
	h.pruneStates()

	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "state_error"})
		return
	}
	h.mu.Lock()
	h.states[state] = time.Now().Add(10 * time.Minute)
	h.mu.Unlock()

	params := url.Values{
		"client_id":     {h.discord.ClientID},
		"redirect_uri":  {h.discord.RedirectURL},
		"response_type": {"code"},
		"scope":         {discordScopes},
		"state":         {state},
	}
	c.Redirect(http.StatusTemporaryRedirect, discordAuthURL+"?"+params.Encode())
}

func (h *OAuthHandler) DiscordCallback(c *pulpgin.Context) {
	h.pruneStates()

	code := c.Query("code")
	state := c.Query("state")

	h.mu.Lock()
	expiry, exists := h.states[state]
	if exists {
		delete(h.states, state)
	}
	h.mu.Unlock()

	if !exists || time.Now().After(expiry) {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "invalid_state", Message: "OAuth state mismatch or expired"})
		return
	}

	accessToken, err := exchangeDiscordCode(h.discord, code)
	if err != nil {
		c.JSON(http.StatusBadRequest, middleware.ErrorResponse{Error: "exchange_failed", Message: err.Error()})
		return
	}

	discordUser, err := fetchDiscordUser(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "provider_error", Message: err.Error()})
		return
	}

	ctx := c.Ctx()

	var existingLink OAuthLink
	err = h.db.NewSelect().Model(&existingLink).
		Where("provider = ? AND provider_id = ?", "discord", discordUser.ID).
		Scan(ctx)
	if err == nil {
		sessionToken, expiresIn, err := h.sessions.Create(existingLink.AccountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
			return
		}
		c.JSON(http.StatusOK, TokenResponse{
			AccessToken: sessionToken,
			ExpiresIn:   expiresIn,
			AccountID:   existingLink.AccountID.String(),
		})
		return
	}

	var account Account
	err = h.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		now := time.Now().UTC()
		account = Account{ID: uuid.New(), CreatedAt: now, UpdatedAt: now}
		if _, err := tx.NewInsert().Model(&account).Exec(ctx); err != nil {
			return err
		}
		link := OAuthLink{
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
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "creation_failed"})
		return
	}

	sessionToken, expiresIn, err := h.sessions.Create(account.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, middleware.ErrorResponse{Error: "session_error"})
		return
	}
	c.JSON(http.StatusCreated, TokenResponse{
		AccessToken: sessionToken,
		ExpiresIn:   expiresIn,
		AccountID:   account.ID.String(),
	})
}

type discordUserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// exchangeDiscordCode posts to Discord's token endpoint with the
// authorization code and returns the access token. Replaces the
// golang.org/x/oauth2 package's Exchange, which internally uses
// net/http and does not work inside a WASM plugin — we route through
// pulp.HTTP.Fetch instead.
func exchangeDiscordCode(cfg DiscordOAuthConfig, code string) (string, error) {
	form := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURL},
	}
	resp, err := pulp.HTTP.Fetch(pulp.HTTPFetchRequest{
		Method:  "POST",
		URL:     discordTokenURL,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    []byte(form.Encode()),
	})
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	if resp.Status != 200 {
		return "", fmt.Errorf("discord token status %d: %s", resp.Status, resp.Body)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return parsed.AccessToken, nil
}

func fetchDiscordUser(accessToken string) (*discordUserInfo, error) {
	resp, err := pulp.HTTP.Fetch(pulp.HTTPFetchRequest{
		Method: "GET",
		URL:    discordUserInfoURL,
		Headers: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("discord user status %d: %s", resp.Status, resp.Body)
	}
	var u discordUserInfo
	if err := json.Unmarshal(resp.Body, &u); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &u, nil
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
