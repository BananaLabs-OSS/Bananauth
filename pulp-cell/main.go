// Bananauth — Pulp cell port.
//
// Identity + authentication service: native (email/password + JWT +
// session revocation) and OAuth (Discord). All outbound HTTP to
// OAuth providers goes through pulp.HTTP.Fetch; password hashing uses
// golang.org/x/crypto/bcrypt (pure Go — works under wasip1). Email
// delivery (password reset OTP) goes through Resend's REST API when
// configured, otherwise the OTP is printed to cell stdout for dev.
//
// Build:
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o bananauth.wasm .
package main

import (
	"context"
	dsql "database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/BananaLabs-OSS/Fiber/pulp"
	_ "github.com/BananaLabs-OSS/Fiber/pulp/entropy/cryptorand" // wires entropy.read into crypto/rand.Reader
	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	_ "github.com/BananaLabs-OSS/Fiber/pulp/sql"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

func main() {}

var db *bun.DB

func init() {
	pulp.OnInit(bootstrap)
}

func bootstrap(configBytes []byte) error {
	cfg, err := parseConfig(configBytes)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	raw, err := dsql.Open("pulp", "")
	if err != nil {
		return fmt.Errorf("open pulp sql driver: %w", err)
	}
	// Match host single-writer pool; prevents nested-BEGIN races.
	raw.SetMaxOpenConns(1)
	raw.SetMaxIdleConns(1)
	db = bun.NewDB(raw, sqlitedialect.New())

	if err := migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	sm := NewSessionManager(cfg.JWTSecret, cfg.TokenExpiry)

	// sendEmail wires the password-reset OTP through Resend's REST
	// API via pulp.HTTP.Fetch. When the API key is unset (dev mode)
	// the OTP is printed to cell stdout instead so local testing
	// can still exercise the reset flow.
	sendEmail := func(to, code string) error {
		if cfg.ResendAPIKey == "" {
			// Parity with native Bananauth/internal/handlers/auth.go:306.
			log.Printf("Password reset OTP for %s: %s", to, code)
			return nil
		}
		body, _ := json.Marshal(map[string]any{
			"from":    cfg.ResendFrom,
			"to":      []string{to},
			"subject": "Password reset code",
			"text":    fmt.Sprintf("Your reset code: %s\nExpires in 10 minutes.", code),
		})
		resp, err := pulp.HTTP.Fetch(pulp.HTTPFetchRequest{
			Method: "POST",
			URL:    "https://api.resend.com/emails",
			Headers: map[string]string{
				"Authorization": "Bearer " + cfg.ResendAPIKey,
				"Content-Type":  "application/json",
			},
			Body: body,
		})
		if err != nil {
			return err
		}
		if resp.Status >= 400 {
			return fmt.Errorf("resend status %d: %s", resp.Status, resp.Body)
		}
		return nil
	}

	authH := NewAuthHandler(db, sm, sendEmail)
	profileH := NewProfileHandler(db)

	var oauthH *OAuthHandler
	if cfg.DiscordClientID != "" && cfg.DiscordClientSecret != "" {
		oauthH = NewOAuthHandler(db, sm, DiscordOAuthConfig{
			ClientID:     cfg.DiscordClientID,
			ClientSecret: cfg.DiscordClientSecret,
			RedirectURL:  cfg.DiscordRedirectURL,
		})
	}

	r := pulpgin.New()

	r.GET("/health", func(c *pulpgin.Context) {
		c.JSON(http.StatusOK, pulpgin.H{"service": "bananauth", "status": "healthy"})
	})

	// Public (no auth)
	auth := r.Group("/auth")
	// Config seam: advertise the enabled login methods so a frontend renders
	// only what this deployment exposes. Driven by the `auth_methods` manifest
	// key (resolved/filtered in parseConfig).
	auth.GET("/config", func(c *pulpgin.Context) {
		c.JSON(http.StatusOK, pulpgin.H{"methods": cfg.AuthMethods})
	})
	auth.POST("/register", authH.Register)
	auth.POST("/login", authH.Login)
	auth.POST("/password/forgot", authH.ForgotPassword)
	auth.POST("/password/reset", authH.ResetPassword)
	if oauthH != nil {
		auth.GET("/oauth/discord", oauthH.DiscordAuthorize)
		auth.GET("/oauth/discord/callback", oauthH.DiscordCallback)
	}

	profiles := r.Group("/profiles")
	profiles.GET("/:id", profileH.Get)

	// Protected (Bananauth's own session-revocation-aware middleware)
	protected := r.Group("/auth")
	protected.Use(sessionAuth(sm))
	protected.GET("/session", authH.Session)
	protected.POST("/logout", authH.Logout)
	protected.POST("/password", authH.ChangePassword)
	protected.DELETE("/account", authH.DeleteAccount)

	protectedProfiles := r.Group("/profiles")
	protectedProfiles.Use(sessionAuth(sm))
	protectedProfiles.POST("", profileH.Create)
	protectedProfiles.PUT("", profileH.Update)

	if err := r.Run(); err != nil {
		return fmt.Errorf("router: %w", err)
	}
	return nil
}

func migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS auth_accounts (
			id TEXT PRIMARY KEY,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS auth_native (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			email TEXT NOT NULL,
			username TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS auth_oauth (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			provider_email TEXT,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS auth_otp_codes (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			code TEXT NOT NULL,
			type TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL,
			metadata TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS profiles (
			account_id TEXT PRIMARY KEY,
			display_name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_native_email ON auth_native (email)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_native_username ON auth_native (username)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_native_account ON auth_native (account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_oauth_account ON auth_oauth (account_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_oauth_provider ON auth_oauth (provider, provider_id)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_otp_code ON auth_otp_codes (code, type)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_otp_email ON auth_otp_codes (email)`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate exec: %w", err)
		}
	}
	return nil
}

type config struct {
	JWTSecret   string
	TokenExpiry time.Duration

	DiscordClientID     string
	DiscordClientSecret string
	DiscordRedirectURL  string

	ResendAPIKey string
	ResendFrom   string

	// AuthMethods is the ordered list of login methods this deployment
	// exposes — the config seam. The public GET /auth/config advertises it
	// so a frontend renders only the enabled methods. Apps flip methods on
	// here without any frontend code change. Known values: "password",
	// "discord" (built); "passwordless", "totp", "passkey" (future).
	AuthMethods []string
}

// knownAuthMethods is every method Bananauth recognizes. Unknown values in
// the manifest are dropped so a typo can't silently advertise a method the
// backend can't service.
var knownAuthMethods = map[string]bool{
	"password": true,
	"discord":  true,
}

// defaultAuthMethods derives the method list when the manifest omits
// auth_methods: password is always available; discord only when its OAuth
// app is configured.
func defaultAuthMethods(cfg config) []string {
	methods := []string{"password"}
	if cfg.DiscordClientID != "" && cfg.DiscordClientSecret != "" {
		methods = append(methods, "discord")
	}
	return methods
}

// resolveAuthMethods filters the requested list to methods Bananauth can
// actually service (built + properly configured), preserving order.
func resolveAuthMethods(requested []string, cfg config) []string {
	if len(requested) == 0 {
		return defaultAuthMethods(cfg)
	}
	out := make([]string, 0, len(requested))
	for _, m := range requested {
		if !knownAuthMethods[m] {
			continue
		}
		if m == "discord" && (cfg.DiscordClientID == "" || cfg.DiscordClientSecret == "") {
			continue // advertised but not configured — drop it
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return defaultAuthMethods(cfg)
	}
	return out
}

func parseConfig(data []byte) (config, error) {
	var cfg config
	if len(data) == 0 {
		return cfg, fmt.Errorf("missing [config]")
	}
	var raw map[string]any
	if err := decodeMsgpack(data, &raw); err != nil {
		return cfg, err
	}
	var tmp struct {
		JWTSecret           string   `json:"jwt_secret"`
		TokenExpiryMinutes  int64    `json:"token_expiry_minutes"`
		DiscordClientID     string   `json:"discord_client_id"`
		DiscordClientSecret string   `json:"discord_client_secret"`
		DiscordRedirectURL  string   `json:"discord_redirect_url"`
		ResendAPIKey        string   `json:"resend_api_key"`
		ResendFrom          string   `json:"resend_from"`
		AuthMethods         []string `json:"auth_methods"`
	}
	jbytes, _ := json.Marshal(raw)
	if err := json.Unmarshal(jbytes, &tmp); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if tmp.JWTSecret == "" {
		return cfg, fmt.Errorf("jwt_secret missing from [config]")
	}
	expiry := time.Duration(tmp.TokenExpiryMinutes) * time.Minute
	if expiry == 0 {
		expiry = 24 * time.Hour
	}
	cfg = config{
		JWTSecret:           tmp.JWTSecret,
		TokenExpiry:         expiry,
		DiscordClientID:     tmp.DiscordClientID,
		DiscordClientSecret: tmp.DiscordClientSecret,
		DiscordRedirectURL:  tmp.DiscordRedirectURL,
		ResendAPIKey:        tmp.ResendAPIKey,
		ResendFrom:          tmp.ResendFrom,
	}
	// Resolve after the rest of cfg is built — discord eligibility depends
	// on the OAuth fields above.
	cfg.AuthMethods = resolveAuthMethods(tmp.AuthMethods, cfg)
	return cfg, nil
}
