// Bananauth — Pulp cell port.
//
// Identity + authentication service: native (email/password + JWT +
// session revocation) and OAuth (Discord). In composed mode, OAuth provider
// protocol and credentials belong to Pulp's host capability; password hashing uses
// golang.org/x/crypto/bcrypt (pure Go — works under wasip1). Email
// delivery (password reset OTP) goes through Resend's REST API when
// configured. In composed mode delivery is a durable host-owned notification
// effect; this direct path exists solely for the legacy compatibility cell.
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
	"github.com/BananaLabs-OSS/Fiber/pulp/cellconfig"
	_ "github.com/BananaLabs-OSS/Fiber/pulp/entropy/cryptorand" // wires entropy.read into crypto/rand.Reader
	pulpgin "github.com/BananaLabs-OSS/Fiber/pulp/gin"
	_ "github.com/BananaLabs-OSS/Fiber/pulp/sql"
	"github.com/BananaLabs-OSS/Fiber/pulp/workflow"
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
	if cfg.ComposedSessions {
		sm = NewComposedSessionManager(cfg.JWTSecret, cfg.TokenExpiry, workflow.NewClient("bananauth-lua"))
	}

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
	var identityDispatch sessionDispatcher
	if cfg.ComposedIdentity {
		identityDispatch = workflow.NewClient("bananauth-lua")
		if err := importLegacyIdentity(context.Background(), db, identityDispatch); err != nil {
			return fmt.Errorf("initialize composed identity: %w", err)
		}
		authH = NewComposedAuthHandler(sm, identityDispatch)
		profileH = NewComposedProfileHandler(identityDispatch)
	}

	var oauthH *OAuthHandler
	if oauthConfigured(cfg) {
		discord := DiscordOAuthConfig{
			ClientID:     cfg.DiscordClientID,
			ClientSecret: cfg.DiscordClientSecret,
			RedirectURL:  cfg.DiscordRedirectURL,
		}
		if cfg.ComposedIdentity {
			oauthH = NewComposedOAuthHandler(sm, cfg.DiscordRedirectURL, identityDispatch)
		} else {
			oauthH = NewOAuthHandler(db, sm, discord)
		}
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
	if cfg.ComposedIdentity {
		// Passwordless verification belongs to auth-identity. Do not expose
		// these routes from the legacy HTTP owner, which has no matching
		// durable verification state.
		auth.POST("/email-verification", authH.IssueEmailVerification)
		auth.POST("/email-verification/consume", authH.ConsumeEmailVerification)
	}
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
	protected.POST("/password/attach", authH.AttachNativeCredential)
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

// oauthConfigured deliberately has separate composed and legacy paths.
// Composed OAuth gets credentials exclusively from identity.oauth.provider;
// the compatibility path still uses its legacy per-cell configuration.
func oauthConfigured(cfg config) bool {
	if cfg.ComposedIdentity {
		return cfg.DiscordRedirectURL != ""
	}
	return cfg.DiscordClientID != "" && cfg.DiscordClientSecret != "" && cfg.DiscordRedirectURL != ""
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
	JWTSecret        string
	TokenExpiry      time.Duration
	ComposedSessions bool
	ComposedIdentity bool

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
	if oauthConfigured(cfg) {
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
		if m == "discord" && !oauthConfigured(cfg) {
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
	var tmp struct {
		JWTSecret           string   `json:"jwt_secret"`
		TokenExpiryMinutes  int64    `json:"token_expiry_minutes"`
		ComposedSessions    bool     `json:"composed_sessions"`
		ComposedIdentity    bool     `json:"composed_identity"`
		DiscordClientID     string   `json:"discord_client_id"`
		DiscordClientSecret string   `json:"discord_client_secret"`
		DiscordRedirectURL  string   `json:"discord_redirect_url"`
		ResendAPIKey        string   `json:"resend_api_key"`
		ResendFrom          string   `json:"resend_from"`
		AuthMethods         []string `json:"auth_methods"`
	}
	if err := cellconfig.Decode(data, &tmp); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if !tmp.ComposedSessions && (tmp.JWTSecret == "" || tmp.JWTSecret == "dev-jwt-secret-change-me") {
		return cfg, fmt.Errorf("jwt_secret missing or still set to the default placeholder — set a real secret before deploying")
	}
	expiry := time.Duration(tmp.TokenExpiryMinutes) * time.Minute
	if expiry == 0 {
		expiry = 24 * time.Hour
	}
	cfg = config{
		JWTSecret:           tmp.JWTSecret,
		TokenExpiry:         expiry,
		ComposedSessions:    tmp.ComposedSessions,
		ComposedIdentity:    tmp.ComposedIdentity,
		DiscordClientID:     tmp.DiscordClientID,
		DiscordClientSecret: tmp.DiscordClientSecret,
		DiscordRedirectURL:  tmp.DiscordRedirectURL,
		ResendAPIKey:        tmp.ResendAPIKey,
		ResendFrom:          tmp.ResendFrom,
	}
	if cfg.ComposedSessions && cfg.JWTSecret != "" {
		return cfg, fmt.Errorf("composed_sessions uses host identity.jwt.hs256; jwt_secret must not be configured in the cell")
	}
	// Resolve after the rest of cfg is built — discord eligibility depends
	// on the OAuth fields above.
	cfg.AuthMethods = resolveAuthMethods(tmp.AuthMethods, cfg)
	return cfg, nil
}
