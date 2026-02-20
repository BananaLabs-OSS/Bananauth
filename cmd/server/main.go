package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/bananalabs-oss/bananauth/internal/config"
	"github.com/bananalabs-oss/bananauth/internal/handlers"
	"github.com/bananalabs-oss/bananauth/internal/middleware"
	"github.com/bananalabs-oss/bananauth/internal/models"
	"github.com/bananalabs-oss/bananauth/internal/sessions"
	"github.com/bananalabs-oss/potassium/database"
	"github.com/bananalabs-oss/potassium/server"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func main() {
	log.Printf("Starting Bananauth")

	cfg := config.Load()

	ctx := context.Background()

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := database.Migrate(ctx, db, []interface{}{
		(*models.Account)(nil),
		(*models.NativeAccount)(nil),
		(*models.OAuthLink)(nil),
		(*models.OTPCode)(nil),
		(*models.Profile)(nil),
	}, []database.Index{
		{Name: "idx_auth_native_email", Query: "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_native_email ON auth_native (email)"},
		{Name: "idx_auth_native_username", Query: "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_native_username ON auth_native (username)"},
		{Name: "idx_auth_native_account", Query: "CREATE INDEX IF NOT EXISTS idx_auth_native_account ON auth_native (account_id)"},
		{Name: "idx_auth_oauth_account", Query: "CREATE INDEX IF NOT EXISTS idx_auth_oauth_account ON auth_oauth (account_id)"},
		{Name: "idx_auth_oauth_provider", Query: "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_oauth_provider ON auth_oauth (provider, provider_id)"},
		{Name: "idx_auth_otp_code", Query: "CREATE INDEX IF NOT EXISTS idx_auth_otp_code ON auth_otp_codes (code, type)"},
		{Name: "idx_auth_otp_email", Query: "CREATE INDEX IF NOT EXISTS idx_auth_otp_email ON auth_otp_codes (email)"},
	}); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	sm := sessions.NewManager(cfg.JWTSecret, cfg.TokenExpiry)

	authHandler := handlers.NewAuthHandler(db, sm, nil)

	profileHandler := handlers.NewProfileHandler(db)

	// OAuth setup (only if configured)
	var oauthHandler *handlers.OAuthHandler
	if cfg.DiscordEnabled() {
		discordConfig := &oauth2.Config{
			ClientID:     cfg.OAuthDiscordClientID,
			ClientSecret: cfg.OAuthDiscordClientSecret,
			RedirectURL:  cfg.OAuthDiscordRedirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://discord.com/api/oauth2/authorize",
				TokenURL: "https://discord.com/api/oauth2/token",
			},
		}
		oauthHandler = handlers.NewOAuthHandler(db, sm, discordConfig)
	}

	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "bananauth",
			"status":  "healthy",
		})
	})

	// Public routes - no auth required
	auth := router.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/password/forgot", authHandler.ForgotPassword)
		auth.POST("/password/reset", authHandler.ResetPassword)

		if oauthHandler != nil {
			auth.GET("/oauth/discord", oauthHandler.DiscordAuthorize)
			auth.GET("/oauth/discord/callback", oauthHandler.DiscordCallback)
		}
	}

	profiles := router.Group("/profiles")
	{
		profiles.GET("/:id", profileHandler.Get)
	}

	// Protected routes - token required
	protected := router.Group("/auth")
	protected.Use(middleware.Auth(sm))
	{
		protected.GET("/session", authHandler.Session)
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/password", authHandler.ChangePassword)
		protected.DELETE("/account", authHandler.DeleteAccount)
	}

	protectedProfiles := router.Group("/profiles")
	protectedProfiles.Use(middleware.Auth(sm))
	{
		protectedProfiles.POST("", profileHandler.Create)
		protectedProfiles.PUT("", profileHandler.Update)
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	server.ListenAndShutdown(addr, router, "Bananauth")
}
