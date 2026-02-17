package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bananalabs-oss/bananauth/internal/config"
	"github.com/bananalabs-oss/bananauth/internal/database"
	"github.com/bananalabs-oss/bananauth/internal/handlers"
	"github.com/bananalabs-oss/bananauth/internal/middleware"
	"github.com/bananalabs-oss/bananauth/internal/sessions"
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

	if err := database.Migrate(ctx, db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	sm := sessions.NewManager(cfg.JWTSecret, cfg.TokenExpiry)

	authHandler := handlers.NewAuthHandler(db, sm, nil)

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

	// Protected routes - token required
	protected := router.Group("/auth")
	protected.Use(middleware.Auth(sm))
	{
		protected.GET("/session", authHandler.Session)
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/password", authHandler.ChangePassword)
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		log.Printf("Bananauth listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Printf("Shutting down Bananauth...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Printf("Bananauth stopped")
}
