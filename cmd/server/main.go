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

	authHandler := handlers.NewAuthHandler(db, sm)

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
	}

	// Protected routes - token required
	protected := router.Group("/auth")
	protected.Use(middleware.Auth(sm))
	{
		protected.GET("/session", authHandler.Session)
		protected.POST("/logout", authHandler.Logout)
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
