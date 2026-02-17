package config

import (
	"flag"
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Host        string
	Port        string
	DatabaseURL string
	JWTSecret   string
	TokenExpiry time.Duration

	OAuthDiscordClientID     string
	OAuthDiscordClientSecret string
	OAuthDiscordRedirectURL  string
}

func Load() *Config {
	cfg := &Config{}

	host := flag.String("host", envOrDefault("HOST", "0.0.0.0"), "Server host")
	port := flag.String("port", envOrDefault("PORT", "8001"), "Server port")
	databaseURL := flag.String("database-url", envOrDefault("DATABASE_URL", "sqlite://bananauth.db"), "Database connection string")
	jwtSecret := flag.String("jwt-secret", envOrDefault("JWT_SECRET", ""), "JWT signing secret (required)")
	tokenExpiry := flag.Int("token-expiry", envOrDefaultInt("TOKEN_EXPIRY", 1440), "Token expiry in minutes (default 24h)")

	discordClientID := flag.String("oauth-discord-client-id", envOrDefault("OAUTH_DISCORD_CLIENT_ID", ""), "Discord OAuth client ID")
	discordClientSecret := flag.String("oauth-discord-client-secret", envOrDefault("OAUTH_DISCORD_CLIENT_SECRET", ""), "Discord OAuth client secret")
	discordRedirectURL := flag.String("oauth-discord-redirect-url", envOrDefault("OAUTH_DISCORD_REDIRECT_URL", ""), "Discord OAuth redirect URL")

	flag.Parse()

	cfg.Host = *host
	cfg.Port = *port
	cfg.DatabaseURL = *databaseURL
	cfg.JWTSecret = *jwtSecret
	cfg.TokenExpiry = time.Duration(*tokenExpiry) * time.Minute
	cfg.OAuthDiscordClientID = *discordClientID
	cfg.OAuthDiscordClientSecret = *discordClientSecret
	cfg.OAuthDiscordRedirectURL = *discordRedirectURL

	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	log.Printf("Bananauth Configuration:")
	log.Printf("  Host:         %s", cfg.Host)
	log.Printf("  Port:         %s", cfg.Port)
	log.Printf("  Database:     %s", maskDSN(cfg.DatabaseURL))
	log.Printf("  Token Expiry: %s", cfg.TokenExpiry)
	log.Printf("  Discord OAuth: %s", enabledStr(cfg.OAuthDiscordClientID))

	return cfg
}

func enabledStr(val string) string {
	if val != "" {
		return "enabled"
	}
	return "disabled"
}

func (c *Config) DiscordEnabled() bool {
	return c.OAuthDiscordClientID != "" && c.OAuthDiscordClientSecret != ""
}

func envOrDefault(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}

func maskDSN(dsn string) string {
	if len(dsn) > 20 {
		return dsn[:20] + "..."
	}
	return dsn
}
