package config

import (
	"flag"
	"log"
	"time"

	pconfig "github.com/bananalabs-oss/potassium/config"
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

	host := flag.String("host", pconfig.EnvOrDefault("HOST", "0.0.0.0"), "Server host")
	port := flag.String("port", pconfig.EnvOrDefault("PORT", "8001"), "Server port")
	databaseURL := flag.String("database-url", pconfig.EnvOrDefault("DATABASE_URL", "sqlite://bananauth.db"), "Database connection string")
	jwtSecret := flag.String("jwt-secret", pconfig.EnvOrDefault("JWT_SECRET", ""), "JWT signing secret (required)")
	tokenExpiry := flag.Int("token-expiry", pconfig.EnvOrDefaultInt("TOKEN_EXPIRY", 1440), "Token expiry in minutes (default 24h)")

	discordClientID := flag.String("oauth-discord-client-id", pconfig.EnvOrDefault("OAUTH_DISCORD_CLIENT_ID", ""), "Discord OAuth client ID")
	discordClientSecret := flag.String("oauth-discord-client-secret", pconfig.EnvOrDefault("OAUTH_DISCORD_CLIENT_SECRET", ""), "Discord OAuth client secret")
	discordRedirectURL := flag.String("oauth-discord-redirect-url", pconfig.EnvOrDefault("OAUTH_DISCORD_REDIRECT_URL", ""), "Discord OAuth redirect URL")

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

func maskDSN(dsn string) string {
	if len(dsn) > 20 {
		return dsn[:20] + "..."
	}
	return dsn
}
