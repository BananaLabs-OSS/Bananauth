package config

import (
	"flag"
	"log"
	"os"
)

type Config struct {
	Host        string
	Port        string
	DatabaseURL string
}

func Load() *Config {
	cfg := &Config{}

	host := flag.String("host", envOrDefault("HOST", "0.0.0.0"), "Server host")
	port := flag.String("port", envOrDefault("PORT", "8001"), "Server port")
	databaseURL := flag.String("database-url", envOrDefault("DATABASE_URL", "sqlite://bananauth.db"), "Database connection string")

	flag.Parse()

	cfg.Host = *host
	cfg.Port = *port
	cfg.DatabaseURL = *databaseURL

	log.Printf("Bananauth Configuration:")
	log.Printf("  Host:     %s", cfg.Host)
	log.Printf("  Port:     %s", cfg.Port)
	log.Printf("  Database: %s", maskDSN(cfg.DatabaseURL))

	return cfg
}

func envOrDefault(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func maskDSN(dsn string) string {
	if len(dsn) > 20 {
		return dsn[:20] + "..."
	}
	return dsn
}
