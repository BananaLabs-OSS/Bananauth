package config

import (
	"flag"
	"log"
	"os"
)

type Config struct {
	Host string
	Port string
}

func Load() *Config {
	cfg := &Config{}

	host := flag.String("host", envOrDefault("HOST", "0.0.0.0"), "Server host")
	port := flag.String("port", envOrDefault("PORT", "8001"), "Server port")

	flag.Parse()

	cfg.Host = *host
	cfg.Port = *port

	log.Printf("Bananauth Configuration:")
	log.Printf("  Host: %s", cfg.Host)
	log.Printf("  Port: %s", cfg.Port)

	return cfg
}

func envOrDefault(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}
