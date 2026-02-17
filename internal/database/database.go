package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/bananalabs-oss/bananauth/internal/models"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

func Connect(databaseURL string) (*bun.DB, error) {
	path := strings.TrimPrefix(databaseURL, "sqlite://")

	sqldb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	if _, err := sqldb.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}

	db := bun.NewDB(sqldb, sqlitedialect.New())

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Printf("Connected to SQLite: %s", path)
	return db, nil
}

func Migrate(ctx context.Context, db *bun.DB) error {
	log.Printf("Running database migrations...")

	tables := []interface{}{
		(*models.Account)(nil),
		(*models.NativeAccount)(nil),
		(*models.OAuthLink)(nil),
	}

	for _, model := range tables {
		_, err := db.NewCreateTable().
			Model(model).
			IfNotExists().
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to create table for %T: %w", model, err)
		}
	}

	indexes := []struct {
		name  string
		query string
	}{
		{
			"idx_auth_native_email",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_native_email ON auth_native (email)",
		},
		{
			"idx_auth_native_username",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_native_username ON auth_native (username)",
		},
		{
			"idx_auth_native_account",
			"CREATE INDEX IF NOT EXISTS idx_auth_native_account ON auth_native (account_id)",
		},
		{
			"idx_auth_oauth_account",
			"CREATE INDEX IF NOT EXISTS idx_auth_oauth_account ON auth_oauth (account_id)",
		},
		{
			"idx_auth_oauth_provider",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_oauth_provider ON auth_oauth (provider, provider_id)",
		},
	}

	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx.query); err != nil {
			return fmt.Errorf("failed to create index %s: %w", idx.name, err)
		}
	}

	log.Printf("Migrations complete")
	return nil
}
