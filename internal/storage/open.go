package storage

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/bananalabs-oss/bananauth/internal/sqlitecompat"
	_ "modernc.org/sqlite"
)

// Open accepts the existing PostgreSQL DSN or a local SQLite path.
func Open(location string) (*sql.DB, error) {
	if location == "" {
		return nil, errors.New("database location is required")
	}
	if strings.HasPrefix(location, "postgres://") || strings.HasPrefix(location, "postgresql://") {
		connector, err := sqlitecompat.NewPostgresConnector(location)
		if err != nil {
			return nil, err
		}
		db := sql.OpenDB(connector)
		db.SetMaxOpenConns(4)
		return db, nil
	}
	db, err := sql.Open("sqlite", strings.TrimPrefix(location, "sqlite://"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
