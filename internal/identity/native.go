package identity

import (
	"context"
	"github.com/bananalabs-oss/bananauth/internal/storage"
	"io"

	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
)

// Open loads the existing durable identity store and exposes its commands.
func Open(ctx context.Context, path string, keys otpsecure.Keyring) (map[string]func([]byte) ([]byte, error), io.Closer, error) {
	db, err := storage.Open(path)
	if err != nil {
		return nil, nil, err
	}
	owner, err := openOwner(ctx, &sqliteEventStore{db: db}, keys)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return owner.providers(), db, nil
}
