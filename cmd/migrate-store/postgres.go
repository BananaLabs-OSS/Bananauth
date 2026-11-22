package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/bananalabs-oss/bananauth/internal/migration"
	"github.com/bananalabs-oss/bananauth/internal/storage"
)

func runPostgres(out io.Writer, archiveKeyFile string) error {
	sourceURL, sourceSocket, err := offlinePostgresURL(os.Getenv("BANANAUTH_MIGRATION_SOURCE"))
	if err != nil {
		return err
	}
	targetURL, targetSocket, err := offlinePostgresURL(os.Getenv("BANANAUTH_MIGRATION_TARGET"))
	if err != nil {
		return err
	}
	if sourceSocket != targetSocket || sourceURL.Query().Get("port") != targetURL.Query().Get("port") || sourceURL.Path == targetURL.Path {
		return errors.New("source and target must be distinct databases on the same local PostgreSQL socket and port")
	}

	source, err := storage.Open(sourceURL.String())
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := storage.Open(targetURL.String())
	if err != nil {
		return err
	}
	defer target.Close()

	ctx := context.Background()
	var report migration.Report
	if archiveKeyFile == "" {
		report, err = migration.IdentityPostgres(ctx, source, target)
	} else {
		key, keyErr := readArchiveKey(archiveKeyFile)
		if keyErr != nil {
			return keyErr
		}
		report, err = migration.IdentityPostgresWithArchive(ctx, source, target, key)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

// offlinePostgresURL only admits Unix sockets. Database-local migrations must
// never connect to a production endpoint or accept query overrides for dbname.
func offlinePostgresURL(raw string) (*url.URL, string, error) {
	invalid := errors.New("expected a PostgreSQL database URL with an absolute local Unix socket host")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host != "" || u.Fragment != "" ||
		!strings.HasPrefix(u.Path, "/") || u.Path == "/" || strings.Contains(u.Path[1:], "/") {
		return nil, "", invalid
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || !filepath.IsAbs(q.Get("host")) {
		return nil, "", invalid
	}
	for key, values := range q {
		if len(values) != 1 || (key != "host" && key != "port" && key != "sslmode" && key != "user") {
			return nil, "", invalid
		}
	}
	socket, err := filepath.EvalSymlinks(q.Get("host"))
	if err != nil {
		return nil, "", invalid
	}
	if q.Get("port") == "" {
		q.Set("port", "5432")
	}
	q.Set("host", socket)
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	return u, socket, nil
}

func readArchiveKey(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1024 {
		return "", errors.New("archive key must be a private regular file of at most 1024 bytes")
	}
	key, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil {
		return "", err
	}
	if len(key) > 1024 {
		return "", errors.New("archive key exceeds 1024 bytes")
	}
	return strings.TrimSpace(string(key)), nil
}
