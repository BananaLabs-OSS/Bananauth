// migrate-store converts a private offline SQLite or PostgreSQL identity copy to the native
// encrypted-message format. It never starts HTTP or a delivery worker.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/bananalabs-oss/bananauth/internal/migration"
	_ "modernc.org/sqlite"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("migrate-store", flag.ContinueOnError)
	input := flags.String("source", "", "private offline source SQLite copy")
	output := flags.String("target", "", "new native SQLite output")
	postgres := flags.Bool("postgres", false, "read local PostgreSQL URLs from BANANAUTH_MIGRATION_SOURCE and BANANAUTH_MIGRATION_TARGET")
	archiveKeyFile := flags.String("archive-key-file", "", "private key file for PostgreSQL historical notification reconciliation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *postgres {
		if *input != "" || *output != "" {
			return errors.New("PostgreSQL mode reads database URLs from the environment")
		}
		return runPostgres(out, *archiveKeyFile)
	}
	if *archiveKeyFile != "" {
		return errors.New("archive key requires PostgreSQL mode")
	}
	if *input == "" || *output == "" {
		return errors.New("source and target required")
	}
	src, err := filepath.Abs(*input)
	if err != nil {
		return err
	}
	dst, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if src == dst {
		return errors.New("source and target must differ")
	}
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		return errors.New("target must not exist")
	}
	stage, err := os.MkdirTemp(filepath.Dir(dst), ".bananauth-migrate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	privateTarget := filepath.Join(stage, "identity.db")
	file, err := os.OpenFile(privateTarget, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	location := (&url.URL{Scheme: "file", Path: src, RawQuery: "mode=ro"}).String()
	source, err := sql.Open("sqlite", location)
	if err != nil {
		return err
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	target, err := sql.Open("sqlite", privateTarget)
	if err != nil {
		return err
	}
	defer target.Close()
	target.SetMaxOpenConns(1)
	report, err := migration.Identity(context.Background(), source, target)
	if err != nil {
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	syncFile, err := os.Open(privateTarget)
	if err != nil {
		return err
	}
	err = syncFile.Sync()
	syncFile.Close()
	if err != nil {
		return err
	}
	if err := os.Link(privateTarget, dst); err != nil {
		return errors.New("target publication failed without overwrite")
	}
	directory, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
