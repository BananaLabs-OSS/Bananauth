//go:build wasip1

package main

import (
	"database/sql"

	"github.com/BananaLabs-OSS/Fiber/pulp"
	_ "github.com/BananaLabs-OSS/Fiber/pulp/sql"
)

func init() {
	pulp.OnInit(func([]byte) error {
		db, err := sql.Open("pulp", "")
		if err != nil {
			return err
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		store, err := newSQLiteStore(db)
		if err != nil {
			return err
		}
		for name, provider := range newOwner(store).providers() {
			pulp.Provide(name, pulp.Provider(provider))
		}
		return nil
	})
}

func main() {}
