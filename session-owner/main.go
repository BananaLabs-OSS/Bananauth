//go:build wasip1

package main

import "github.com/BananaLabs-OSS/Fiber/pulp"

type guestSQLite struct{}

func (guestSQLite) Exec(query string, args ...any) error {
	_, err := pulp.SQLite.Exec(query, args...)
	return err
}

func (guestSQLite) Query(query string, args ...any) ([][]any, error) {
	result, err := pulp.SQLite.Query(query, args...)
	return result.Rows, err
}

func init() {
	pulp.OnInit(func([]byte) error {
		store, err := newSQLiteStore(guestSQLite{})
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
