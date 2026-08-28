//go:build wasip1

package main

import (
	"context"

	"github.com/BananaLabs-OSS/Fiber/pulp"
)

func init() {
	pulp.OnInit(func([]byte) error {
		store, err := openSQLite("")
		if err != nil {
			return err
		}
		cell, err := openOwner(context.Background(), store)
		if err != nil {
			return err
		}
		for name, provider := range cell.providers() {
			pulp.Provide(name, pulp.Provider(provider))
		}
		return nil
	})
}

func main() {}
