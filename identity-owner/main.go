//go:build wasip1

package main

import (
	"context"
	"fmt"

	"github.com/BananaLabs-OSS/Fiber/pulp"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"github.com/vmihailenco/msgpack/v5"
)

type identityOwnerConfig struct {
	OTPKeyCurrent  string `msgpack:"otp_key_current"`
	OTPKeyPrevious string `msgpack:"otp_key_previous,omitempty"`
}

func init() {
	pulp.OnInit(func(raw []byte) error {
		var config identityOwnerConfig
		if err := msgpack.Unmarshal(raw, &config); err != nil {
			return fmt.Errorf("decode identity owner config: %w", err)
		}
		keys, err := otpsecure.Parse(config.OTPKeyCurrent, config.OTPKeyPrevious)
		if err != nil {
			return fmt.Errorf("identity owner OTP security: %w", err)
		}
		store, err := openSQLite("")
		if err != nil {
			return err
		}
		cell, err := openOwner(context.Background(), store, keys)
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
