package main

import (
	_ "github.com/BananaLabs-OSS/Pulp-ext-entropy" // entropy.read — crypto/rand for tokens/OTP (required when bananauth runs in its own host)
	_ "github.com/BananaLabs-OSS/Pulp-ext-http"
	_ "github.com/BananaLabs-OSS/Pulp-ext-jwt" // identity.jwt.hs256 â€” host-owned signing key
	_ "github.com/BananaLabs-OSS/Pulp-ext-oauth" // identity.oauth.provider — host-owned OAuth client credentials
	_ "github.com/BananaLabs-OSS/Pulp-ext-sqlite"
	_ "github.com/BananaLabs-OSS/Pulp-ext-workers"

	"github.com/BananaLabs-OSS/Pulp/run"
)

func main() { run.Main() }
