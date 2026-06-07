package main

import (
	_ "github.com/BananaLabs-OSS/Pulp-ext-entropy" // entropy.read — crypto/rand for tokens/OTP (required when bananauth runs in its own host)
	_ "github.com/BananaLabs-OSS/Pulp-ext-http"
	_ "github.com/BananaLabs-OSS/Pulp-ext-sqlite"

	"github.com/BananaLabs-OSS/Pulp/run"
)

func main() { run.Main() }
