module github.com/bananalabs-oss/bananauth/sessions-identity-shadow

go 1.25.6

require (
	github.com/SirNiklas9/pulp-engines/identity-core v0.0.0
	github.com/vmihailenco/msgpack/v5 v5.4.1
)

require (
	github.com/BananaLabs-OSS/Fiber v0.0.0 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
)

replace github.com/SirNiklas9/pulp-engines/identity-core => ../../pulp-engines/identity-core

replace github.com/BananaLabs-OSS/Fiber => ../../Fiber
