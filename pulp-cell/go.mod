module bananauth-cell

go 1.25

require (
	github.com/BananaLabs-OSS/Fiber v0.0.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/uptrace/bun v1.2.16
	github.com/uptrace/bun/dialect/sqlitedialect v1.2.16
	github.com/vmihailenco/msgpack/v5 v5.4.1
	golang.org/x/crypto v0.48.0
)

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/BananaLabs-OSS/Fiber => ../../Fiber
