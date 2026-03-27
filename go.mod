module github.com/LCGant/role-notification

go 1.26.0

toolchain go1.26.1

require (
	github.com/LCGant/role-config v0.0.0
	github.com/LCGant/role-crypto v0.0.0
	github.com/LCGant/role-errors v0.0.0
	github.com/LCGant/role-httpx v0.0.0
	github.com/LCGant/role-internaltoken v0.0.0
	github.com/LCGant/role-ratelimit v0.0.0
	github.com/jackc/pgx/v5 v5.8.0
	golang.org/x/crypto v0.47.0
)

replace github.com/LCGant/role-config => ../../libs/config

replace github.com/LCGant/role-crypto => ../../libs/crypto

replace github.com/LCGant/role-errors => ../../libs/errors

replace github.com/LCGant/role-httpx => ../../libs/httpx

replace github.com/LCGant/role-internaltoken => ../../libs/internaltoken

replace github.com/LCGant/role-ratelimit => ../../libs/ratelimit

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/redis/go-redis/v9 v9.17.2 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.33.0 // indirect
)
