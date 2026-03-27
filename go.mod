module github.com/LCGant/role-notification

go 1.26.0

toolchain go1.26.1

require (
	github.com/LCGant/role-config v0.0.0
	github.com/LCGant/role-crypto v0.0.0
	github.com/LCGant/role-errors v0.0.0
	github.com/LCGant/role-httpx v0.0.0
	github.com/LCGant/role-internaltoken v0.0.0
	github.com/jackc/pgx/v5 v5.8.0
)

replace github.com/LCGant/role-config => ../../libs/config

replace github.com/LCGant/role-crypto => ../../libs/crypto

replace github.com/LCGant/role-errors => ../../libs/errors

replace github.com/LCGant/role-httpx => ../../libs/httpx

replace github.com/LCGant/role-internaltoken => ../../libs/internaltoken

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
