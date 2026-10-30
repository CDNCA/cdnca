module github.com/cdnca/cdnca/services/control-api/tests/dns-provider-sandbox-e2e

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/services/control-api v0.0.0
	github.com/google/uuid v1.6.0
)

require (
	github.com/cdnca/cdnca/libs/entitlement v0.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.7.5 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/text v0.26.0 // indirect
)

replace github.com/cdnca/cdnca/services/control-api => ../../services/control-api

replace github.com/cdnca/cdnca/libs/entitlement => ../../libs/entitlement
