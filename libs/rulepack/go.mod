module github.com/cdnca/cdnca/libs/rulepack

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/libs/edgeconfig v0.0.0
	github.com/cdnca/cdnca/libs/entitlement v0.0.0
	github.com/cloudflare/circl v1.6.1
	golang.org/x/mod v0.25.0
)

require (
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace github.com/cdnca/cdnca/libs/edgeconfig => ../edgeconfig

replace github.com/cdnca/cdnca/libs/entitlement => ../entitlement
