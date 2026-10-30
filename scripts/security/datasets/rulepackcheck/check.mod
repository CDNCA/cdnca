module cdnca/rulepackcheck

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/libs/edgeconfig v0.0.0
	github.com/cdnca/cdnca/libs/rulepack v0.0.0
)

require (
	github.com/cdnca/cdnca/libs/entitlement v0.0.0 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace github.com/cdnca/cdnca/libs/edgeconfig => ../../../../libs/edgeconfig

replace github.com/cdnca/cdnca/libs/rulepack => ../../../../libs/rulepack

replace github.com/cdnca/cdnca/libs/entitlement => ../../../../libs/entitlement
