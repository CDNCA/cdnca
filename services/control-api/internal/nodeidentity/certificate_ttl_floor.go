//go:build !cdnca_e2e_short_cert_ttl

package nodeidentity

import "time"

// minimumCertificateTTL is the shortest node certificate lifetime validConfig
// accepts. Production builds keep one hour and ignore any override; only the
// expiry e2e test build (tag cdnca_e2e_short_cert_ttl,
// certificate_ttl_floor_e2e.go) lowers it.
const minimumCertificateTTL = time.Hour

func withTestCertificateTTL(config Config) Config { return config }
