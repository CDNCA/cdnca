//go:build cdnca_e2e_short_cert_ttl

package nodeidentity

import (
	"os"
	"time"
)

// Test build only (tests/cert-recovery-e2e, ADR 0013 GW-02): node certificates
// of a few minutes really expire under the gateway's wall-clock TLS.
const minimumCertificateTTL = time.Minute

// TestCertificateTTLEnv names the lifetime DefaultConfig issues in this build
// (e.g. "2m"); certificates renew at half life. Unset: the production default.
const TestCertificateTTLEnv = "CDNCA_E2E_NODE_CERTIFICATE_TTL"

func withTestCertificateTTL(config Config) Config {
	ttl, err := time.ParseDuration(os.Getenv(TestCertificateTTLEnv))
	if err != nil || ttl < 2*minimumCertificateTTL || ttl > MaxCertificateTTL {
		return config
	}
	config.CertificateTTL, config.RenewBefore = ttl, ttl/2
	return config
}
