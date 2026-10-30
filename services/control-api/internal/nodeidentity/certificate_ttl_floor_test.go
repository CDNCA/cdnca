//go:build !cdnca_e2e_short_cert_ttl

package nodeidentity

import (
	"testing"
	"time"
)

// Production builds keep the one-hour certificate TTL floor; only the
// cdnca_e2e_short_cert_ttl test build accepts minutes (GW-02 expiry e2e).
func TestValidConfigCertificateTTLFloorIsOneHourInProductionBuilds(t *testing.T) {
	for _, testCase := range []struct {
		ttl  time.Duration
		want bool
	}{
		{ttl: 2 * time.Minute, want: false},
		{ttl: time.Hour - time.Second, want: false},
		{ttl: time.Hour, want: true},
	} {
		config := DefaultConfig()
		config.CertificateTTL, config.RenewBefore = testCase.ttl, time.Minute
		if got := validConfig(config); got != testCase.want {
			t.Fatalf("validConfig(CertificateTTL=%s) = %v, want %v", testCase.ttl, got, testCase.want)
		}
	}
}

// The e2e override variable has no effect outside the test build.
func TestDefaultConfigIgnoresTestCertificateTTLEnvInProductionBuilds(t *testing.T) {
	t.Setenv("CDNCA_E2E_NODE_CERTIFICATE_TTL", "2m")
	if config := DefaultConfig(); config.CertificateTTL != DefaultCertificateTTL || config.RenewBefore != DefaultRenewBefore {
		t.Fatalf("CertificateTTL=%s RenewBefore=%s", config.CertificateTTL, config.RenewBefore)
	}
}
