//go:build cdnca_e2e_short_cert_ttl

package nodeidentity

import (
	"testing"
	"time"
)

// The expiry e2e build signs two-minute certificates that really expire.
func TestValidConfigAcceptsMinuteCertificateTTLInExpiryE2EBuild(t *testing.T) {
	config := DefaultConfig()
	config.CertificateTTL, config.RenewBefore = 2*time.Minute, time.Minute
	if !validConfig(config) {
		t.Fatal("validConfig rejected a 2m CertificateTTL in the cdnca_e2e_short_cert_ttl build")
	}
	config.CertificateTTL = time.Minute - time.Second
	if validConfig(config) {
		t.Fatal("validConfig accepted a TTL below one minute")
	}
}

func TestDefaultConfigTakesTestCertificateTTLFromEnvInExpiryE2EBuild(t *testing.T) {
	t.Setenv(TestCertificateTTLEnv, "2m")
	config := DefaultConfig()
	if config.CertificateTTL != 2*time.Minute || config.RenewBefore != time.Minute || !validConfig(config) {
		t.Fatalf("CertificateTTL=%s RenewBefore=%s valid=%v", config.CertificateTTL, config.RenewBefore, validConfig(config))
	}
}
