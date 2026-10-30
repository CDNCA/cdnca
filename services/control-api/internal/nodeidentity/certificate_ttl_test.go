package nodeidentity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type capturingSigner struct{ request SignRequest }

func (signer *capturingSigner) SignNodeCertificate(_ context.Context, request SignRequest) (SignedCertificate, error) {
	signer.request = request
	return SignedCertificate{}, nil
}

// ADR 0013 §6.1 a / GW-01: node certificates live 30 days and renew at the half-way point.
func TestDefaultConfigIssuesThirtyDayCertificatesRenewingAtHalfLife(t *testing.T) {
	config := DefaultConfig()
	if config.CertificateTTL != 30*24*time.Hour || config.RenewBefore != 15*24*time.Hour {
		t.Fatalf("CertificateTTL=%s RenewBefore=%s, want 720h/360h", config.CertificateTTL, config.RenewBefore)
	}
	if config.RecoveryWindow != 180*24*time.Hour {
		t.Fatalf("RecoveryWindow=%s, want 4320h", config.RecoveryWindow)
	}
	if !validConfig(config) {
		t.Fatal("DefaultConfig() is rejected by validConfig")
	}
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	signer := &capturingSigner{}
	service := &Service{signer: signer, config: config}
	if _, err := service.sign(context.Background(), uuid.New(), []byte{1}, "renewal", now); err != nil {
		t.Fatal(err)
	}
	if got := signer.request.NotAfter.Sub(now); got != 30*24*time.Hour {
		t.Fatalf("signed NotAfter-now = %s, want 720h", got)
	}
}

func TestValidConfigCertificateTTLUpperBoundIsThirtyOneDays(t *testing.T) {
	for _, testCase := range []struct {
		ttl  time.Duration
		want bool
	}{
		{ttl: 8 * 24 * time.Hour, want: true},
		{ttl: 31 * 24 * time.Hour, want: true},
		{ttl: 31*24*time.Hour + time.Second, want: false},
	} {
		config := DefaultConfig()
		config.CertificateTTL = testCase.ttl
		config.RenewBefore = testCase.ttl / 2
		if got := validConfig(config); got != testCase.want {
			t.Fatalf("validConfig(CertificateTTL=%s) = %v, want %v", testCase.ttl, got, testCase.want)
		}
	}
	config := DefaultConfig()
	config.RecoveryWindow = 0
	if validConfig(config) {
		t.Fatal("validConfig accepted a zero RecoveryWindow")
	}
}
