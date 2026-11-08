package nodeidentity

import (
	"context"
	"errors"
	"strings"
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

type failingSigner struct{ err error }

func (signer failingSigner) SignNodeCertificate(context.Context, SignRequest) (SignedCertificate, error) {
	return SignedCertificate{}, signer.err
}

// 签发失败对外仍是 ErrSigningFailed（RPC 映射不变），错误文本带上签发器给的具体原因；
// 签发器返回的 context 错误不进错误链，避免 RPC 码从 Unavailable 变成 Canceled。
func TestSignKeepsSigningFailedAndCarriesSignerReason(t *testing.T) {
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	reason := errors.New("invalid node certificate signing request: chain certificate \"issuing\" does not cover the requested validity")
	service := &Service{signer: failingSigner{err: reason}, config: DefaultConfig()}
	_, err := service.sign(context.Background(), uuid.New(), []byte{1}, "renewal", now)
	if !errors.Is(err, ErrSigningFailed) || !strings.Contains(err.Error(), "does not cover the requested validity") {
		t.Fatalf("sign() error = %v, want ErrSigningFailed carrying the signer reason", err)
	}
	service.signer = failingSigner{err: context.Canceled}
	if _, err := service.sign(context.Background(), uuid.New(), []byte{1}, "renewal", now); !errors.Is(err, ErrSigningFailed) || errors.Is(err, context.Canceled) {
		t.Fatalf("sign() canceled error = %v, want ErrSigningFailed only", err)
	}
}
