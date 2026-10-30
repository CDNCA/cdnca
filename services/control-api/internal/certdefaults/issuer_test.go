package certdefaults

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// CERT-04：用户默认签发机构；上传类型不带签发机构，未知签发机构拒绝，签发机构进摘要。
func TestServiceUpdateIssuer(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	fake := &serviceStoreFake{}
	service := &Service{store: fake}
	zerossl, letsEncrypt, unknown := "zerossl", "lets_encrypt", "buypass"
	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeACME, Issuer: &zerossl, IdempotencyKey: "k1", RequestID: "r1",
	}); err != nil || fake.updateRequest.Issuer == nil || *fake.updateRequest.Issuer != zerossl {
		t.Fatalf("issuer = %v, err=%v", fake.updateRequest.Issuer, err)
	}
	first := fake.updateDigest
	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeACME, Issuer: &letsEncrypt, IdempotencyKey: "k1", RequestID: "r1",
	}); err != nil || fake.updateDigest == first {
		t.Fatalf("issuer is not part of the digest, err=%v", err)
	}
	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeUploaded, Issuer: &zerossl, IdempotencyKey: "k2", RequestID: "r2",
	}); err != nil || fake.updateRequest.Issuer != nil {
		t.Fatalf("uploaded default kept issuer %v, err=%v", fake.updateRequest.Issuer, err)
	}
	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeACME, Issuer: &unknown, IdempotencyKey: "k3", RequestID: "r3",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown issuer error = %v", err)
	}
}

// fp-cert2 补充：保存默认签发机构时就检查是否可用（与建单同一规则 acmecacredentials.Configured），
// 未配置 EAB 的 CA 返回 ErrIssuerUnavailable（HTTP 409 certificate_issuer_unavailable），不写库；
// 未选签发机构（平台默认）与上传类型不检查。
func TestServiceUpdateRefusesUnavailableIssuer(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	fake := &serviceStoreFake{unconfigured: map[string]bool{"zerossl": true}}
	service := &Service{store: fake}
	zerossl, letsEncrypt := "zerossl", "lets_encrypt"
	_, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeACME, Issuer: &zerossl, IdempotencyKey: "k1", RequestID: "r1",
	})
	if !errors.Is(err, ErrIssuerUnavailable) || fake.updateRequest.IdempotencyKey != "" {
		t.Fatalf("unconfigured zerossl: err=%v, stored=%+v", err, fake.updateRequest)
	}
	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeACME, Issuer: &letsEncrypt, IdempotencyKey: "k2", RequestID: "r2",
	}); err != nil || fake.updateRequest.IdempotencyKey != "k2" {
		t.Fatalf("lets_encrypt: err=%v", err)
	}
	fake.issuerChecks = nil
	for _, request := range []UpdateRequest{
		{CertificateType: CertificateTypeACME, IdempotencyKey: "k3", RequestID: "r3"},
		{CertificateType: CertificateTypeUploaded, Issuer: &zerossl, IdempotencyKey: "k4", RequestID: "r4"},
	} {
		if _, err := service.Update(context.Background(), actor, request); err != nil {
			t.Fatalf("%s without issuer check: %v", request.CertificateType, err)
		}
	}
	if len(fake.issuerChecks) != 0 {
		t.Fatalf("checked issuers %v for the platform default / uploaded", fake.issuerChecks)
	}
	// a lookup failure is not mistaken for "unavailable"
	fake.issuerErr = errors.New("db down")
	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeACME, Issuer: &letsEncrypt, IdempotencyKey: "k5", RequestID: "r5",
	}); err == nil || errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("lookup failure: %v", err)
	}
}
