package certdefaults

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

// fix-fielderr-be4: a refused certificate default names the field (details.field)
// so the defaults form marks it instead of a dialog.
func TestUpdateRefusalsLocateField(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	service := &Service{store: &serviceStoreFake{}}
	unknown, nilID := "unknown_ca", uuid.Nil
	for name, check := range map[string]struct {
		request       UpdateRequest
		field, reason string
	}{
		"type":     {UpdateRequest{CertificateType: "self_signed"}, "certificate_type", fielderr.Invalid},
		"issuer":   {UpdateRequest{CertificateType: CertificateTypeACME, Issuer: &unknown}, "issuer", fielderr.Invalid},
		"provider": {UpdateRequest{CertificateType: CertificateTypeACME, DNSProviderID: &nilID}, "dns_provider_id", fielderr.Invalid},
	} {
		t.Run(name, func(t *testing.T) {
			check.request.IdempotencyKey, check.request.RequestID = "key-1", "request-1"
			_, err := service.Update(context.Background(), actor, check.request)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Update() error = %v, want %v", err, ErrInvalidInput)
			}
			located, ok := fielderr.As(err)
			if !ok || located.Field != check.field || located.Reason != check.reason {
				t.Fatalf("Update() field error = %+v (located %v), want %s/%s", located, ok, check.field, check.reason)
			}
		})
	}
	// Idempotency key / request ID / revision are not form fields.
	if _, err := service.Update(context.Background(), actor, UpdateRequest{CertificateType: CertificateTypeACME, IdempotencyKey: "bad key", RequestID: "r"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Update() bad key error = %v", err)
	} else if _, ok := fielderr.As(err); ok {
		t.Fatalf("Update() bad key located a field: %v", err)
	}
}
