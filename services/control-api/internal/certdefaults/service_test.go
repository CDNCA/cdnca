package certdefaults

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type serviceStoreFake struct {
	getRequest    Request
	updateRequest UpdateRequest
	updateDigest  [32]byte
	getResult     Defaults
	updateResult  Defaults
	getErr        error
	updateErr     error
	// unconfigured issuers (no platform EAB credentials); issuerChecks
	// records what Update asked
	unconfigured map[string]bool
	issuerChecks []string
	issuerErr    error
}

func (f *serviceStoreFake) IssuerConfigured(_ context.Context, issuer string) (bool, error) {
	f.issuerChecks = append(f.issuerChecks, issuer)
	return !f.unconfigured[issuer], f.issuerErr
}

func (f *serviceStoreFake) Get(_ context.Context, _ Actor, request Request) (Defaults, error) {
	f.getRequest = request
	return f.getResult, f.getErr
}

func (f *serviceStoreFake) Update(_ context.Context, _ Actor, request UpdateRequest, digest [32]byte) (Defaults, error) {
	f.updateRequest = request
	f.updateDigest = digest
	return f.updateResult, f.updateErr
}

func TestServiceGetNormalizesTenantTarget(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	fake := &serviceStoreFake{}
	service := &Service{store: fake}

	if _, err := service.Get(context.Background(), actor, Request{}); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if fake.getRequest.TargetScopeID != actor.ScopeID || fake.getRequest.TargetUserID != actor.UserID {
		t.Fatalf("Get() target = %#v, want actor scope/user", fake.getRequest)
	}

	if _, err := service.Get(context.Background(), actor, Request{TargetScopeID: uuid.New(), TargetUserID: actor.UserID}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Get() mismatched tenant target error = %v, want %v", err, ErrPermissionDenied)
	}
}

func TestServicePlatformRequiresExplicitTarget(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	service := &Service{store: &serviceStoreFake{}}

	if _, err := service.Get(context.Background(), actor, Request{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Get() without platform target error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestServiceUpdateNormalizesAndValidatesRequest(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	providerID := uuid.New()
	fake := &serviceStoreFake{updateResult: Defaults{ScopeID: actor.ScopeID, UserID: actor.UserID, CertificateType: CertificateTypeUploaded, Revision: 1}}
	service := &Service{store: fake}

	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		CertificateType: CertificateTypeUploaded, DNSProviderID: &providerID,
		IdempotencyKey: "certificate-defaults-1", RequestID: "request-1",
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if fake.updateRequest.TargetScopeID != actor.ScopeID || fake.updateRequest.TargetUserID != actor.UserID {
		t.Fatalf("Update() target = %#v, want actor scope/user", fake.updateRequest)
	}
	if fake.updateRequest.DNSProviderID != nil {
		t.Fatal("Update() retained DNS provider for uploaded certificate")
	}
	if fake.updateDigest == [32]byte{} {
		t.Fatal("Update() did not pass a request digest")
	}

	invalid := []UpdateRequest{
		{CertificateType: "unknown", IdempotencyKey: "key", RequestID: "request"},
		{CertificateType: CertificateTypeACME, IdempotencyKey: "", RequestID: "request"},
		{CertificateType: CertificateTypeACME, IdempotencyKey: "key", RequestID: "bad request"},
		{CertificateType: CertificateTypeACME, ExpectedRevision: -1, IdempotencyKey: "key", RequestID: "request"},
	}
	for _, request := range invalid {
		if _, err := service.Update(context.Background(), actor, request); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Update(%#v) error = %v, want %v", request, err, ErrInvalidInput)
		}
	}

	if _, err := service.Update(context.Background(), actor, UpdateRequest{
		TargetScopeID: uuid.New(), TargetUserID: actor.UserID,
		CertificateType: CertificateTypeACME, IdempotencyKey: "certificate-defaults-2", RequestID: "request-2",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Update() mismatched tenant target error = %v, want %v", err, ErrPermissionDenied)
	}
}
