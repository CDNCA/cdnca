package acmedispatch

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

func TestPrepareSaveMatchesLeafSANsAsSet(t *testing.T) {
	t.Parallel()

	requestDomains := []string{"example.test", "www.example.test"}
	tests := []struct {
		name        string
		leafDomains []string
		wantErr     error
	}{
		{
			name:        "same unique set in reverse certificate order",
			leafDomains: []string{"www.example.test", "example.test"},
		},
		{
			name:        "missing SAN",
			leafDomains: []string{"example.test"},
			wantErr:     ErrConflict,
		},
		{
			name:        "extra SAN",
			leafDomains: []string{"example.test", "www.example.test", "api.example.test"},
			wantErr:     ErrConflict,
		},
		{
			name:        "duplicate SAN",
			leafDomains: []string{"example.test", "www.example.test", "www.example.test"},
			wantErr:     ErrConflict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			key := newDispatchKey(t)
			certificate := issueDispatchCertificate(
				t,
				key,
				1,
				time.Date(2026, time.August, 6, 0, 0, 0, 0, time.UTC),
				24*time.Hour,
				test.leafDomains,
			)
			orderID := uuid.New()
			scopeID := uuid.New()
			digest := "sha256:test-request"
			keyRef := "certificate/test-key"
			lease := acmeworker.OperationLease{
				TenantID:    uuid.New(),
				ScopeID:     scopeID,
				OperationID: orderID.String(),
				Token:       uuid.New(),
				Revision:    1,
				Digest:      digest,
				Request: acmeworker.IssueRequest{
					CertificateOrderID: orderID,
					ScopeID:            scopeID,
					ActorUserID:        uuid.New(),
					CertificateKeyRef:  keyRef,
					Domains:            append([]string(nil), requestDomains...),
				},
			}
			lease.Request.TenantID = lease.TenantID
			lease.Request.OperationID = lease.OperationID
			certificate.RequestDigest = digest
			certificate.CertificateKeyRef = keyRef
			certificate.CertificateURL = "https://ca.example/certificate/1"
			certificate.DNSNames = append([]string(nil), requestDomains...)

			requestBefore := append([]string(nil), lease.Request.Domains...)
			certificateBefore := append([]string(nil), certificate.DNSNames...)
			_, err := prepareSave(lease, certificate)
			if test.wantErr == nil && err != nil {
				t.Fatalf("prepareSave() error = %v, want nil", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("prepareSave() error = %v, want %v", err, test.wantErr)
			}
			if !slices.Equal(lease.Request.Domains, requestBefore) {
				t.Fatalf("prepareSave() mutated request domains: got %v, want %v", lease.Request.Domains, requestBefore)
			}
			if !slices.Equal(certificate.DNSNames, certificateBefore) {
				t.Fatalf("prepareSave() mutated certificate DNS names: got %v, want %v", certificate.DNSNames, certificateBefore)
			}
		})
	}
}
