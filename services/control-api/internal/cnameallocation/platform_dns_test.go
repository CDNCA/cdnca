package cnameallocation

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

type fakePlatformDNS struct {
	synced bool
	err    error
	scopes []uuid.UUID
}

func (fake *fakePlatformDNS) EnsurePlatformTenantCopy(_ context.Context, scopeID uuid.UUID) (bool, error) {
	fake.scopes = append(fake.scopes, scopeID)
	return fake.synced, fake.err
}

// A tenant created after the platform DNS configuration gets the copy before
// zone resolution; a failed copy reports its own code, never "not configured".
func TestEnsurePlatformDNSMapsCopyOutcome(t *testing.T) {
	scopeID := uuid.New()
	if err := (&Store{}).ensurePlatformDNS(t.Context(), scopeID); err != nil {
		t.Fatalf("no platform DNS wired: %v", err)
	}
	for _, tc := range []struct {
		name     string
		fake     fakePlatformDNS
		wantCode string
		wantBase error
	}{
		{name: "copied", fake: fakePlatformDNS{synced: true}},
		{name: "present or unconfigured", fake: fakePlatformDNS{}},
		{name: "credentials unavailable", fake: fakePlatformDNS{
			err: fmt.Errorf("%w: credential_encryption_unavailable", dnsacme.ErrPlatformTenantSyncFailed)},
			wantCode: FailurePlatformDNSSyncFailed, wantBase: ErrNotFound},
		{name: "in-flight mutation", fake: fakePlatformDNS{err: dnsacme.ErrPlatformTenantSyncRetry},
			wantCode: FailureAllocationRejected, wantBase: ErrUnavailable},
		{name: "database error", fake: fakePlatformDNS{err: errors.New("connection reset")},
			wantCode: FailureAllocationRejected, wantBase: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake
			store := &Store{}
			store.UsePlatformDNS(&fake)
			err := store.ensurePlatformDNS(t.Context(), scopeID)
			if len(fake.scopes) != 1 || fake.scopes[0] != scopeID {
				t.Fatalf("copy requested for %v", fake.scopes)
			}
			if tc.wantBase == nil {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if !errors.Is(mapError(err), tc.wantBase) || failureCode(err) != tc.wantCode {
				t.Fatalf("err = %v code = %s, want %v/%s", err, failureCode(err), tc.wantBase, tc.wantCode)
			}
			if failureCode(err) == FailureDNSProviderNotConfigured {
				t.Fatal("a configured platform must not report dns_provider_not_configured")
			}
		})
	}
}
