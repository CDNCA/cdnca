package dashboard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type identityVerificationQueryStub struct {
	verified bool
	err      error
	query    string
	args     []any
}

func (stub *identityVerificationQueryStub) QueryRow(
	_ context.Context,
	query string,
	args ...any,
) pgx.Row {
	stub.query = query
	stub.args = append([]any(nil), args...)
	return identityVerificationRowStub{verified: stub.verified, err: stub.err}
}

type identityVerificationRowStub struct {
	verified bool
	err      error
}

func (row identityVerificationRowStub) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != 1 {
		return errors.New("unexpected identity verification destination count")
	}
	verified, ok := destinations[0].(*bool)
	if !ok {
		return errors.New("unexpected identity verification destination")
	}
	*verified = row.verified
	return nil
}

func TestReadTenantIdentityVerificationUsesSettledAuthoritativeFacts(t *testing.T) {
	scopeID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	userID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	for _, verified := range []bool{false, true} {
		t.Run(map[bool]string{false: "unverified", true: "verified"}[verified], func(t *testing.T) {
			query := &identityVerificationQueryStub{verified: verified}
			result, err := readTenantIdentityVerification(t.Context(), query, scopeID, userID)
			if err != nil || result.Verified != verified {
				t.Fatalf("identity verification = %#v, %v", result, err)
			}
			for _, fact := range []string{
				"identity_verified_persons", "identity_verified_organizations",
				"identity_verification_cases", "identity_verification_evidence_settlements",
				"status='approved'", "settlement.state='settled'",
				"ORDER BY created_at DESC,id DESC LIMIT 1",
			} {
				if !strings.Contains(query.query, fact) {
					t.Fatalf("identity query omitted %q: %s", fact, query.query)
				}
			}
			if len(query.args) != 2 || query.args[0] != scopeID || query.args[1] != userID {
				t.Fatalf("identity query args = %#v", query.args)
			}
		})
	}
}

func TestReadTenantIdentityVerificationPropagatesReadFailure(t *testing.T) {
	want := errors.New("identity facts unavailable")
	query := &identityVerificationQueryStub{err: want}
	_, err := readTenantIdentityVerification(t.Context(), query, uuid.New(), uuid.New())
	if !errors.Is(err, want) {
		t.Fatalf("identity verification error = %v, want %v", err, want)
	}
}

func TestPostgresTenantDashboardReturnsAuthoritativeUnverifiedStatus(t *testing.T) {
	fixture, cleanup := newDashboardFixture(t)
	defer cleanup()

	query, err := NewQuery(AudienceTenant, "today", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, query)
	if err != nil {
		t.Fatal(err)
	}
	if !response.IdentityVerification.Available || response.IdentityVerification.Value == nil ||
		response.IdentityVerification.Value.Verified {
		t.Fatalf("tenant identity verification = %#v", response.IdentityVerification)
	}
}
