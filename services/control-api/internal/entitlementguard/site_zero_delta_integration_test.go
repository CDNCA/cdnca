package entitlementguard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/jackc/pgx/v5"
)

// FX06: after the lease quota is lowered below the current usage, an edit
// that does not add a domain (cache, origin auth, HTTP policy, challenge:
// Delta 0) is still allowed; adding a domain is rejected. Lease state and
// feature checks keep applying to Delta 0.
func TestSiteGuardZeroDeltaIgnoresQuotaOverage(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	lease := integrationLease(fixture.now, 1)
	lease.Quotas = []entitlement.Quota{{Code: QuotaDomainsCount, Limit: 2}}
	fixture.install(t, lease, fixture.now)
	overLimit := func(context.Context, pgx.Tx) (int64, error) { return 5, nil }

	run := func(guard *Guard, delta int64) error {
		t.Helper()
		tx := fixture.begin(t)
		defer func() { _ = tx.Rollback(context.Background()) }()
		return guard.check(t.Context(), tx, resourceCheck{
			AuditScopeID: fixture.targetScope, ActorUserID: fixture.actorUser, ResourceID: fixture.resourceID,
			RequestID: "fx06", Operation: "cache.policy.update", ResourceType: "site",
			Feature: FeatureSitesManage, Quota: QuotaDomainsCount, Delta: delta, Count: overLimit,
		})
	}
	if err := run(fixture.guard(), 0); err != nil {
		t.Fatalf("Delta 0 over quota = %v, want allowed", err)
	}
	if err := run(fixture.guard(), 1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Delta 1 over quota = %v, want ErrQuotaExceeded", err)
	}
	expired := NewGuard(fixture.pool, func() time.Time { return time.Unix(lease.GraceUntil, 0).UTC().Add(time.Second) }, fixture.trust)
	if err := run(expired, 0); !errors.Is(err, ErrStateDenied) {
		t.Fatalf("Delta 0 with expired lease = %v, want ErrStateDenied", err)
	}
}
