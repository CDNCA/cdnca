package entitlementguard

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

// User decision 2026-10-21: a lease in grace keeps create/publish/feature
// checks usable while the license service is unreachable; expired and revoked
// leases are denied. Control upgrades (ReadValidVersion) still need valid.
// The revocation list stays current here (accepted five minutes before now).
func TestGuardEntryPointsAllowValidAndGraceOnly(t *testing.T) {
	for _, test := range []struct {
		name   string
		window func(lease *entitlement.Lease, now time.Time)
		revoke bool
		usable bool
	}{
		{name: "valid", usable: true},
		{name: "grace", usable: true, window: func(lease *entitlement.Lease, now time.Time) {
			lease.NotBefore = now.Add(-3 * time.Hour).Unix()
			lease.ExpiresAt = now.Add(-30 * time.Minute).Unix()
			lease.GraceUntil = now.Add(time.Hour).Unix()
		}},
		{name: "expired", window: func(lease *entitlement.Lease, now time.Time) {
			lease.NotBefore = now.Add(-4 * time.Hour).Unix()
			lease.ExpiresAt = now.Add(-2 * time.Hour).Unix()
			lease.GraceUntil = now.Add(-time.Hour).Unix()
		}},
		{name: "revoked", revoke: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebhookFeatureFixture(t)
			lease := integrationLease(fixture.now, 1)
			lease.Features = []entitlement.Feature{{Code: FeatureExtensionsWebhooks}, {Code: testModule},
				{Code: FeatureNodesManage}, {Code: FeatureSitesManage}}
			lease.Quotas = []entitlement.Quota{{Code: QuotaDomainsCount, Limit: 10},
				{Code: QuotaExtensionsWebhooksCount, Limit: 3}, {Code: QuotaNodesCount, Limit: 10}}
			if test.window != nil {
				test.window(&lease, fixture.now)
			}
			fixture.install(t, lease, fixture.now)
			if test.revoke {
				if _, err := fixture.pool.Exec(t.Context(), `UPDATE entitlement_cached_leases SET status='revoked' WHERE serial=1`); err != nil {
					t.Fatal(err)
				}
			}
			guard := fixture.guard()
			wantDenial := func(name string, err error) {
				t.Helper()
				if test.usable && err != nil {
					t.Fatalf("%s(%s) error = %v, want allowed", name, test.name, err)
				}
				if !test.usable && !errors.Is(err, ErrStateDenied) {
					t.Fatalf("%s(%s) error = %v, want ErrStateDenied", name, test.name, err)
				}
			}

			tx := fixture.begin(t)
			_, err := guard.CheckFeature(t.Context(), tx, fixture.check("states-"+test.name))
			_ = tx.Rollback(t.Context())
			wantDenial("CheckFeature", err)

			tx = fixture.begin(t)
			err = guard.CheckSiteChange(t.Context(), tx, SiteCheck{AuditScopeID: fixture.targetScope,
				ActorUserID: fixture.actorUser, ResourceID: uuid.New(), RequestID: "states-site-" + test.name,
				Operation: "site.create", Delta: 1})
			_ = tx.Rollback(t.Context())
			wantDenial("CheckSiteChange", err)

			tx = fixture.begin(t)
			err = guard.CheckNodeCreate(t.Context(), tx, NodeCheck{AuditScopeID: fixture.targetScope,
				ActorUserID: fixture.actorUser, ResourceID: uuid.New(), RequestID: "states-node-" + test.name,
				Operation: "node.create"})
			_ = tx.Rollback(t.Context())
			wantDenial("CheckNodeCreate", err)

			wantDenial("CheckModule", fixture.checkModule(t, testModule, "states-"+test.name))

			grants := fixture.grantedModules(t)
			if test.usable != (len(grants.Codes) == 1 && grants.Codes[0] == testModule) {
				t.Fatalf("GrantedModules(%s) = %+v, usable=%v", test.name, grants, test.usable)
			}

			tx = fixture.begin(t)
			features, err := guard.ReadValidFeatures(t.Context(), tx)
			_ = tx.Rollback(t.Context())
			if err != nil || test.usable != features[FeatureSitesManage] {
				t.Fatalf("ReadValidFeatures(%s) = (%v, %v), usable=%v", test.name, features, err, test.usable)
			}

			tx = fixture.begin(t)
			_, err = guard.ReadValidVersion(t.Context(), tx)
			_ = tx.Rollback(t.Context())
			// B17: upgrades need a valid lease; a locally revoked lease is
			// denied the same way the feature guard denies it.
			if (test.name == "valid") != (err == nil) || test.name == "revoked" && !errors.Is(err, ErrStateDenied) {
				t.Fatalf("ReadValidVersion(%s) error = %v; upgrades need a valid, unrevoked lease", test.name, err)
			}
		})
	}
}

// B17 (LIC-REC-01): once the signed revocation list naming the current serial
// is accepted, the upgrade/maintenance eligibility read must report the lease
// as denied, like CheckFeature and the installation lock, not as valid.
func TestReadValidVersionHonoursAcceptedRevocationList(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, integrationLease(fixture.now, 1), fixture.now)
	guard := fixture.guard()

	tx := fixture.begin(t)
	_, err := guard.ReadValidVersion(t.Context(), tx)
	_ = tx.Rollback(t.Context())
	if err != nil {
		t.Fatalf("ReadValidVersion(before revocation) error = %v, want valid", err)
	}

	acceptIntegrationRevocation(t, fixture.pool, fixture.trust, fixture.signer, fixture.now, fixture.now, 2, []uint64{1})
	tx = fixture.begin(t)
	grant, err := guard.ReadValidVersion(t.Context(), tx)
	_ = tx.Rollback(t.Context())
	if !errors.Is(err, ErrStateDenied) || grant.Serial != 1 {
		t.Fatalf("ReadValidVersion(after revocation) = (%+v, %v), want serial 1 and ErrStateDenied", grant, err)
	}

}
