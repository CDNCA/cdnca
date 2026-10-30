package entitlementguard

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

// While the license service is
// down the stale revocation list stays last-known-good until the lease grace
// window ends, so feature/module checks (including publication, which is
// CheckFeature(sites.manage)) behave like site/node quota checks.
func TestLicenseServiceOutageKeepsLastRevocationListUntilGraceEnds(t *testing.T) {
	const day = 24 * time.Hour
	for _, test := range []struct {
		name    string
		outage  time.Duration
		revoked bool
		usable  bool
	}{
		{name: "1h", outage: time.Hour, usable: true},
		{name: "7d", outage: 7 * day, usable: true},
		{name: "29d", outage: 29 * day, usable: true},
		{name: "31d", outage: 31 * day},
		{name: "7d revoked serial", outage: 7 * day, revoked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebhookFeatureFixtureWithKeyWindow(t, 60*day)
			lease := integrationLease(fixture.now, 1)
			lease.Features = []entitlement.Feature{{Code: testModule}, {Code: FeatureNodesManage},
				{Code: FeatureSitesManage}}
			lease.Quotas = []entitlement.Quota{{Code: QuotaDomainsCount, Limit: 10}, {Code: QuotaNodesCount, Limit: 10}}
			lease.GraceUntil = time.Unix(lease.ExpiresAt, 0).Add(30 * day).Unix()
			fixture.install(t, lease, fixture.now)
			if test.revoked {
				// The last list fetched before the outage revokes serial 1.
				acceptIntegrationRevocation(t, fixture.pool, fixture.trust, fixture.signer,
					fixture.now, fixture.now.Add(-4*time.Minute), 2, []uint64{1})
			}
			at := fixture.now.Add(test.outage)
			guard := NewGuard(fixture.pool, func() time.Time { return at }, fixture.trust)
			want := func(name string, err error) {
				t.Helper()
				if test.usable && err != nil {
					t.Fatalf("%s after %s outage = %v, want allowed", name, test.name, err)
				}
				if !test.usable && !errors.Is(err, ErrStateDenied) {
					t.Fatalf("%s after %s outage = %v, want ErrStateDenied", name, test.name, err)
				}
			}

			check := fixture.check("outage-" + test.name)
			check.Feature = FeatureSitesManage
			tx := fixture.begin(t)
			_, err := guard.CheckFeature(t.Context(), tx, check)
			_ = tx.Rollback(t.Context())
			want("CheckFeature(publish)", err)

			tx = fixture.begin(t)
			_, err = guard.CheckModule(t.Context(), tx, ModuleCheck{TargetScopeID: fixture.targetScope,
				ActorScopeID: fixture.actorScope, ActorUserID: fixture.actorUser, ResourceType: "module_probe",
				ResourceID: fixture.resourceID, RequestID: "outage-module-" + test.name,
				Operation: "module_probe.use", Module: testModule})
			_ = tx.Rollback(t.Context())
			want("CheckModule", err)

			tx = fixture.begin(t)
			err = guard.CheckSiteChange(t.Context(), tx, SiteCheck{AuditScopeID: fixture.targetScope,
				ActorUserID: fixture.actorUser, ResourceID: uuid.New(), RequestID: "outage-site-" + test.name,
				Operation: "site.create", Delta: 1})
			_ = tx.Rollback(t.Context())
			want("CheckSiteChange", err)

			tx = fixture.begin(t)
			err = guard.CheckNodeCreate(t.Context(), tx, NodeCheck{AuditScopeID: fixture.targetScope,
				ActorUserID: fixture.actorUser, ResourceID: uuid.New(), RequestID: "outage-node-" + test.name,
				Operation: "node.create"})
			_ = tx.Rollback(t.Context())
			want("CheckNodeCreate", err)

			tx = fixture.begin(t)
			grants, err := guard.GrantedModules(t.Context(), tx)
			_ = tx.Rollback(t.Context())
			if err != nil || test.usable != (len(grants.Codes) == 1 && grants.Codes[0] == testModule) {
				t.Fatalf("GrantedModules after %s outage = (%+v, %v), usable=%v", test.name, grants, err, test.usable)
			}

			tx = fixture.begin(t)
			features, err := guard.ReadValidFeatures(t.Context(), tx)
			_ = tx.Rollback(t.Context())
			if err != nil || test.usable != features[FeatureSitesManage] {
				t.Fatalf("ReadValidFeatures after %s outage = (%v, %v), usable=%v", test.name, features, err, test.usable)
			}

			// Readiness keeps the stale list; the strict Restore used to advance
			// revisions still reports it expired.
			service := NewRevocationService(fixture.pool, fixture.trust)
			if _, err := service.RestoreLKG(t.Context(), at); err != nil {
				t.Fatalf("RestoreLKG after %s outage = %v", test.name, err)
			}
			if _, err := service.Restore(t.Context(), at); !errors.Is(err, ErrRevocationExpired) {
				t.Fatalf("Restore after %s outage = %v, want ErrRevocationExpired", test.name, err)
			}
		})
	}
}

// The stale list is still bound to its signing key: once the key leaves its
// verification window the list is no longer trusted (signature checks are not
// relaxed by the outage rule).
func TestStaleRevocationListRejectedAfterSigningKeyVerifyWindow(t *testing.T) {
	fixture := newWebhookFeatureFixtureWithKeyWindow(t, 60*24*time.Hour)
	lease := integrationLease(fixture.now, 1)
	fixture.install(t, lease, fixture.now)
	trust := fixture.trust
	key, _ := trust.PublicKey(fixture.signer.id)
	expiredAt := fixture.now.Add(time.Hour)
	short := mustTrustStore(t, VerificationKey{KeyID: fixture.signer.id, PublicKey: key,
		NotBefore: fixture.now.Add(-24 * time.Hour), SignUntil: &expiredAt, VerifyUntil: &expiredAt})
	tx := fixture.begin(t)
	defer tx.Rollback(t.Context())
	if _, err := loadRevocationLKGTx(t.Context(), tx, short, expiredAt, integrationCustomerID,
		integrationInstallationID, integrationLicenseID); !errors.Is(err, ErrRevocationInvalid) {
		t.Fatalf("stale list after key verify window = %v, want ErrRevocationInvalid", err)
	}
	if _, err := loadRevocationLKGTx(t.Context(), tx, short, expiredAt.Add(-time.Minute), integrationCustomerID,
		integrationInstallationID, integrationLicenseID); err != nil {
		t.Fatalf("stale list inside key verify window = %v", err)
	}
}
