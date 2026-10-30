//go:build integration

package edgepublish

import (
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSiteRuntimeV2TelemetrySubscriptions: the package subscription a v2
// publication records per site (migration 295) is the site's, for a
// subscribed site, a site recovering from package_expired in this
// publication; a site without a subscription is not published at all
// (fix-nopkgpub), so it has no binding.
func TestSiteRuntimeV2TelemetrySubscriptions(t *testing.T) {
	fixture := newL4V2ContractFixture(t)
	subscribed := fixture.createSite(t, "telemetry-subscribed.example.com", 18081, false).Site
	recovering := fixture.createSite(t, "telemetry-recovering.example.com", 18082, false).Site
	plain := fixture.createSite(t, "telemetry-plain.example.com", 18083, false).Site
	fixture.unbindSitePackage(t, plain.ID)
	revision := fixture.sourceRevision()

	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, fixture.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	// Bind two sites to the package and put one in a renewal recovery that
	// targets this source revision (seeded directly: the writers that own
	// these facts are not under test).
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE sites SET package_subscription_id=$2,
				package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=ANY($1::uuid[])`,
			[]uuid.UUID{subscribed.ID, recovering.ID}, fixture.subscriptionID); err != nil {
			return err
		}
		var siteRevision int64
		if err := tx.QueryRow(t.Context(), `UPDATE sites SET status='package_expired' WHERE id=$1 RETURNING revision`,
			recovering.ID).Scan(&siteRevision); err != nil {
			return err
		}
		jobID := uuid.New()
		subject := fmt.Sprintf("site/status-recovery/%s/renewal/%d/%d", recovering.ID, siteRevision, revision)
		if _, err := tx.Exec(t.Context(), `INSERT INTO background_jobs (
				id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,state,attempt,max_attempts,
				claimable_at,total_count,created_at,updated_at)
			VALUES($1,$2,'site.status_recovery',$3,$4,decode(repeat('00',32),'hex'),'telemetry-recovery','queued',0,3,
				now(),1,now(),now())`, jobID, tenantID, subject, "telemetry-recovery-"+jobID.String()); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state)
			VALUES($1,$2,1,$3,'pending')`, tenantID, jobID, recovering.ID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	seedSiteRuntimeV2Capabilities(t, fixture, "", append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion}))
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
		VALUES($1,$2,now()) ON CONFLICT DO NOTHING`, fixture.nodeID, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, v2, err := fixture.service.compileSiteRuntimeV2Facts(t.Context(), tx, fixture.scopeID, uuid.New(),
		revision, TargetSnapshot{NodeIDs: []uuid.UUID{fixture.nodeID}}, publishTestClock, nil)
	if err != nil {
		t.Fatalf("site runtime v2: %v", err)
	}

	want := map[uuid.UUID]uuid.UUID{subscribed.ID: fixture.subscriptionID, recovering.ID: fixture.subscriptionID}
	for name, got := range map[string]map[uuid.UUID]uuid.UUID{"v2": v2} {
		if len(got) != len(want) {
			t.Fatalf("%s sites = %v, want %v", name, got, want)
		}
		for siteID, subscription := range want {
			if got[siteID] != subscription {
				t.Errorf("%s site %s subscription = %s, want %s", name, siteID, got[siteID], subscription)
			}
		}
	}
}
