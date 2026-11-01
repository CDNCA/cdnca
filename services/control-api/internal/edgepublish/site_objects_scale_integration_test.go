//go:build integration

package edgepublish

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// siteObjectScaleSites is the local scale bound (the node side measured the
// same; larger scopes are bounded by the 16 MiB canonical document).
const siteObjectScaleSites = 5000

// A 5000-site scope publishes (the canonical document is ~6 MB, above the
// former 4 MiB bound) as site objects, and after one site changes the next
// publication stores only that site, its bucket and the release-wide
// objects, reusing every other site object.
func TestSiteObjectPublicationAtFiveThousandSites(t *testing.T) {
	fixture := newPublishFixture(t)
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	// Only a site on a valid package is published: the scale
	// sites go on the fixture's subscription, whose domain limit must hold
	// them (the guard refuses the write, so it is written as a replica).
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET domain_limit=-1,site_limit=-1 WHERE id=$1`,
			fixture.subscriptionID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE package_subscription_entitlement_versions SET domain_limit=-1,site_limit=-1
			WHERE subscription_id=$1`, fixture.subscriptionID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,
		tenant_scope_id,owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',clock_timestamp())
		ON CONFLICT DO NOTHING`, fixture.subscriptionID, fixture.scopeID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `
		WITH generated AS (
			SELECT gen_random_uuid() AS id, n FROM generate_series(1,$4::int) n
		), inserted AS (
			INSERT INTO sites (
				id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
				https_enabled,enabled,status,package_subscription_id,package_id,
				created_by_user_id,updated_by_user_id,created_at,updated_at)
			SELECT id,n,$1,$2,'scale-'||n||'.example.test',ARRAY['80'],ARRAY[]::text[],
				ARRAY['203.0.113.10:8080'],ARRAY['203.0.113.10'],false,true,'active',
				$5,(SELECT product_id FROM package_subscriptions WHERE id=$5),$2,$2,$3,$3
			FROM generated RETURNING id
		), pools AS (
			INSERT INTO site_origin_pools(site_id,balance_method,failover_tries,connect_timeout_ms,read_timeout_ms,updated_at)
			SELECT id,'round_robin',1,3000,30000,$3 FROM inserted RETURNING site_id
		)
		INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
		SELECT site_id,1,'203.0.113.10',8080,1,true FROM pools`,
		fixture.scopeID, fixture.userID, publishTestClock, siteObjectScaleSites, fixture.subscriptionID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at)
		VALUES($1,$2,$3) ON CONFLICT(scope_id) DO UPDATE SET next_value=EXCLUDED.next_value`,
		fixture.scopeID, siteObjectScaleSites+1, publishTestClock); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	first, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "v8-scale-first",
		fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("publish %d sites: %v", siteObjectScaleSites, err)
	}
	firstDuration := time.Since(started)
	var objects, snapshotBytes int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_site_objects WHERE configuration_scope_id=$1),
		(SELECT octet_length(canonical_snapshot) FROM config_versions WHERE id=$2)`,
		fixture.scopeID, first.ConfigVersionID).Scan(&objects, &snapshotBytes); err != nil {
		t.Fatal(err)
	}
	if objects < siteObjectScaleSites || snapshotBytes <= 4<<20 {
		t.Fatalf("%d objects, %d snapshot bytes", objects, snapshotBytes)
	}
	if release := receivedV2Bundle(t, fixture, first, fixture.nodeID, key); len(decodeReceivedV2Document(t, release).Sites) != siteObjectScaleSites {
		t.Fatal("the node release does not carry every site")
	}
	finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)

	if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_origins SET port=8081
		WHERE site_id=(SELECT id FROM sites WHERE scope_id=$1 AND display_id=1)`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET revision=revision+1 WHERE scope_id=$1 AND display_id=1`,
		fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	next, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "v8-scale-second",
		fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("republish %d sites: %v", siteObjectScaleSites, err)
	}
	secondDuration := time.Since(started)
	var after int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_site_objects WHERE configuration_scope_id=$1`,
		fixture.scopeID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	// The changed site, its bucket, the scope object and the release-wide
	// files (telemetry/origin-route envelopes live in scope): a handful.
	if added := after - objects; added < 2 || added > 8 {
		t.Fatalf("one changed site added %d objects", added)
	}
	t.Logf("%d sites: first publication %s (%d objects, %d snapshot bytes), one-site change %s (+%d objects)",
		siteObjectScaleSites, firstDuration, objects, snapshotBytes, secondDuration, after-objects)
	_ = next
}
