package migrations

import (
	"strings"
	"testing"
)

// Migration 692: on the exact
// verified 691 head, a site that belongs in the publication but is not carried
// by the latest one (or by none) is pending while a scope publication that
// will carry it is in flight (an automatic request of any source, a
// scope-level one included, or the system channel with a stop/restore
// trigger such as package_suspension), and the sync status maps excluded /
// never published to synced only when the site is not meant to be served.
// The per-site and batch functions say the same. Down restores 619 / 618 / 663.
func TestSitePublicationRestoreInFlight692Contract(t *testing.T) {
	expectedSet := "site.enabled\n          AND site.status<>'traffic_exceeded'\n" +
		"          AND subscription.admin_enabled AND subscription.deleted_at IS NULL AND subscription.suspended_at IS NULL\n" +
		"          AND NOT EXISTS (SELECT 1 FROM package_traffic_site_suspensions open\n" +
		"              WHERE open.site_id=site.id AND open.recovered_at IS NULL)\n" +
		"          AND NOT EXISTS (SELECT 1 FROM domain_claim_suspensions claim\n" +
		"              WHERE claim.site_id=site.id AND claim.released_at IS NULL)"
	restoreTriggers := "head.triggers && ARRAY['package_suspension','package_expiry','traffic_enforcement',"
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"692_site_publication_restore_in_flight.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 691", "(SELECT max(version) FROM schema_migrations) <> 691",
			"migration_id='691_package_change_current_entitlement'", "ERRCODE='P6920'",
			"to_regprocedure('site_publication_expected_692(uuid,uuid)') IS NOT NULL",
			"CREATE FUNCTION site_publication_expected_692(scope_id uuid, site_id uuid) RETURNS boolean",
			"CREATE OR REPLACE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid",
			"CREATE OR REPLACE FUNCTION site_sync_status_503(scope_id uuid, site_id uuid) RETURNS text",
			"CREATE OR REPLACE FUNCTION site_sync_status_batch_663(scope_ids uuid[])",
			// per-site and batch: the same "belongs in the publication" set (once each)
			expectedSet,
			// 619 rules stay
			"WHEN summary.total = 0 AND serving_active.total > 0 AND NOT scope_request.in_flight THEN 'undelivered'",
			"AND inflight.iscope IS NULL THEN 'undelivered'",
			// 692: in flight before excluded
			"WHEN (publication.rollout_id IS NULL OR NOT publication.carries) AND restoring.expected AND restoring.in_flight\n                 THEN 'pending'",
			"WHEN (pub.rollout_id IS NULL OR NOT carried.carries) AND expected.esite IS NOT NULL\n" +
				"             AND (inflight.iscope IS NOT NULL OR system_inflight.hscope IS NOT NULL) THEN 'pending'",
			restoreTriggers, "head.state IN ('pending','leased')",
			// sync status: synced only from succeeded, or not meant to be served
			"WHEN 'succeeded' THEN 'synced'\n        ELSE CASE WHEN site_publication_expected_692($1, $2) THEN 'pending' ELSE 'synced' END END",
			"WHEN 'pending' THEN 'pending' WHEN 'succeeded' THEN 'synced'\n" +
				"            ELSE CASE WHEN expected.esite IS NOT NULL THEN 'pending' ELSE 'synced' END END",
			"GRANT EXECUTE ON FUNCTION site_publication_expected_692(uuid, uuid) TO cdnca_control_app",
		}, []string{"UPDATE ", "DELETE FROM", "INSERT INTO", "DROP TABLE", "DROP FUNCTION", "ALTER TABLE",
			"ELSE 'synced' END\n    FROM site_publication_outcome_618"}},
		{"692_site_publication_restore_in_flight.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 692", "migration_id='692_site_publication_restore_in_flight'",
			"ERRCODE='P6921'", "CREATE OR REPLACE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid",
			"WHEN 'undelivered' THEN 'serving_nodes_undelivered'",
			"SELECT CASE outcome.state WHEN 'failed' THEN 'failed' WHEN 'pending' THEN 'pending' ELSE 'synced' END",
			"CREATE OR REPLACE FUNCTION site_sync_status_batch_663(scope_ids uuid[])",
			"DROP FUNCTION site_publication_expected_692(uuid, uuid);",
		}, []string{"restoring", "system_inflight", "edge_system_republication_heads", "DROP TABLE"}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
	up, err := FS.ReadFile("692_site_publication_restore_in_flight.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(up), expectedSet); got != 2 {
		t.Errorf("692 up: the per-site and batch functions must share one expected-in-publication set, found %d copies", got)
	}
	if got := strings.Count(string(up), restoreTriggers); got != 2 {
		t.Errorf("692 up: the per-site and batch functions must share one restore trigger set, found %d copies", got)
	}
}
