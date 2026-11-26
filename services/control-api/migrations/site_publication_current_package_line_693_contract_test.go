package migrations

import (
	"strings"
	"testing"
)

// Migration 693: on the exact
// verified 692 head, the per-site outcome (detail, site_sync_status_503 and
// the access check) and the batch sync status take the package's main /
// backup line and package L2 line from the entitlement in effect now
// (package_subscription_current_product_snapshot, as the edgepublish compiler
// does), not from the purchase snapshot. Nothing else of 692 changes. Down
// restores the 692 definitions.
func TestSitePublicationCurrentPackageLine693Contract(t *testing.T) {
	const (
		upName   = "693_site_publication_current_package_line.up.sql"
		downName = "693_site_publication_current_package_line.down.sql"
		current  = "LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true"
		initial  = "subscription.product_snapshot"
	)
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down, prior := read(upName), read(downName), read("692_site_publication_restore_in_flight.up.sql")
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 692", "(SELECT max(version) FROM schema_migrations) <> 692",
		"migration_id='692_site_publication_restore_in_flight'", "ERRCODE='P6930'",
		"to_regprocedure('package_subscription_current_product_snapshot(uuid,timestamptz)') IS NULL",
		"to_regprocedure('site_publication_expected_692(uuid,uuid)') IS NULL",
		"CREATE OR REPLACE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid",
		"CREATE OR REPLACE FUNCTION site_sync_status_batch_663(scope_ids uuid[])",
		"(subscription_current.product_snapshot->'spec'->>'node_group_id')::uuid,\n" +
			"             (subscription_current.product_snapshot->'spec'->>'backup_node_group_id')::uuid,",
		"AND line_group.id=COALESCE(site.node_group_id, (subscription_current.product_snapshot->'spec'->>'node_group_id')::uuid)",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("%s missing %q", upName, fragment)
		}
	}
	for _, fragment := range []string{initial, "CREATE OR REPLACE FUNCTION site_sync_status_503", "UPDATE ", "DELETE FROM",
		"INSERT INTO", "DROP ", "ALTER TABLE"} {
		if strings.Contains(up, fragment) {
			t.Errorf("%s must not contain %q", upName, fragment)
		}
	}
	// Both serving branches of both functions read the current entitlement.
	if got := strings.Count(up, current); got != 4 {
		t.Errorf("%s: want the current-entitlement join in 4 serving branches, found %d", upName, got)
	}
	// Only the snapshot source changes: undoing it gives 692's text back.
	for _, fn := range []string{"site_publication_outcome_618", "site_sync_status_batch_663"} {
		got := function(t, up, fn)
		got = strings.ReplaceAll(got, "        "+current+"\n", "")
		got = strings.ReplaceAll(got, "subscription_current.product_snapshot", initial)
		if want := function(t, prior, fn); got != want {
			t.Errorf("%s: %s differs from 692 beyond the snapshot source", upName, fn)
		}
		if function(t, down, fn) != function(t, prior, fn) {
			t.Errorf("%s: %s must restore the 692 definition", downName, fn)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 693", "migration_id='693_site_publication_current_package_line'",
		"ERRCODE='P6931'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("%s missing %q", downName, fragment)
		}
	}
	for _, fragment := range []string{"subscription_current", "DROP ", "UPDATE ", "DELETE FROM"} {
		if strings.Contains(down, fragment) {
			t.Errorf("%s must not contain %q", downName, fragment)
		}
	}
}

// function returns a script's CREATE OR REPLACE FUNCTION name ... $$; text.
func function(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, "CREATE OR REPLACE FUNCTION "+name+"(")
	if start < 0 {
		t.Fatalf("no CREATE OR REPLACE FUNCTION %s", name)
	}
	end := strings.Index(script[start:], "\n$$;")
	if end < 0 {
		t.Fatalf("%s: unterminated body", name)
	}
	return script[start : start+end+len("\n$$;")]
}
