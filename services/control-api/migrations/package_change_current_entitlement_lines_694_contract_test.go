package migrations

import (
	"strings"
	"testing"
)

// Migration 694: on the exact
// verified 693 head, tenant_carries_node_287, acme_http01_site_candidate_nodes
// and site_supply_bindings_effective take the package's main / backup line
// from the entitlement in effect now instead of the purchase snapshot, and the
// L2 branches of site_publication_outcome_618 / site_sync_status_batch_663
// count L2 members only when the package's l2_origin is not false (as the
// edgepublish compiler). Nothing else changes; down restores 460 / 285 / 693.
func TestPackageChangeCurrentEntitlementLines694Contract(t *testing.T) {
	const (
		upName   = "694_package_change_current_entitlement_lines.up.sql"
		downName = "694_package_change_current_entitlement_lines.down.sql"
		l2Origin = "          AND COALESCE(subscription_current.product_snapshot#>>'{spec,limits,l2_origin}','')<>'false'\n"
	)
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read(upName), read(downName)
	m460, m285, m693 := read("460_attack_escalation.up.sql"), read("285_site_supply_binding.up.sql"),
		read("693_site_publication_current_package_line.up.sql")
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 693", "(SELECT max(version) FROM schema_migrations) <> 693",
		"migration_id='693_site_publication_current_package_line'", "ERRCODE='P6940'",
		"to_regprocedure('package_subscription_current_product_snapshot(uuid,timestamptz)') IS NULL",
		"ALTER FUNCTION %I.tenant_carries_node_287(uuid, uuid) SET search_path = pg_catalog, %I, pg_temp",
		"CREATE OR REPLACE VIEW site_supply_bindings_effective AS",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("%s missing %q", upName, fragment)
		}
	}
	for _, fragment := range []string{"subscription.product_snapshot", "sub.product_snapshot", "UPDATE ", "DELETE FROM",
		"INSERT INTO", "DROP ", "ALTER TABLE"} {
		if strings.Contains(up, fragment) {
			t.Errorf("%s must not contain %q", upName, fragment)
		}
	}
	// Only the snapshot source changes in the 460 functions.
	for _, fn := range []struct{ name, join string }{
		{"tenant_carries_node_287", "                        LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id, now()) AS product_snapshot)\n                          subscription_current ON true\n"},
		{"acme_http01_site_candidate_nodes", "    LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true\n"},
	} {
		got := function(t, up, fn.name)
		if !strings.Contains(got, fn.join) {
			t.Errorf("%s: %s has no current-entitlement join", upName, fn.name)
		}
		got = strings.ReplaceAll(strings.ReplaceAll(got, fn.join, ""), "subscription_current.product_snapshot", "subscription.product_snapshot")
		if want := function(t, m460, fn.name); got != want {
			t.Errorf("%s: %s differs from 460 beyond the snapshot source", upName, fn.name)
		}
		if function(t, down, fn.name) != function(t, m460, fn.name) {
			t.Errorf("%s: %s must restore the 460 definition", downName, fn.name)
		}
	}
	// The view: the backup branch reads the current entitlement.
	view := func(script string) string {
		start := strings.Index(script, "VIEW site_supply_bindings_effective AS")
		if start < 0 {
			t.Fatal("no site_supply_bindings_effective")
		}
		return script[start : start+strings.Index(script[start:], ";\n")]
	}
	got := strings.ReplaceAll(view(up), "CROSS JOIN LATERAL (SELECT package_subscription_current_product_snapshot(sub.id, now()) AS product_snapshot) sub_current\n", "")
	if got = strings.ReplaceAll(got, "sub_current.product_snapshot", "sub.product_snapshot"); got != view(m285) {
		t.Errorf("%s: site_supply_bindings_effective differs from 285 beyond the snapshot source", upName)
	}
	if view(down) != view(m285) {
		t.Errorf("%s: site_supply_bindings_effective must restore the 285 definition", downName)
	}
	// 618 / 663: the l2_origin condition on the L2 branch, nothing else.
	for _, fn := range []string{"site_publication_outcome_618", "site_sync_status_batch_663"} {
		got := function(t, up, fn)
		if strings.Count(got, l2Origin) != 1 {
			t.Errorf("%s: %s wants the l2_origin condition once on its L2 branch", upName, fn)
		}
		if strings.ReplaceAll(got, l2Origin, "") != function(t, m693, fn) {
			t.Errorf("%s: %s differs from 693 beyond the l2_origin condition", upName, fn)
		}
		if function(t, down, fn) != function(t, m693, fn) {
			t.Errorf("%s: %s must restore the 693 definition", downName, fn)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 694", "migration_id='694_package_change_current_entitlement_lines'",
		"ERRCODE='P6941'", "ALTER FUNCTION %I.tenant_carries_node_287(uuid, uuid) SET search_path = pg_catalog, %I, pg_temp",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("%s missing %q", downName, fragment)
		}
	}
	for _, fragment := range []string{"sub_current", "l2_origin", "DROP ", "UPDATE ", "DELETE FROM"} {
		if strings.Contains(down, fragment) {
			t.Errorf("%s must not contain %q", downName, fragment)
		}
	}
}
