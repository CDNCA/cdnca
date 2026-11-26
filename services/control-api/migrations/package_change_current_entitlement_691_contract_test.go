package migrations

import (
	"strings"
	"testing"
)

// Migration 691: on the exact
// verified 690 head, it adds the current entitlement resolvers (effective
// entitlement of the same scope, else the subscription row) and the package
// change republication marks; it never writes package_subscriptions, whose
// product columns stay the purchase record (261).
func TestPackageChangeCurrentEntitlement691Contract(t *testing.T) {
	up, err := FS.ReadFile("691_package_change_current_entitlement.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("691_package_change_current_entitlement.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 690", "(SELECT max(version) FROM schema_migrations) <> 690",
		"migration_id='690_source_ip_header_reset'", "ERRCODE='P6910'",
		"CREATE FUNCTION package_subscription_current_product_id(p_subscription uuid, p_at timestamptz)",
		"CREATE FUNCTION package_subscription_current_product_snapshot(p_subscription uuid, p_at timestamptz)",
		"e.tenant_scope_id=s.tenant_scope_id",
		"e.revision=package_subscription_effective_entitlement_revision(s.id,p_at)",
		"coalesce(e.product_id,s.product_id)", "coalesce(e.product_snapshot,s.product_snapshot)",
		"CREATE TABLE package_entitlement_republication_marks",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("691 up missing %q", fragment)
		}
	}
	if strings.Contains(string(up), "UPDATE ") || strings.Contains(string(up), "INSERT INTO") ||
		strings.Contains(string(up), "ALTER TABLE package_subscriptions") || strings.Contains(string(up), "DELETE FROM") {
		t.Error("691 up must not rewrite subscription or entitlement facts")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 691",
		"migration_id='691_package_change_current_entitlement'", "ERRCODE='P6911'",
		"DROP TABLE package_entitlement_republication_marks;",
		"DROP FUNCTION package_subscription_current_product_snapshot(uuid,timestamptz);",
		"DROP FUNCTION package_subscription_current_product_id(uuid,timestamptz);",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("691 down missing %q", fragment)
		}
	}
}
