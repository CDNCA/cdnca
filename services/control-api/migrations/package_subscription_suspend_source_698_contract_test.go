package migrations

import (
	"strings"
	"testing"
)

// Migration 698: on the
// exact verified 697 head, package_subscription_suspend_source_698 reads who
// suspended a subscription: the suspend version snapshot's suspend_source,
// else a billing bridge suspend request covering suspended_at, else admin;
// NULL while not suspended. Down drops the function.
func TestPackageSubscriptionSuspendSource698Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("698_package_subscription_suspend_source.up.sql"), read("698_package_subscription_suspend_source.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 697", "(SELECT max(version) FROM schema_migrations) <> 697",
		"migration_id='697_analytics_log_export_downloads'",
		"to_regprocedure('package_subscription_suspend_source_698(uuid)') IS NOT NULL", "ERRCODE='P6980'",
		"CREATE FUNCTION package_subscription_suspend_source_698(target_subscription_id uuid) RETURNS text",
		"LANGUAGE sql STABLE",
		"CASE WHEN subscription.suspended_at IS NULL THEN NULL",
		"version.operation='suspend'", "version.created_at=subscription.suspended_at",
		"version.snapshot->>'suspend_source' IN ('billing_bridge','admin')",
		"JOIN billing_bridge_services service ON service.id=request.service_id",
		"request.action='suspend'", "request.created_at<=subscription.suspended_at",
		"'admin') END",
		"REVOKE ALL ON FUNCTION package_subscription_suspend_source_698(uuid) FROM PUBLIC;",
		"GRANT EXECUTE ON FUNCTION package_subscription_suspend_source_698(uuid) TO cdnca_control_app, cdnca_control_runtime;",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("698 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 698", "migration_id='698_package_subscription_suspend_source'",
		"ERRCODE='P6981'", "DROP FUNCTION package_subscription_suspend_source_698(uuid);",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("698 down missing %q", fragment)
		}
	}
}
