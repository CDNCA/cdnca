//go:build integration

package migrations_test

import (
	"os"
	"strings"
	"testing"
)

func TestCNAMEAllocationTargets126FreezesSoldSealedAuthority(t *testing.T) {
	up, err := os.ReadFile("126_cname_allocation_targets.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	source := string(up)
	for _, required := range []string{
		"package_subscriptions", "product_snapshot", "node_group_id", "node_line_groups",
		"node_line_group_revisions", "sealed_at", "node_line_endpoints", "enabled",
		"cname_allocation_targets", "target_digest", "child_task_id", "child_task_revision",
		"package_subscription_id", "site_revision", "zone_revision", "ttl",
		"cname_allocation_intents", "dns.cname.intent", "tenant_scope_id,tenant_id",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("migration 126 missing %q", required)
		}
	}
	for _, forbidden := range []string{"site.node_group_id", "node_line_endpoint_health"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("migration 126 uses mutable authority %q", forbidden)
		}
	}
	if !strings.Contains(source, "SELECT intent.*,job.state AS intent_job_state INTO intent_match") ||
		strings.Contains(source, "INTO intent_row,intent_job_state") {
		t.Error("migration 126 must use one record target for the intent and job-state projection")
	}
}

func TestCNAMEAllocationTargets126PG17RoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 125)
	assert126 := func(wantApplied bool) {
		t.Helper()
		var applied, targets, intents bool
		if err := pool.QueryRow(t.Context(), `SELECT
			EXISTS (SELECT 1 FROM schema_migrations WHERE version=126),
			to_regclass('cname_allocation_targets') IS NOT NULL,
			to_regclass('cname_allocation_intents') IS NOT NULL`).Scan(&applied, &targets, &intents); err != nil {
			t.Fatal(err)
		}
		if applied != wantApplied || targets != wantApplied || intents != wantApplied {
			t.Fatalf("migration/table state=%t/%t/%t, want %t/%t/%t",
				applied, targets, intents, wantApplied, wantApplied, wantApplied)
		}
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 126); err != nil {
		t.Fatalf("apply migration 126 on PostgreSQL 17: %v", err)
	}
	assert126(true)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 126); err != nil {
		t.Fatalf("rollback migration 126 on PostgreSQL 17: %v", err)
	}
	assert126(false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 126); err != nil {
		t.Fatalf("reapply migration 126 on PostgreSQL 17: %v", err)
	}
	assert126(true)
}
