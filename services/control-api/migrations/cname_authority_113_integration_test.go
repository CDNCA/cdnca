package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	migration112UpSHA113   = "d26988f21844ba759a0345ad1aed1fd3d40156c6a22dd2e382736987348a8017"
	migration112DownSHA113 = "d329f963d275aad130595d2e4f477e9cfd5416e06bec2761e78760db8f4f1aa0"
	migration113UpSHA113   = "ac4716d79decdb1076dbc19a5bf9ac9400d997f198cd56a8639b3d1924c12ccb"
)

func TestCNAMEAuthority113MigrationContract(t *testing.T) {
	up := readMigration113(t, "113_cname_authority.up.sql")
	down := readMigration113(t, "113_cname_authority.down.sql")
	assertMigrationSHA113(t, "112_dns_reconcile_actor_receipts.up.sql", migration112UpSHA113)
	assertMigrationSHA113(t, "112_dns_reconcile_actor_receipts.down.sql", migration112DownSHA113)
	assertMigrationSHA113(t, "113_cname_authority.up.sql", migration113UpSHA113)

	for _, required := range []string{
		"migration 113 requires the exact verified 112 release head",
		"count(*) FROM schema_migrations) <> 112",
		"max(version) FROM schema_migrations) <> 112",
		"migration_id='112_dns_reconcile_actor_receipts'",
		"checksum_sha256='" + migration112UpSHA113 + "'",
		"down_checksum_sha256='" + migration112DownSHA113 + "'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("113 up release guard missing %q", required)
		}
	}
	guard := strings.Index(up, "migration 113 requires the exact verified 112 release head")
	firstMutation := strings.Index(up, "ALTER TABLE dns_zones")
	if guard < 0 || firstMutation < 0 || guard > firstMutation {
		t.Fatal("113 predecessor guard must run before the first schema mutation")
	}
	if strings.Contains(up, "__MIGRATION_") || strings.Contains(down, "__MIGRATION_") {
		t.Fatal("113 migration retains a provisional release-head placeholder")
	}
}

func TestCNAMEAuthority113ZoneAndSiteProjection(t *testing.T) {
	up := readMigration113(t, "113_cname_authority.up.sql")
	for _, required := range []string{
		"ALTER TABLE dns_zones",
		"ADD COLUMN is_default boolean NOT NULL DEFAULT false",
		"CREATE UNIQUE INDEX dns_zones_scope_default_113_uidx",
		"ON dns_zones (scope_id) WHERE is_default",
		"CONSTRAINT dns_zones_scope_zone_provider_name_113_key UNIQUE (scope_id,id,provider_id,name)",
		"CONSTRAINT package_subscriptions_scope_id_product_113_key UNIQUE (tenant_scope_id,id,product_id)",
		"package_subscription_id uuid",
		"cname_mode text",
		"cname_domain text",
		"cname_hostname2 text",
		"cname_state text",
		"cname_task_id uuid",
		"cname_current_revision bigint",
		"cname_lkg_revision bigint",
		"cname_mode IN ('site','package')",
		"cname_state IN ('pending','failed','done')",
		"package_monitor_subscription_owners",
		"validate_sites_cname_authority_113",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("113 zone/site authority missing %q", required)
		}
	}
	if !strings.Contains(up, "package_subscription_id IS NULL") ||
		!strings.Contains(up, "package_id") || !strings.Contains(up, "tenant_scope_id") {
		t.Fatal("113 must keep unsafe legacy package bindings NULL and validate safe scope/product backfill")
	}
}

func TestCNAMEAuthority113DurableFactsAndConcurrency(t *testing.T) {
	up := readMigration113(t, "113_cname_authority.up.sql")
	for _, required := range []string{
		"CREATE TABLE cname_allocations",
		"CREATE TABLE cname_hostname_claims",
		"CREATE TABLE cname_site_bindings",
		"CREATE TABLE cname_allocation_requests",
		"tenant_id uuid NOT NULL",
		"tenant_scope_id uuid NOT NULL",
		"site_owner_id uuid",
		"package_subscription_id uuid",
		"current_claim_id uuid",
		"lkg_claim_id uuid",
		"current_revision bigint",
		"lkg_revision bigint",
		"generation bigint",
		"job_id uuid NOT NULL",
		"actor_scope_id uuid NOT NULL",
		"actor_user_id uuid NOT NULL",
		"idempotency_key text NOT NULL",
		"request_digest bytea NOT NULL",
		"audit_event_id uuid NOT NULL",
		"expected_revision bigint NOT NULL",
		"result_revision bigint",
		"result_lkg_revision bigint",
		"result_state text",
		"validate_cname_allocation_113",
		"protect_cname_hostname_claim_113",
		"validate_cname_site_binding_113",
		"validate_cname_allocation_request_113",
		"CREATE UNIQUE INDEX",
		"lower(hostname)",
		"UNIQUE (allocation_id,generation)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("113 durable authority missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"ON DELETE CASCADE",
		"UPDATE cname_hostname_claims SET",
		"DELETE FROM cname_hostname_claims",
	} {
		if strings.Contains(up, forbidden) {
			t.Errorf("113 durable facts contain destructive contract %q", forbidden)
		}
	}
}

func TestCNAMEAuthority113PLpgSQLCaseIsUnambiguous(t *testing.T) {
	up := readMigration113(t, "113_cname_authority.up.sql")
	if !strings.Contains(up, "(CASE WHEN NEW.result_state='failed' THEN 'failure' ELSE 'success' END)") {
		t.Fatal("113 allocation request validation must parenthesize its CASE expression inside the PL/pgSQL IF condition")
	}
}

func TestCNAMEAuthority113DownFailsClosedWithFacts(t *testing.T) {
	down := readMigration113(t, "113_cname_authority.down.sql")
	for _, required := range []string{
		"count(*) FROM schema_migrations) <> 113",
		"max(version) FROM schema_migrations) <> 113",
		"migration_id='113_cname_authority'",
		"checksum_sha256='" + migration113UpSHA113 + "'",
		"migration 113 rollback would discard CNAME authority facts",
		"EXISTS (SELECT 1 FROM cname_allocations",
		"EXISTS (SELECT 1 FROM cname_hostname_claims",
		"EXISTS (SELECT 1 FROM cname_site_bindings",
		"EXISTS (SELECT 1 FROM cname_allocation_requests",
		"EXISTS (SELECT 1 FROM dns_zones WHERE is_default",
		"package_subscription_id IS NOT NULL",
		"cname_current_revision IS NOT NULL",
		"cname_lkg_revision IS NOT NULL",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("113 down fail-closed guard missing %q", required)
		}
	}
	guard := strings.Index(down, "migration 113 rollback would discard CNAME authority facts")
	firstDrop := strings.Index(down, "DROP TRIGGER")
	if guard < 0 || firstDrop < 0 || guard > firstDrop {
		t.Fatal("113 rollback fact guard must run before the first schema mutation")
	}
}

func readMigration113(t *testing.T, name string) string {
	t.Helper()
	data, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertMigrationSHA113(t *testing.T, name, expected string) {
	t.Helper()
	data, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(data))
	if actual != expected {
		t.Fatalf("%s SHA=%s want %s", name, actual, expected)
	}
}
