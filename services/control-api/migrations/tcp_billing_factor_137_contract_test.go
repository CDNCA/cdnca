package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestTCPBillingFactor137BusinessSchemaContract(t *testing.T) {
	up := readTCPBilling137(t, "137_tcp_billing_factor.up.sql")
	down := readTCPBilling137(t, "137_tcp_billing_factor.down.sql")
	for _, required := range []string{
		"CREATE TABLE tcp_billing_factor_revisions",
		"factor IN ('1.0','1.1')",
		"factor_numerator=1 AND factor_denominator=1",
		"factor_numerator=11 AND factor_denominator=10",
		"UNIQUE (platform_scope_id,revision)",
		"UNIQUE (platform_scope_id,effective_at)",
		"CREATE TABLE tcp_billing_cycle_settlements",
		"raw_tcp_bytes",
		"billed_tcp_bytes",
		"factor_revision_id",
		"factor_effective_at",
		"finalized_through>=cycle_ends_at",
		"octet_length(evidence_sha256)=32",
		"CREATE TABLE tcp_billing_adjustments",
		"operation IN ('refund','void')",
		"CREATE TABLE tcp_billing_write_receipts",
		"request_digest",
		"idempotency_key",
		"BEFORE UPDATE OR DELETE",
		"BEFORE TRUNCATE",
		"tcp_billing.read",
		"tcp_billing.manage",
		"tcp_billing.settle",
		"tcp_billing.adjust",
	} {
		if !strings.Contains(strings.Join(strings.Fields(up), " "), required) {
			t.Errorf("137 up missing %q", required)
		}
	}
	for _, required := range []string{
		"DROP TABLE tcp_billing_write_receipts",
		"DROP TABLE tcp_billing_adjustments",
		"DROP TABLE tcp_billing_cycle_settlements",
		"DROP TABLE tcp_billing_factor_revisions",
	} {
		if !strings.Contains(strings.Join(strings.Fields(down), " "), required) {
			t.Errorf("137 down missing %q", required)
		}
	}
}

func TestTCPBillingFactor137PinsExactReleaseChainBeforeMutation(t *testing.T) {
	up := readTCPBilling137(t, "137_tcp_billing_factor.up.sql")
	down := readTCPBilling137(t, "137_tcp_billing_factor.down.sql")
	for _, required := range []string{
		"migration 137 requires the exact verified 136 release head",
		"version = 136 AND migration_id = '136_site_protocol_batch'",
		"checksum_sha256 = 'f73cf9d49c0da51b31186cadfa57bb68438041fe5af2289d66d85a8f19b38ccb'",
		"down_checksum_sha256 = 'dd787a88f25e0594a9daa8a687224ce464fa67d0b91c8cb5c6ecb0d2206000f1'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("137 up missing release guard %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 137 requires the exact verified 136 release head"), strings.Index(up, "INSERT INTO permissions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("137 predecessor guard must run before the first mutation")
	}
	for _, required := range []string{
		"migration 137 rollback requires the exact verified 137 head",
		"version = 137 AND migration_id = '137_tcp_billing_factor'",
		"checksum_sha256 = '741cabd2ca7d32915d7c2a5e13f42a75ccd9888f3662be8f572cacd3b6d7a4df'",
		"version = 136 AND migration_id = '136_site_protocol_batch'",
		"checksum_sha256 = 'f73cf9d49c0da51b31186cadfa57bb68438041fe5af2289d66d85a8f19b38ccb'",
		"down_checksum_sha256 = 'dd787a88f25e0594a9daa8a687224ce464fa67d0b91c8cb5c6ecb0d2206000f1'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("137 down missing release guard %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 137 rollback requires the exact verified 137 head"), strings.Index(down, "DROP TRIGGER"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("137 rollback release guard must run before the first mutation")
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("137 down must leave migration metadata ownership to the runner")
	}
}

func TestTCPBillingFactor137EnforcesCeilingSnapshotAndAppendOnlyAdjustments(t *testing.T) {
	up := strings.Join(strings.Fields(readTCPBilling137(t, "137_tcp_billing_factor.up.sql")), " ")
	for _, required := range []string{
		"billed_tcp_bytes::numeric = ceil(raw_tcp_bytes::numeric * factor_numerator::numeric / factor_denominator::numeric)",
		"UNIQUE (tenant_scope_id,subscription_id,cycle_key)",
		"UNIQUE (tenant_scope_id,subscription_id,source_watermark)",
		"tcp billing settlements are append-only",
		"tcp billing adjustments are append-only",
		"tcp billing adjustment exceeds remaining billed bytes",
		"void must reverse all remaining billed bytes",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("137 business invariant missing %q", required)
		}
	}
}

func readTCPBilling137(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
