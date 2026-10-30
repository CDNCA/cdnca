package migrations_test

import (
	"os"
	"strings"
	"testing"
)

func TestDNSReconcileProviderReportFence125Contract(t *testing.T) {
	up := readDNSProviderReportFence125(t, "125_dns_reconcile_provider_report_fence.up.sql")
	down := readDNSProviderReportFence125(t, "125_dns_reconcile_provider_report_fence.down.sql")
	for _, marker := range []string{
		"migration 125 requires the exact verified 124 release head",
		"checksum_sha256 = 'd53d6c1fc04d4d09c227989e507b2b35de5855a4a524081290984921fce97afb'",
		"down_checksum_sha256 = '3ecbc3b06be8ad64cac9ea4ba5e7eb9a8fea9710e4957cf89c6ff868c03477cb'",
		"dns_reconcile_provider_reports_source_shape_125",
		"job_attempt IS NOT NULL AND lease_id IS NOT NULL AND worker_id IS NOT NULL",
		"NEW.source = 'worker' OR NEW.job_attempt IS NOT NULL",
		"assert_dns_reconcile_live_claim_076",
	} {
		if !strings.Contains(up, marker) {
			t.Errorf("125 up missing %q", marker)
		}
	}
	for _, marker := range []string{
		"migration 125 rollback requires the exact verified release head",
		"migration_id = '125_dns_reconcile_provider_report_fence'",
		"source = 'workload' AND job_attempt IS NOT NULL",
		"migration 125 rollback would discard fenced provider report facts",
		"DROP CONSTRAINT dns_reconcile_provider_reports_source_shape_125",
		"DROP TABLE dns_reconcile_provider_report_fence_125_backup",
	} {
		if !strings.Contains(down, marker) {
			t.Errorf("125 down missing %q", marker)
		}
	}
	if strings.Contains(strings.ToUpper(up+down), "CASCADE") {
		t.Fatal("125 migration must not use CASCADE")
	}
}

func readDNSProviderReportFence125(t *testing.T, name string) string {
	t.Helper()
	for _, root := range []string{".", "services/control-api/migrations"} {
		if body, err := os.ReadFile(root + "/" + name); err == nil {
			return string(body)
		}
	}
	t.Fatalf("migration file %s not found", name)
	return ""
}
