package migrations

import (
	"os"
	"strings"
	"testing"
)

func TestPackageSubscriptionManualOpen140Contract(t *testing.T) {
	up, err := os.ReadFile("140_package_subscription_manual_open.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("140_package_subscription_manual_open.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 140 requires the exact verified 139 release head",
		"'manual_open'",
		"operation IN ('migration_backfill','manual_open')",
		"source_order_id IS NULL",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("migration 140 up missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 140 rollback requires the verified 140 head",
		"migration 140 rollback would discard manual subscription facts",
		"operation='manual_open'",
	} {
		if !strings.Contains(string(down), required) {
			t.Fatalf("migration 140 down missing %q", required)
		}
	}
}
