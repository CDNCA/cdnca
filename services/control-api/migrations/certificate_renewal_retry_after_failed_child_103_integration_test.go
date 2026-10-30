//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestCertificateRenewalRetryAfterFailedChild103MigrationContract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("103_certificate_renewal_retry_after_failed_child.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("103_certificate_renewal_retry_after_failed_child.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 103 requires the exact verified 102 release head",
		"ALTER TABLE acme_renewal_claim_facts",
		"reopened_from_order_id",
		"claim_reopened",
		"previous.status = 'completed'",
		"renewal_order.status IS DISTINCT FROM 'failed'",
		"renewal_order.renewal_of_order_id IS DISTINCT FROM NEW.source_order_id",
		"renewal_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id",
		"previous.renewal_order_id IS DISTINCT FROM NEW.reopened_from_order_id",
		"NEW.lease_expires_at <= database_now",
		"claim_reopened event must bind the exact failed child",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("103 up missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 103 rollback requires the exact verified 103 head",
		"claim_reopened facts exist; rollback is unsafe",
		"DROP COLUMN reopened_from_order_id",
		"CREATE OR REPLACE FUNCTION validate_acme_renewal_claim_fact_048()",
		"'claim_created', 'lease_taken_over', 'retry_scheduled', 'completed'",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("103 down missing %q", required)
		}
	}
}
