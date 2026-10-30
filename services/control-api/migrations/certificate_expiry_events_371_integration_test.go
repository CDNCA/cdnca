//go:build integration

package migrations_test

import "testing"

// TestCertificateExpiryEvents371Migration rolls 371 up/down/up. The fact table,
// its event trigger and the scanner are exercised in certificateexpiry.
func TestCertificateExpiryEvents371Migration(t *testing.T) {
	const version = 371
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var active int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_event_contracts_122
		WHERE status='active' AND event_type='io.cdnca.certificate.v1.expiry_reached'`).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active expiry contract = %d, %v", active, err)
	}
}
