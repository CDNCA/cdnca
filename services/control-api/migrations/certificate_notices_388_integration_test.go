//go:build integration

package migrations_test

import "testing"

// TestCertificateNotices388: certificate.renew_failed is supported (email on
// by default for members who have not chosen) with versioned zh-CN templates,
// next to 371's expiring/expired; up, down and up again.
func TestCertificateNotices388(t *testing.T) {
	const version = 388
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policies, templates int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM notification_event_policies
		  WHERE event_type IN ('certificate.expiring','certificate.expired','certificate.renew_failed')
		    AND enabled AND supported AND default_email),
		(SELECT count(*) FROM notification_templates WHERE version=1 AND
		  template_id IN ('certificate.expiring.zh-cn','certificate.expired.zh-cn','certificate.renew_failed.zh-cn'))`).
		Scan(&policies, &templates); err != nil || policies != 3 || templates != 6 { // 371: 2 + 4
		t.Fatalf("policies=%d templates=%d (%v)", policies, templates, err)
	}
}
