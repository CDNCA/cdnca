//go:build integration

package migrations_test

import (
	"testing"
)

// TestNodeCertificateRecovery434 rolls 434 up, down and up, checks the
// notification event and the 'recovered' certificate event, and that the
// recovery facts are append-only.
func TestNodeCertificateRecovery434(t *testing.T) {
	const version = 434
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policy, templates int
	var recovered bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_event_policies WHERE event_type='node.certificate.recovered'
			AND enabled AND supported AND default_email AND NOT default_sms),
		(SELECT count(*) FROM notification_templates WHERE template_id='node.certificate.recovered.zh-cn'),
		pg_get_constraintdef((SELECT oid FROM pg_constraint WHERE conname='node_certificate_events_event_type_check'
			AND conrelid='node_certificate_events'::regclass)) LIKE '%recovered%'`).Scan(&policy, &templates, &recovered); err != nil ||
		policy != 1 || templates != 2 || !recovered {
		t.Fatalf("policy=%d templates=%d recovered event=%v, %v", policy, templates, recovered, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_certificate_recoveries SET recovered_at=now()`); err != nil {
		t.Fatalf("empty update: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE node_certificate_recoveries`); err == nil {
		t.Fatal("TRUNCATE node_certificate_recoveries succeeded")
	}
}
