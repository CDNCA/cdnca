//go:build integration

package migrations_test

import "testing"

// TestTicketAttachmentCleanup314Migration rolls 314 up, down and up on a 313
// schema and checks the runtime may delete only unbound attachments.
func TestTicketAttachmentCleanup314Migration(t *testing.T) {
	const version = 314
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_app','ticket_attachments','DELETE') AND
		has_table_privilege('cdnca_control_runtime','ticket_attachments','DELETE') AND
		NOT has_table_privilege('cdnca_control_app','tickets','DELETE')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants = %v (%v)", granted, err)
	}
	var guarded bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ticket_attachments'::regclass
		AND tgname='ticket_attachments_delete_guard_314' AND NOT tgisinternal)`).Scan(&guarded); err != nil || !guarded {
		t.Fatalf("delete guard = %v (%v)", guarded, err)
	}
}
