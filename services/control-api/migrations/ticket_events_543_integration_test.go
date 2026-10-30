//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestTicketEvents543: up/down/up, and the value check refuses rows that do
// not match their kind.
func TestTicketEvents543(t *testing.T) {
	const version = 543
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var check string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname='ticket_events_values_543_check'`).Scan(&check); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"'reopened'", "'closed'", "'urgent'", "pending_customer"} {
		if !strings.Contains(check, required) {
			t.Errorf("value check lacks %s: %s", required, check)
		}
	}
	var grants string
	if err := pool.QueryRow(ctx, `SELECT string_agg(privilege_type, ',' ORDER BY privilege_type)
		FROM information_schema.role_table_grants WHERE table_name='ticket_events' AND grantee='cdnca_control_runtime'`).
		Scan(&grants); err != nil || grants != "INSERT,SELECT" {
		t.Fatalf("runtime grants on ticket_events = %q (%v)", grants, err)
	}
}
