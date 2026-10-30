//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestGENodes376: after 376 a line group cannot be written with the
// undefined failover_mode 'interval'; the two implemented modes still work;
// up, down and up again.
func TestGENodes376(t *testing.T) {
	const version = 376
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var table string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('cname_carrier_line_records')::text,'')`).Scan(&table); err != nil ||
		table != "cname_carrier_line_records" {
		t.Fatalf("cname_carrier_line_records = %q (%v)", table, err)
	}
	var customHTTPAllowed bool
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) LIKE '%custom_http%' FROM pg_constraint
		WHERE conname='dns_providers_provider_type_check'`).Scan(&customHTTPAllowed); err != nil || !customHTTPAllowed {
		t.Fatalf("custom_http provider type not allowed (%v)", err)
	}
	scopeID, userID, _ := seedNodeLineGroupMigration233(t, pool, "tenant", "ge-nodes-376")
	if err := insertNodeLineGroupMigration234(t, pool, scopeID, userID, uuid.New(),
		"376 interval", "", "v4-ge-nodes-interval", nil, "interval"); sqlState(err) != "23514" {
		t.Fatalf("interval failover: %v, want 23514", err)
	}
	for index, mode := range []string{"primary_offline", "online_less_than_backup_count"} {
		if err := insertNodeLineGroupMigration234(t, pool, scopeID, userID, uuid.New(),
			"376 "+mode, "", "v4-ge-nodes-"+string(rune('a'+index)), nil, mode); err != nil {
			t.Fatalf("failover %s: %v", mode, err)
		}
	}
}
