//go:build integration

package migrations_test

import (
	"testing"
)

// TestSiteSchedule302387: up, down and up again; the settings table checks
// its bounds; a node direct hostname is lower case and unique.
func TestSiteSchedule302387(t *testing.T) {
	const version = 390
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	for _, table := range []string{"site_schedule302_settings", "site_schedule302_write_requests", "node_schedule302_tables"} {
		var name string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass($1)::text,'')`, table).Scan(&name); err != nil || name != table {
			t.Fatalf("%s = %q (%v)", table, name, err)
		}
	}
	scopeID, userID, _ := seedNodeLineGroupMigration233(t, pool, "tenant", "schedule302-390")
	insertNode := func(name string) (string, error) {
		var id string
		err := pool.QueryRow(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES(gen_random_uuid(),$1,$2,'active',$3,(SELECT COALESCE(max(display_id),0)+1 FROM nodes WHERE scope_id=$1))
			RETURNING id::text`, scopeID, name, userID).Scan(&id)
		return id, err
	}
	first, err := insertNode("s302-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := insertNode("s302-b")
	if err != nil {
		t.Fatal(err)
	}
	setHostname := func(id, hostname string) error {
		_, err := pool.Exec(ctx, `UPDATE nodes SET management_settings=management_settings||jsonb_build_object('schedule302_hostname',$2::text)
			WHERE id=$1::uuid`, id, hostname)
		return err
	}
	if err := setHostname(first, "edge-a.cdnca.com"); err != nil {
		t.Fatalf("valid hostname: %v", err)
	}
	if err := setHostname(second, "Edge-B.cdnca.com"); sqlState(err) != "23514" {
		t.Fatalf("upper-case hostname: %v, want 23514", err)
	}
	if err := setHostname(second, "edge-a.cdnca.com"); sqlState(err) != "23505" {
		t.Fatalf("duplicate hostname: %v, want 23505", err)
	}
}
