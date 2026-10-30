//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestAutoDefenseModuleValues414: up/down/up; site and port group rows are
// accepted, mixed targets, l4 on a site, a frozen suggestion and duplicates
// are refused; both foreign keys cascade.
func TestAutoDefenseModuleValues414(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_autodefense_module_values.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("module values migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	tenantID, scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'414 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ad-414','AD 414','unused')`, userID)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,display_id,name,admin_state,created_by_user_id) VALUES($1,$2,41401,'ad-414','active',$3)`,
		nodeID, scopeID, userID)

	insert := `INSERT INTO autodefense_module_values(target_kind,tenant_scope_id,site_id,port_group_id,node_id,module,field,value,previous,
		reason,suggest,frozen_until,reported_at) VALUES($1,$2,$3,$4,$5,$6,$7,2,1,'r',$8,$9,now())`
	site := uuid.New()
	var none *string
	group := "tcp-443"
	// a site row needs a live site (foreign key); the port group row only the node
	mustExec(t, pool, insert, "port_group", nil, nil, &group, nodeID, "l4", "l4.syn_tier", false, nil)
	for name, args := range map[string][]any{
		"site row with port group": {"site", scopeID, site, &group, nodeID, "cc", "cc.challenge", false, nil},
		"port group with site":     {"port_group", scopeID, site, &group, nodeID, "l4", "l4.syn_tier", false, nil},
		"l4 on a site":             {"site", scopeID, site, none, nodeID, "l4", "l4.syn_tier", false, nil},
		"cc on a port group":       {"port_group", nil, nil, &group, nodeID, "cc", "cc.challenge", false, nil},
		"frozen suggestion":        {"port_group", nil, nil, &group, nodeID, "l4", "l4.idle_seconds", true, "2026-10-19T12:00:00Z"},
	} {
		if _, err := pool.Exec(ctx, insert, args...); sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", name, err)
		}
	}
	if _, err := pool.Exec(ctx, insert, "port_group", nil, nil, &group, nodeID, "l4", "l4.syn_tier", false, nil); sqlState(err) != "23505" {
		t.Fatalf("duplicate port group item: %v, want 23505", err)
	}
	if _, err := pool.Exec(ctx, insert, "site", scopeID, site, none, nodeID, "cc", "cc.challenge", false, nil); sqlState(err) != "23503" {
		t.Fatalf("unknown site: %v, want 23503", err)
	}
	// both foreign keys cascade (deleting a node is refused by unrelated
	// append-only tables in this fixture, so the definition is checked)
	rows, err := pool.Query(ctx, `SELECT confdeltype::text FROM pg_constraint WHERE conrelid='autodefense_module_values'::regclass AND contype='f'`)
	if err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, action)
	}
	rows.Close()
	if len(actions) != 2 || actions[0] != "c" || actions[1] != "c" {
		t.Fatalf("foreign key delete actions = %v (want two cascades)", actions)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
