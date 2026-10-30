//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestAutoDefenseNodeSnapshots411: up/down/up; a delivery row with an
// applied or refused receipt is accepted, inconsistent receipt columns and
// unknown error codes are refused, the node foreign key cascades.
func TestAutoDefenseNodeSnapshots411(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_autodefense_node_snapshots.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("node snapshots migration: %v %v", matches, err)
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
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'411 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ad-411','AD 411','unused')`, userID)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,display_id,name,admin_state,created_by_user_id) VALUES($1,$2,40601,'ad-411','active',$3)`,
		nodeID, scopeID, userID)

	mustExec(t, pool, `INSERT INTO autodefense_node_snapshots(node_id,revision,issued_at,content_sha256,sites,updated_at)
		VALUES($1,1760000000000,now(),$2,1,now())`, nodeID, make([]byte, 32))
	update := `UPDATE autodefense_node_snapshots SET receipt_revision=$2,receipt_applied=$3,receipt_error=$4,receipt_sites=$5,
		receipt_signatures=$5,receipt_mitigations=$5,receipt_at=now() WHERE node_id=$1`
	sites := 1
	for name, args := range map[string][]any{
		"applied with error":   {int64(1760000000000), true, "not_supported", &sites},
		"refused with counts":  {int64(1760000000000), false, "not_supported", &sites},
		"unknown error":        {int64(1760000000000), false, "boom", nil},
		"applied without sums": {int64(1760000000000), true, nil, nil},
	} {
		if _, err := pool.Exec(ctx, update, append([]any{nodeID}, args...)...); sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", name, err)
		}
	}
	mustExec(t, pool, update, nodeID, int64(1760000000000), false, "not_supported", nil)
	mustExec(t, pool, update, nodeID, int64(1760000000000), true, nil, &sites)
	if _, err := pool.Exec(ctx, `UPDATE autodefense_node_snapshots SET content_sha256=$2 WHERE node_id=$1`, nodeID, []byte{1}); sqlState(err) != "23514" {
		t.Fatalf("short digest: %v", err)
	}

	var cascade string
	if err := pool.QueryRow(ctx, `SELECT confdeltype::text FROM pg_constraint WHERE conrelid='autodefense_node_snapshots'::regclass
		AND contype='f'`).Scan(&cascade); err != nil || cascade != "c" {
		t.Fatalf("node foreign key delete action = %q, %v (want cascade)", cascade, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
