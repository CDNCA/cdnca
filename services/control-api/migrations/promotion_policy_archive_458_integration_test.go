//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestPromotionPolicyArchive458 rolls 458 up, down and up, and checks down
// refuses once a policy is archived (it would re-activate it).
func TestPromotionPolicyArchive458(t *testing.T) {
	const version = 458
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='promotion_policies'
		  AND column_name IN ('archived_at','archived_by_user_id')`).Scan(&columns); err != nil || columns != 2 {
		t.Fatalf("archive columns = %d err=%v", columns, err)
	}
	// Seed an archived policy row without its trigger checks (the store path is
	// covered by internal/promotion); the down guard must then refuse.
	scope, user := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'archive-458','Archive 458','unused')`, user)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, user)
	mustExec(t, pool, `ALTER TABLE promotion_policies DISABLE TRIGGER USER`)
	mustExec(t, pool, `INSERT INTO promotion_policies(id,created_by_scope_id,created_by_user_id,created_at,archived_at,archived_by_user_id)
		VALUES(gen_random_uuid(),$1,$2,now(),now(),$2)`, scope, user)
	mustExec(t, pool, `ALTER TABLE promotion_policies ENABLE TRIGGER USER`)
	err := migrateVersionIsolated(ctx, pool, "down", version)
	if err == nil || !strings.Contains(err.Error(), "re-activate archived promotion policies") {
		t.Fatalf("down with an archived policy error = %v", err)
	}
}
