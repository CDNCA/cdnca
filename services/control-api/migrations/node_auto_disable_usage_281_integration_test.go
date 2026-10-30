//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

func TestNodeAutoDisableUsageMigration281(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 280)
	ctx := t.Context()
	scopeID, userID := uuid.New(), uuid.New()
	untouched, chosen, created := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'quota-owner','Quota owner','test-only')`, []any{userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'untouched','active',$3,1)`, []any{untouched, scopeID, userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'chosen','active',$3,2)`, []any{chosen, scopeID, userID}},
		{`UPDATE nodes SET management_settings=jsonb_set(management_settings,'{auto_disable,traffic_total_gb}','800') WHERE id=$1`, []any{chosen}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 281); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'created','active',$3,3)`,
		created, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	enabled := func(id uuid.UUID) bool {
		t.Helper()
		var value bool
		if err := pool.QueryRow(ctx, `SELECT (management_settings->'auto_disable'->>'traffic_enabled')::boolean FROM nodes WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if enabled(untouched) || !enabled(chosen) || enabled(created) {
		t.Fatalf("traffic_enabled untouched=%v chosen=%v created=%v; want false,true,false", enabled(untouched), enabled(chosen), enabled(created))
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_auto_disable_usage(node_id,period_start,period_end,settings_digest,last_sequence,
		usage_bytes,over_streak,under_streak,last_bandwidth_bps,updated_at) VALUES($1,now(),now()+interval '1 month',$2,0,0,0,0,0,now())`,
		created, "0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 281); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if enabled(untouched) {
		t.Fatal("rollback re-enabled a cap nobody chose")
	}
}
