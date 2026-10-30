//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestMarketSupplyTenantPlugins437 rolls 437 up, down and up and checks the
// row constraints (plugin count, caps shape) and the scope cascade.
func TestMarketSupplyTenantPlugins437(t *testing.T) {
	const version = 437
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	tenant, tenantID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'t437')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenant, tenantID)
	const insert = `INSERT INTO market_supply_tenant_plugins(tenant_scope_id,grant_id,plugins,autodefense_caps,updated_at)
		VALUES($1,$2,$3,$4,now())`
	mustExec(t, pool, insert, tenant, uuid.New(), []string{"module.autodefense"}, `{"max_level":2,"modules_allowed":[]}`)
	for name, args := range map[string][]any{
		"caps array":  {uuid.New(), uuid.New(), []string{}, `[]`},
		"33 plugins":  {uuid.New(), uuid.New(), make([]string, 33), nil},
		"null plugin": {uuid.New(), uuid.New(), []*string{nil}, nil},
	} {
		if _, err := pool.Exec(ctx, insert, args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	mustExec(t, pool, `DELETE FROM access_scopes WHERE id=$1`, tenant)
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM market_supply_tenant_plugins`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("cascade left %d rows: %v", left, err)
	}
}
