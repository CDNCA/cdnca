//go:build integration

package cccoord

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// stats-platform-l7: ListStates without a tenant scope or site reads every
// tenant's active states newest first, carries each row's tenant, keeps the
// limit, and a tenant scope still sees only its own rows.
func TestListStatesPlatformWideAgainstRealSchema(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (scripts/control-api-integration-sharded.sh)")
	}
	ctx := t.Context()
	store := &Store{pool: pool}
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	siteA, siteB := uuid.New(), uuid.New()
	base := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The state row's foreign keys (settings, facts, sites, policy versions)
	// are not what this read is about; seed the rows directly.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []struct{ id, scope uuid.UUID }{{tenantA, scopeA}, {tenantB, scopeB}} {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants (id, display_name) VALUES ($1, 'stats-l7')`, tenant.id); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, tenant.scope, tenant.id); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(scope, site uuid.UUID, state string, updated time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		digest := make([]byte, 32)
		copy(digest, id[:])
		if _, err := tx.Exec(ctx, `INSERT INTO cc_coordination_states (id,tenant_scope_id,settings_id,settings_revision,site_id,
			source_cc_policy_id,aggregate_digest,rule_id,host,path,method,listen_port,protocol,request_class,client_cidr,
			generation,state,reason_code,hit_count,node_count,current_policy_version,lkg_policy_version,decision_digest,
			last_fact_id,window_started_at,expires_at,release_hold_until,updated_at)
			VALUES ($1,$2,$3,1,$4,$5,$6,$7,'edge.example.test','/login','POST',443,'https','standard','203.0.113.9/32',
			1,$8,'cc_cross_node_threshold_reached',5,2,NULL,NULL,$6,$9,$10,$11,$11,$12)`,
			id, scope, uuid.New(), site, uuid.New(), digest, uuid.New(), state, uuid.New(),
			updated.Add(-time.Minute), updated.Add(time.Hour), updated); err != nil {
			t.Fatal(err)
		}
		return id
	}
	oldA := insert(scopeA, siteA, StateBlocked, base)
	newB := insert(scopeB, siteB, StateBlockPending, base.Add(2*time.Minute))
	midA := insert(scopeA, siteA, StateFailed, base.Add(time.Minute))
	insert(scopeB, siteB, StateReleased, base.Add(3*time.Minute)) // inactive: never listed
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	all, err := store.ListStates(ctx, uuid.Nil, uuid.Nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].ID != newB || all[1].ID != midA || all[2].ID != oldA ||
		all[0].TenantID != tenantB || all[1].TenantID != tenantA || all[0].TenantScopeID != scopeB {
		t.Fatalf("platform list = %+v", all)
	}
	if limited, err := store.ListStates(ctx, uuid.Nil, uuid.Nil, 1); err != nil || len(limited) != 1 || limited[0].ID != newB {
		t.Fatalf("limited = %+v, %v", limited, err)
	}
	if bySite, err := store.ListStates(ctx, uuid.Nil, siteA, 100); err != nil || len(bySite) != 2 || bySite[0].ID != midA {
		t.Fatalf("site filter = %+v, %v", bySite, err)
	}
	own, err := store.ListStates(ctx, scopeA, uuid.Nil, 100)
	if err != nil || len(own) != 2 {
		t.Fatalf("tenant scope = %+v, %v", own, err)
	}
	for _, state := range own {
		if state.TenantScopeID != scopeA || state.TenantID != tenantA {
			t.Fatalf("tenant scope leaked another tenant: %+v", state)
		}
	}
	if got, err := store.GetState(ctx, scopeA, siteA, oldA); err != nil || got.TenantID != tenantA {
		t.Fatalf("GetState = %+v, %v", got, err)
	}
	if _, err := store.GetState(ctx, scopeB, siteA, oldA); err != ErrScopeMismatch {
		t.Fatalf("cross-tenant GetState error = %v", err)
	}
}
