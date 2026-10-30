//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNodeLineEndpointCarrierUnique500（NET-02）：同一线路组版本里同一 IP+端口可挂到
// 不同运营商线路，同一运营商下仍唯一；499 无法表达跨运营商重复时 down 拒绝（P5003），没有重复时可来回。
// 待出包前全量跑（子任务不跑 PG 集成）。
func TestNodeLineEndpointCarrierUnique500(t *testing.T) {
	const version = 500
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'net02-owner','NET-02','test-only')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'net02','active',$3,1)`,
		nodeID, scopeID, userID)

	// 499：同一 IP+端口跨运营商仍被旧约束拒绝。
	if err := seedCarrierLineGroup500(t, pool, scopeID, userID, nodeID, "", "电信"); sqlState(err) != "23505" {
		t.Fatalf("499 cross-carrier duplicate: %v, want 23505", err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d without shared addresses: %v", step, version, err)
		}
	}
	if err := seedCarrierLineGroup500(t, pool, scopeID, userID, nodeID, "电信", "电信"); sqlState(err) != "23505" {
		t.Fatalf("same-carrier duplicate: %v, want 23505", err)
	}
	if err := seedCarrierLineGroup500(t, pool, scopeID, userID, nodeID, "", "电信", "联通", "移动"); err != nil {
		t.Fatalf("one IP on default/电信/联通/移动: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P5003" {
		t.Fatalf("down with a cross-carrier shared address: %v, want P5003", err)
	}
}

// seedCarrierLineGroup500 seals revision 1 of a new line group holding
// 192.0.2.10:443 once per carrier.
func seedCarrierLineGroup500(t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID, carriers ...string) error {
	t.Helper()
	groupID := uuid.New()
	return pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'net02',1,$3,$3,now(),now())`,
			groupID, scopeID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'net02','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,$3,$4,$5,now())`,
			groupID, scopeID, len(carriers), make([]byte, 32), userID); err != nil {
			return err
		}
		for _, carrier := range carriers {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,
				config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,'192.0.2.10',4,443,'',$5,0,1,true)`, uuid.New(), nodeID, scopeID, groupID, carrier); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now() FROM node_line_endpoints
			WHERE tenant_scope_id=$1 AND line_group_id=$2`, scopeID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, scopeID, groupID)
		return err
	})
}
