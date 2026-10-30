//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestNodeLineEndpointPublishedPerCarrier501：主备按运营商线路分别计算。
// 电信线路 192.0.2.10（priority 0）为主、192.0.2.11（priority 1）为备；联通线路只有 192.0.2.11（priority 1）。
// 312 按地址族全组计算时联通那条被当成备用、不发布；501 后它是联通线路自己的主 IP，发布。
// 回退后恢复 312 行为，再升级可来回。待出包前全量跑（子任务不跑 PG 集成）。
func TestNodeLineEndpointPublishedPerCarrier501(t *testing.T) {
	const version = 501
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	scopeID, userID, nodeID, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'net02-501','NET-02','test-only')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'net02-501','active',$3,1)`,
		nodeID, scopeID, userID)
	unicomID := uuid.New()
	endpoints := []struct {
		id               uuid.UUID
		address, carrier string
		priority         int
	}{
		{uuid.New(), "192.0.2.10", "电信", 0}, {uuid.New(), "192.0.2.11", "电信", 1}, {unicomID, "192.0.2.11", "联通", 1},
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'net02-501',1,$3,$3,now(),now())`,
			groupID, scopeID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'net02-501','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,$3,$4,$5,now())`,
			groupID, scopeID, len(endpoints), make([]byte, 32), userID); err != nil {
			return err
		}
		for _, endpoint := range endpoints {
			if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,
				config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,$5,4,443,'',$6,$7,1,true)`, endpoint.id, nodeID, scopeID, groupID,
				endpoint.address, endpoint.carrier, endpoint.priority); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now() FROM node_line_endpoints
			WHERE tenant_scope_id=$1 AND line_group_id=$2`, scopeID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, scopeID, groupID)
		return err
	}); err != nil {
		t.Fatalf("seed line group: %v", err)
	}
	published := func() (unicomPublished, unicomStandby bool, count int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT bool_or(published) FILTER (WHERE endpoint_id=$2),
			bool_or(standby) FILTER (WHERE endpoint_id=$2), count(*) FILTER (WHERE published)
			FROM node_line_endpoint_published WHERE line_group_id=$1`, groupID, unicomID).
			Scan(&unicomPublished, &unicomStandby, &count); err != nil {
			t.Fatal(err)
		}
		return
	}
	// 500：全组按地址族计算，联通那条被当成备用。
	if ok, standby, count := published(); ok || !standby || count != 1 {
		t.Fatalf("500 view: unicom published=%v standby=%v published=%d", ok, standby, count)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	// 501：电信 192.0.2.10 主、192.0.2.11 备（主在线不发布）；联通 192.0.2.11 是本线路主 IP。
	if ok, standby, count := published(); !ok || standby || count != 2 {
		t.Fatalf("501 view: unicom published=%v standby=%v published=%d", ok, standby, count)
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_app','node_line_endpoint_published','SELECT') AND
		has_table_privilege('cdnca_control_runtime','node_line_endpoint_published','SELECT')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants kept by CREATE OR REPLACE = %v (%v)", granted, err)
	}
}
