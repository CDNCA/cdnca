//go:build integration

package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 迁移 616：287 把 cache_operation_nodes 等 9 张表引用 nodes 的外键改成
// RESTRICT，覆盖了 284 的级联；节点只要做过一次缓存清理（cache_operation_nodes 有 succeeded 行）
// 删除就报 23503 → node_in_use，永远删不掉。已结束的历史行随节点删除；进行中的缓存任务仍拒绝。
func TestNodePurgeRemovesFinishedCacheOperationHistory(t *testing.T) {
	f := newPurgeHistoryFixture(t)
	ctx := t.Context()

	finished := f.platformNode(t, "purge-finished")
	open := f.platformNode(t, "purge-open")
	running := f.platformNode(t, "purge-running")
	for _, nodeID := range []uuid.UUID{finished, open, running} {
		f.publishTo(t, nodeID)
	}
	succeeded := f.purgeOn(t, "finished", finished)
	claims := f.claim(t, "finished", finished)
	reported, err := f.cache.Report(ctx, cachecontrol.ReportRequest{
		ScopeID: claims.ScopeID, OperationID: claims.OperationID, NodeID: claims.NodeID,
		WorkerID: "purge-history-worker-finished", LeaseID: claims.LeaseID, Attempt: claims.Attempt, Sequence: 1,
		Results:   []cachecontrol.TargetResult{{TargetOrdinal: claims.Targets[0].Ordinal, State: cachecontrol.ItemSucceeded}},
		RequestID: "purge-history-report",
	})
	if err != nil || reported.Operation.State != cachecontrol.StateSucceeded {
		t.Fatalf("settle cache operation: %+v %v", reported, err)
	}
	if got := f.count(t, `SELECT count(*) FROM cache_operation_nodes WHERE node_id=$1 AND state='succeeded'`, finished); got != 1 {
		t.Fatalf("succeeded cache operation rows = %d, want 1", got)
	}
	// A deployment that failed by timeout (348) is history too.
	f.timedOutDeployment(t, finished)
	// Current availability alert state (321) is the node's own row.
	f.exec(t, `INSERT INTO node_availability_alert_states(node_id,offline,reason_code,revision,offline_since,changed_at)
		VALUES($1,true,'probe_failed',1,now(),now())`, finished)

	if err := f.retire(t, finished); err != nil {
		t.Fatalf("delete node with finished cache operation: %v", err)
	}
	if got := f.count(t, `SELECT count(*) FROM nodes WHERE id=$1`, finished); got != 0 {
		t.Fatalf("node row still present")
	}
	for _, query := range []string{
		`SELECT count(*) FROM cache_operation_nodes WHERE node_id=$1`,
		`SELECT count(*) FROM cache_operation_node_targets WHERE node_id=$1`,
		`SELECT count(*) FROM cache_operation_node_attempts WHERE node_id=$1`,
		`SELECT count(*) FROM cache_operation_target_results WHERE node_id=$1`,
		`SELECT count(*) FROM node_deployments WHERE node_id=$1`,
		`SELECT count(*) FROM node_availability_alert_states WHERE node_id=$1`,
	} {
		if got := f.count(t, query, finished); got != 0 {
			t.Fatalf("%s = %d after purge, want 0", query, got)
		}
	}
	if got := f.count(t, `SELECT count(*) FROM node_purged_ids WHERE node_id=$1`, finished); got != 1 {
		t.Fatalf("purged id not recorded")
	}
	if got := f.count(t, `SELECT count(*) FROM audit_events WHERE action='node.delete' AND resource_id=$1::text`, finished); got != 1 {
		t.Fatalf("node.delete audit events = %d, want 1", got)
	}
	// The operation itself (tenant's record) survives with its creation audit.
	if got := f.count(t, `SELECT count(*) FROM cache_operations WHERE id=$1`, succeeded); got != 1 {
		t.Fatalf("cache operation row removed with the node")
	}

	// Queued and running cache operations still block the delete.
	f.purgeOn(t, "open", open)
	f.purgeOn(t, "running", running)
	f.claim(t, "running", running)
	for name, nodeID := range map[string]uuid.UUID{"queued": open, "running": running} {
		if err := f.retire(t, nodeID); !errors.Is(err, ErrInUse) {
			t.Fatalf("delete node with %s cache operation: %v, want ErrInUse", name, err)
		}
		if got := f.count(t, `SELECT count(*) FROM nodes WHERE id=$1`, nodeID); got != 1 {
			t.Fatalf("%s node was deleted", name)
		}
	}
}

// Outside a node purge the 348 timeout facts stay immutable after 616.
func TestNodeDeploymentTimeoutsStayImmutableOutsidePurge(t *testing.T) {
	f := newPurgeHistoryFixture(t)
	nodeID := f.platformNode(t, "purge-guard")
	deployment := f.timedOutDeployment(t, nodeID)
	_, err := f.pool.Exec(t.Context(), `DELETE FROM node_deployment_timeouts WHERE deployment_id=$1`, deployment)
	if err == nil {
		t.Fatal("direct delete of a deployment timeout was accepted")
	}
	_, err = f.pool.Exec(t.Context(), `UPDATE node_deployment_timeouts SET previous_state='queued' WHERE deployment_id=$1`, deployment)
	if err == nil {
		t.Fatal("update of a deployment timeout was accepted")
	}
}

type purgeHistoryFixture struct {
	pool                    *pgxpool.Pool
	cache                   *cachecontrol.Store
	platformScope, operator uuid.UUID
	tenant                  cachecontrol.Actor
	siteID                  uuid.UUID
	domain                  string
}

func newPurgeHistoryFixture(t *testing.T) *purgeHistoryFixture {
	t.Helper()
	pool := databasetest.MigratedPool(t, nil)
	cache, err := cachecontrol.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	f := &purgeHistoryFixture{pool: pool, cache: cache, operator: uuid.New(), siteID: uuid.New()}
	suffix := uuid.NewString()[:8]
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&f.platformScope); errors.Is(err, pgx.ErrNoRows) {
		f.platformScope = uuid.New()
		f.exec(t, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, f.platformScope)
	} else if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO users(id,username,display_name,password_hash,status) VALUES($1,$2,'purge operator','x','active')`,
		f.operator, "purge-operator-"+suffix)
	f.exec(t, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, f.platformScope, f.operator)

	tenantID, roleID := uuid.New(), uuid.New()
	f.tenant = cachecontrol.Actor{UserID: uuid.New(), ScopeID: uuid.New()}
	f.tenant.ActorScopeID = f.tenant.ScopeID
	f.domain = "purge-" + suffix + ".example"
	f.exec(t, `INSERT INTO tenants(id,display_name,status) VALUES($1,$2,'active')`, tenantID, "purge tenant "+suffix)
	f.exec(t, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, f.tenant.ScopeID, tenantID)
	f.exec(t, `INSERT INTO users(id,username,display_name,password_hash,status) VALUES($1,$2,'purge tenant','x','active')`,
		f.tenant.UserID, "purge-tenant-"+suffix)
	f.exec(t, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, f.tenant.ScopeID, f.tenant.UserID)
	f.exec(t, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'purge test',true)`,
		roleID, f.tenant.ScopeID, "purge-manage-"+suffix)
	f.exec(t, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'sites.manage'),($1,'sites.read')`, roleID)
	f.exec(t, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.tenant.ScopeID, f.tenant.UserID, roleID)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,
			origin_hosts,https_enabled,enabled,status,created_by_user_id,updated_by_user_id,display_id)
			VALUES($1,$2,$3,$4,'{80}','{443}','{192.0.2.1}','{192.0.2.1}',true,true,'active',$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`,
			f.siteID, f.tenant.ScopeID, f.tenant.UserID, f.domain); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, f.siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.1',80,1,true)`, f.siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *purgeHistoryFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *purgeHistoryFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var value int
	if err := f.pool.QueryRow(t.Context(), sql, args...).Scan(&value); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return value
}

func (f *purgeHistoryFixture) platformNode(t *testing.T, name string) uuid.UUID {
	t.Helper()
	nodeID := uuid.New()
	f.exec(t, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes WHERE scope_id=$2))`,
		nodeID, f.platformScope, name+"-"+nodeID.String()[:8], f.operator)
	return nodeID
}

// publishTo makes the tenant's configuration current on the platform node,
// so the tenant may run cache operations there (tenant_carries_node_287).
func (f *purgeHistoryFixture) publishTo(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	configID := uuid.New()
	f.exec(t, `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,'purge-history',$3,'purge-test','1','releasable',$4,$3,now(),now())`,
		configID, f.tenant.ScopeID, make([]byte, 32), "purge-history-"+configID.String())
	f.exec(t, `INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
		VALUES($1,$2,$3,now())`, nodeID, f.tenant.ScopeID, configID)
}

func (f *purgeHistoryFixture) purgeOn(t *testing.T, key string, nodeID uuid.UUID) uuid.UUID {
	t.Helper()
	result, err := f.cache.CreateOperation(context.Background(), f.tenant, cachecontrol.CreateOperationRequest{
		SiteID: f.siteID, Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
		Targets: []string{"http://" + f.domain + "/" + key}, NodeIDs: []uuid.UUID{nodeID},
		IdempotencyKey: "purge-history-" + key, RequestID: "purge-history-" + key,
	})
	if err != nil {
		t.Fatalf("create cache operation %s: %v", key, err)
	}
	return result.Operation.ID
}

func (f *purgeHistoryFixture) claim(t *testing.T, key string, nodeID uuid.UUID) cachecontrol.Claim {
	t.Helper()
	claims, err := f.cache.Claim(context.Background(), cachecontrol.ClaimRequest{
		ScopeID: f.tenant.ScopeID, WorkerID: "purge-history-worker-" + key, OnlineNodeIDs: []uuid.UUID{nodeID},
		Limit: 1, LeaseDuration: time.Minute, RequestID: "purge-history-claim-" + key,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim cache operation %s: %+v %v", key, claims, err)
	}
	return claims[0]
}

// timedOutDeployment records an overdue deployment of the tenant to the node
// and its 348 timeout fact (as nodeserving's sweep writes it).
func (f *purgeHistoryFixture) timedOutDeployment(t *testing.T, nodeID uuid.UUID) uuid.UUID {
	t.Helper()
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
				generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,'timeout',$3,'purge-test','1','releasable',$4,$3,now(),now())`,
				[]any{configID, f.tenant.ScopeID, make([]byte, 32), "purge-timeout-" + configID.String()}},
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,contract_version,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,'apply','building',1,$4,$5,$6,$6,60000,60000,1,
				now()-interval '2 hours',now()-interval '3 hours',now()-interval '3 hours')`,
				[]any{rolloutID, f.tenant.ScopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New()}},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
				command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES($1,$2,$3,1,$4,'apply','queued',$5,'x',$6,now()-interval '2 hours',
				now()-interval '3 hours',now()-interval '3 hours',$7)`,
				[]any{deploymentID, rolloutID, nodeID, configID, uuid.New(), make([]byte, 32), f.tenant.ScopeID}},
			{`SET LOCAL session_replication_role = origin`, nil},
			{`INSERT INTO node_deployment_timeouts(deployment_id,attempt,previous_state,deadline_at,timed_out_at)
				SELECT id,attempt,state,deadline_at,deadline_at+interval '1 minute' FROM node_deployments WHERE id=$1`,
				[]any{deploymentID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed timed-out deployment: %v", err)
	}
	return deploymentID
}

// retire deletes the node through the administrator path (Store.Update with
// admin_state retired, as POST /v1/nodes/batch-admin-state does per node).
func (f *purgeHistoryFixture) retire(t *testing.T, nodeID uuid.UUID) error {
	t.Helper()
	var revision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT revision FROM nodes WHERE id=$1`, nodeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	retired := StateRetired
	_, err := NewStore(f.pool).Update(t.Context(), Actor{UserID: f.operator, ScopeID: f.platformScope}, UpdateRequest{
		ID: nodeID, ExpectedRevision: revision, Fields: UpdateFields{AdminState: &retired},
		IdempotencyKey: "purge-" + nodeID.String(), RequestID: uuid.NewString(),
	}, [32]byte{1})
	return err
}
