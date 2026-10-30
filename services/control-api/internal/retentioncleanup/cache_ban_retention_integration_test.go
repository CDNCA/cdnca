//go:build integration

package retentioncleanup

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cleanup_cache_days（清缓存、解锁IP历史记录）由 worker 执行（迁移 566）。
// 行用 session_replication_role=replica 播种（跳过外键与审计链触发器），删除走真实的清理角色与守卫。
func TestWorkerPrunesCacheOperationsAndBanHistory(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	grantCleanupRole(t, pool)
	platform := uuid.New()
	tenant, site, node, actor := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)

	display := int64(0)
	operation := func(state string, completedAgo string, parent *uuid.UUID, openCommand bool) uuid.UUID {
		id := uuid.New()
		display++
		completed := "NULL"
		if completedAgo != "" {
			completed = "now()-'" + completedAgo + "'::interval"
		}
		seed(t, pool, `INSERT INTO cache_operations(id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,
			request_digest,request_id,actor_user_id,actor_scope_id,state,max_attempts,target_count,node_count,total_count,
			completed_count,succeeded_count,created_at,started_at,updated_at,completed_at,display_id,auto_nodes,parent_operation_id)
			VALUES($1,$2,$3,$4,'purge','whole_site',$5,$6,'retention-cache',$7,$2,$8,3,1,1,1,
			CASE WHEN $8='succeeded' THEN 1 ELSE 0 END,CASE WHEN $8='succeeded' THEN 1 ELSE 0 END,
			now()-interval '400 days',CASE WHEN $8='queued' THEN NULL ELSE now()-interval '400 days' END,now(),`+completed+`,$9,$10,$11)`,
			id, tenant, tenant, site, "k"+id.String()[:8], make([]byte, 32), actor, state, display, parent != nil, parent)
		seed(t, pool, `INSERT INTO cache_operation_targets(operation_id,scope_id,ordinal,canonical_url,canonical_path)
			VALUES($1,$2,1,'/','/')`, id, tenant)
		if state != "succeeded" {
			if openCommand {
				seed(t, pool, `INSERT INTO cache_operation_commands(id,operation_id,scope_id,command,idempotency_key,request_digest,
					actor_user_id,actor_scope_id,created_at) VALUES($1,$2,$3,'retry','retry-open',$4,$5,$3,now())`,
					uuid.New(), id, tenant, make([]byte, 32), actor)
			}
			return id
		}
		seed(t, pool, `INSERT INTO cache_operation_nodes(operation_id,scope_id,node_id,state,attempt,total_count,completed_count,
			succeeded_count,created_at,updated_at,completed_at) VALUES($1,$2,$3,'succeeded',1,1,1,1,now()-interval '400 days',now(),now())`,
			id, tenant, node)
		seed(t, pool, `INSERT INTO cache_operation_node_targets(operation_id,scope_id,node_id,target_ordinal,state,attempt,sequence,completed_at)
			VALUES($1,$2,$3,1,'succeeded',1,1,now())`, id, tenant, node)
		seed(t, pool, `INSERT INTO cache_operation_node_attempts(operation_id,scope_id,node_id,attempt,lease_id,worker_id,state,
			target_count,report_sequence,report_digest,started_at,lease_expires_at,completed_at)
			VALUES($1,$2,$3,1,$4,'worker','succeeded',1,1,$5,now()-interval '400 days',now(),now())`,
			id, tenant, node, uuid.New(), make([]byte, 32))
		seed(t, pool, `INSERT INTO cache_operation_target_results(id,operation_id,scope_id,node_id,target_ordinal,attempt,source,
			state,sequence,report_digest,audit_event_id,created_at) VALUES($1,$2,$3,$4,1,1,'report','succeeded',1,$5,$6,now())`,
			uuid.New(), id, tenant, node, make([]byte, 32), uuid.New())
		seed(t, pool, `INSERT INTO cache_operation_commands(id,operation_id,scope_id,command,idempotency_key,request_digest,
			actor_user_id,actor_scope_id,created_at,completed_at) VALUES($1,$2,$3,'cancel',$4,$5,$6,$3,now()-interval '400 days',now())`,
			uuid.New(), id, tenant, "c"+id.String()[:8], make([]byte, 32), actor)
		return id
	}
	expired := operation("succeeded", "40 days", nil, false)
	recent := operation("succeeded", "10 days", nil, false)
	queued := operation("queued", "", nil, false)
	retrying := operation("failed", "40 days", nil, true)
	// 父操作已过期但后续操作还在期限内：父子都保留；父子都过期：同批删除。
	parentKept := operation("succeeded", "40 days", nil, false)
	childRecent := operation("succeeded", "1 day", &parentKept, false)
	parentGone := operation("succeeded", "50 days", nil, false)
	childGone := operation("succeeded", "45 days", &parentGone, false)

	ban := func(bannedAgo, untilAgo, releasedAgo string) uuid.UUID {
		id := uuid.New()
		released := "NULL"
		if releasedAgo != "" {
			released = "now()-'" + releasedAgo + "'::interval"
		}
		seed(t, pool, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until,released_at)
			VALUES($1,$2,$3,'192.0.2.1','manual',now()-$4::interval,now()-$5::interval,`+released+`)`,
			id, tenant, site, bannedAgo, untilAgo)
		return id
	}
	releasedOld := ban("50 days", "45 days", "40 days")
	releasedRecent := ban("12 days", "1 day", "10 days")
	expiredOld := ban("60 days", "35 days", "")
	active := ban("1 day", "-1 day", "")

	worker, err := NewWorker(pool, audit.New(pool), Config{BatchSize: 2, BatchPause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	results := map[string]Result{}
	for _, result := range worker.RunOnce(ctx) {
		results[result.Table] = result
	}
	if result := results["cache_operations"]; result.Err != nil || result.Deleted != 3 {
		t.Fatalf("cache result = %+v", result)
	}
	if result := results["security_ban_entries"]; result.Err != nil || result.Deleted != 2 {
		t.Fatalf("ban result = %+v", result)
	}
	assertRows(t, pool, "cache_operations", []uuid.UUID{recent, queued, retrying, parentKept, childRecent},
		[]uuid.UUID{expired, parentGone, childGone})
	for _, table := range []string{"cache_operation_targets", "cache_operation_nodes", "cache_operation_node_targets",
		"cache_operation_node_attempts", "cache_operation_target_results", "cache_operation_commands"} {
		var left int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE operation_id = ANY($1)`,
			[]uuid.UUID{expired, parentGone, childGone}).Scan(&left); err != nil || left != 0 {
			t.Fatalf("%s rows of deleted operations = %d (%v)", table, left, err)
		}
	}
	assertRows(t, pool, "security_ban_entries", []uuid.UUID{releasedRecent, active}, []uuid.UUID{releasedOld, expiredOld})
	var audited int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(sum((payload->>'deleted')::bigint),0) FROM audit_events
		WHERE action=$1 AND resource_id IN ('cache_operations','security_ban_entries')`, AuditAction).Scan(&audited); err != nil || audited != 5 {
		t.Fatalf("audited deletes = %d (%v)", audited, err)
	}

	// 其他角色仍不能删缓存历史；清理角色也删不掉期限内的行。
	if _, err := pool.Exec(ctx, `DELETE FROM cache_operation_targets WHERE operation_id=$1`, recent); err == nil {
		t.Fatal("plain delete of cache operation target succeeded")
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+Role); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM security_ban_entries WHERE id=$1`, releasedRecent)
		return err
	}); err == nil {
		t.Fatal("cleanup role deleted a ban entry within retention")
	}

	// 期限 5 天：6 天前解除的仍在 7 天释放下发窗口内，保留。
	seed(t, pool, `INSERT INTO platform_system_cleanup_settings(platform_scope_id,revision,settings,updated_at)
		VALUES($1,1,'{"cleanup_cache_days":5}',now())`, platform)
	windowed := ban("9 days", "8 days", "6 days")
	if again := worker.RunOnce(ctx); again[0].Err != nil {
		t.Fatalf("second run = %+v", again)
	}
	assertRows(t, pool, "security_ban_entries", []uuid.UUID{windowed, active}, []uuid.UUID{releasedRecent})
	assertRows(t, pool, "cache_operations", []uuid.UUID{queued, retrying, childRecent, parentKept}, []uuid.UUID{recent})

	// 0 = 永久保留。
	seed(t, pool, `UPDATE platform_system_cleanup_settings SET settings='{"cleanup_cache_days":0}' WHERE platform_scope_id=$1`, platform)
	for _, result := range worker.RunOnce(ctx) {
		if (result.Table == "cache_operations" || result.Table == "security_ban_entries") && (result.Err != nil || result.Deleted != 0) {
			t.Fatalf("keep-forever run %s = %+v", result.Table, result)
		}
	}
}

func seed(t *testing.T, pool *pgxpool.Pool, statement string, arguments ...any) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role=replica`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), statement, arguments...)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func assertRows(t *testing.T, pool *pgxpool.Pool, table string, kept, deleted []uuid.UUID) {
	t.Helper()
	var keptCount, deletedCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE id = ANY($1)), count(*) FILTER (WHERE id = ANY($2))
		FROM `+table, kept, deleted).Scan(&keptCount, &deletedCount); err != nil {
		t.Fatal(err)
	}
	if keptCount != len(kept) || deletedCount != 0 {
		t.Fatalf("%s kept %d/%d, deleted rows left %d", table, keptCount, len(kept), deletedCount)
	}
}
