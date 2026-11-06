//go:build integration

package retentioncleanup

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 插件拨测请求表（迁移 639）过了 expires_at（创建后 24 小时）的行由 worker 分批删除，
// 每轮最多 MaxBatches×BatchSize 行，剩下的下一轮再删；期限内的行清理角色也删不掉（迁移 643 守卫）。
func TestWorkerPrunesExpiredProbePluginRequests(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	grantCleanupRole(t, pool)
	seed(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, uuid.New())
	request := func(expiresIn string) uuid.UUID {
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO probe_dnspup_plugin_requests(id,origin,idempotency_key,request_digest_sha256,
			request,status,created_at,expires_at) VALUES($1,'admin',$2,$3,'{}','completed',now()-interval '1 day'+$4::interval,
			now()+$4::interval)`, id, id.String(), make([]byte, 32), expiresIn); err != nil {
			t.Fatalf("seed: %v", err)
		}
		return id
	}
	var expired []uuid.UUID
	for _, ago := range []string{"-5 hours", "-4 hours", "-3 hours", "-2 hours", "-1 minute"} {
		expired = append(expired, request(ago))
	}
	fresh := []uuid.UUID{request("1 hour"), request("23 hours")}

	worker, err := NewWorker(pool, audit.New(pool), Config{BatchSize: 2, MaxBatches: 2, BatchPause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	run := func() Result {
		for _, result := range worker.RunOnce(ctx) {
			if result.Table == "probe_dnspup_plugin_requests" {
				return result
			}
		}
		t.Fatal("no probe_dnspup_plugin_requests result")
		return Result{}
	}
	// 每轮上限 2 批 × 2 行：先删最早过期的 4 行，最后 1 行留到下一轮。
	if result := run(); result.Err != nil || result.Deleted != 4 {
		t.Fatalf("first run = %+v", result)
	}
	assertRows(t, pool, "probe_dnspup_plugin_requests", append([]uuid.UUID{expired[4]}, fresh...), expired[:4])
	if result := run(); result.Err != nil || result.Deleted != 1 {
		t.Fatalf("second run = %+v", result)
	}
	assertRows(t, pool, "probe_dnspup_plugin_requests", fresh, expired)
	if result := run(); result.Err != nil || result.Deleted != 0 {
		t.Fatalf("idle run = %+v", result)
	}
	var audited int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(sum((payload->>'deleted')::bigint),0) FROM audit_events
		WHERE action=$1 AND resource_id='probe_dnspup_plugin_requests'`, AuditAction).Scan(&audited); err != nil || audited != 5 {
		t.Fatalf("audited deletes = %d (%v)", audited, err)
	}

	// 清理角色删不掉未过期的行。
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+Role); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM probe_dnspup_plugin_requests WHERE id=$1`, fresh[0])
		return err
	})
	if !hasCode(err, "P6432") {
		t.Fatalf("cleanup role deleted an unexpired probe request: %v", err)
	}
}
