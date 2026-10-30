//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestPackageTrafficStreamSuspensions508（待出包前全量跑）：508 up/down/up 往返，
// 表/索引/触发器随步骤出现与消失；只能关闭一次（P5081）；存在 open 停服事实时
// 拒绝回退（P5083），关闭后可回退。
func TestPackageTrafficStreamSuspensions508(t *testing.T) {
	const version = 508
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	present := func() (tables, indexes, triggers, functions int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM pg_class WHERE oid=to_regclass(current_schema()||'.package_traffic_stream_suspensions')),
			(SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname IN
				('package_traffic_stream_suspensions_open_508','package_traffic_stream_suspensions_subscription_508')),
			(SELECT count(*) FROM pg_trigger WHERE tgname='package_traffic_stream_suspensions_close_once_508'),
			(SELECT count(*) FROM pg_proc WHERE proname='protect_package_traffic_stream_suspension_508')`).
			Scan(&tables, &indexes, &triggers, &functions); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		tables, indexes, triggers, functions := present()
		want := map[string]int{"up": 1, "down": 0}[step]
		if tables != want || indexes != 2*want || triggers != want || functions != want {
			t.Fatalf("after %s: tables=%d indexes=%d triggers=%d functions=%d", step, tables, indexes, triggers, functions)
		}
	}

	// replica 角色跳过外键，只为造一条 open 停服事实。
	suspension, now := uuid.New(), time.Now().UTC()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO package_traffic_stream_suspensions(
			suspension_id,tenant_scope_id,subscription_id,stream_id,period_key,head_revision,suspended_at)
			VALUES($1,$2,$3,$4,'2026-10',1,$5)`, suspension, uuid.New(), uuid.New(), uuid.New(), now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P5083" {
		t.Fatalf("down with an open suspension: %v, want P5083", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE package_traffic_stream_suspensions SET period_key='other' WHERE suspension_id=$1`, suspension); sqlState(err) != "P5081" {
		t.Fatalf("rewrite open suspension: %v, want P5081", err)
	}
	mustExec(t, pool, `UPDATE package_traffic_stream_suspensions SET recovered_at=$2, recovered_period_key='2026-11',
		recovered_reason='new_cycle', recovered_stream_status='normal' WHERE suspension_id=$1`, suspension, now.Add(time.Minute))
	if _, err := pool.Exec(ctx, `UPDATE package_traffic_stream_suspensions SET recovered_reason='within_limit' WHERE suspension_id=$1`, suspension); sqlState(err) != "P5081" {
		t.Fatalf("reclose suspension: %v, want P5081", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM package_traffic_stream_suspensions WHERE suspension_id=$1`, suspension); sqlState(err) != "P5081" {
		t.Fatalf("delete suspension: %v, want P5081", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down after recovery: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
