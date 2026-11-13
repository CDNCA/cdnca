//go:build integration

package migrations_test

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationUpDownUp 校验某个迁移 up 改变了结构、down 后与 up 前逐对象一致、再 up 与首次 up 一致。
func migrationUpDownUp(t *testing.T, pool *pgxpool.Pool, version int64) {
	t.Helper()
	before := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	applied := migrationSchemaFingerprint(t, pool)
	if slices.Equal(before, applied) {
		t.Fatalf("up %d changed no schema object", version)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	assertMigrationSchemaEqual(t, "down vs before", before, migrationSchemaFingerprint(t, pool))
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up %d again: %v", version, err)
	}
	assertMigrationSchemaEqual(t, "up again vs first up", applied, migrationSchemaFingerprint(t, pool))
}

// 662 audit_events 时间索引、663 站点同步状态批量函数、664 状态页分组/来源、665 状态页采样明细：
// 各自 up/down/up 对象级还原（down 后与 up 前的结构指纹一致，再 up 与首次 up 一致）。
func TestConsolePerfAndStatusSources662To665UpDownUp(t *testing.T) {
	pool := migrationPoolAt(t, 661)
	for _, version := range []int64{662, 663, 664, 665} {
		migrationUpDownUp(t, pool, version)
	}
}

// 665 状态页采样明细：同一组件同一分钟只留一行（多副本各写一次），状态只允许 degraded / outage，
// 超过保留期的行按 minute 清理（与 sample.go 的清理语句一致），组件被删时明细级联删除。
func TestStatusPageSamples665Semantics(t *testing.T) {
	pool := migrationPoolAt(t, 665)
	ctx := t.Context()
	component := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO status_page_components(id,name,source,manual_status,sort_order,created_at,updated_at)
		VALUES($1,'samples665','manual','operational',0,now(),now())`, component); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	old := now.Add(-31 * 24 * time.Hour)
	insert := `INSERT INTO status_page_samples(component_id,minute,status,reason) VALUES($1,$2,$3,$4) ON CONFLICT (component_id,minute) DO NOTHING`
	for _, row := range []struct {
		at     time.Time
		status string
	}{{now, "outage"}, {now, "degraded"}, {now.Add(-time.Minute), "degraded"}, {old, "outage"}} {
		if _, err := pool.Exec(ctx, insert, component, row.at, row.status, "HTTP 502"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	var status string
	if err := pool.QueryRow(ctx, `SELECT count(*), (SELECT status FROM status_page_samples WHERE component_id=$1 AND minute=$2) FROM status_page_samples WHERE component_id=$1`,
		component, now).Scan(&count, &status); err != nil || count != 3 || status != "outage" {
		t.Fatalf("after inserts: count=%d status=%q err=%v", count, status, err)
	}
	if _, err := pool.Exec(ctx, insert, component, now.Add(-2*time.Minute), "operational", ""); err == nil {
		t.Fatal("status operational must be rejected")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM status_page_samples WHERE minute < $1`, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM status_page_samples WHERE component_id=$1`, component).Scan(&count); err != nil || count != 2 {
		t.Fatalf("after retention delete: count=%d err=%v", count, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM status_page_components WHERE id=$1`, component); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM status_page_samples WHERE component_id=$1`, component).Scan(&count); err != nil || count != 0 {
		t.Fatalf("after component delete: count=%d err=%v", count, err)
	}
}
