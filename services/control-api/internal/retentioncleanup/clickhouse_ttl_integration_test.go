//go:build integration

package retentioncleanup

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// FX01: ClickHouse history TTLs follow the cleanup settings, through the
// ingest identity's table-scoped ALTER MODIFY TTL grant (configure-clickhouse.py).
// Needs TEST_CLICKHOUSE_URL/DATABASE/USERNAME/PASSWORD for that identity on a
// database migrated with infra/clickhouse/migrations.
func TestSyncClickHouseTTLFollowsSettings(t *testing.T) {
	endpoint := os.Getenv("TEST_CLICKHOUSE_URL")
	if endpoint == "" {
		t.Skip("TEST_CLICKHOUSE_URL is not set")
	}
	clickHouse, err := NewClickHouseHTTP(endpoint, os.Getenv("TEST_CLICKHOUSE_DATABASE"),
		os.Getenv("TEST_CLICKHOUSE_USERNAME"), os.Getenv("TEST_CLICKHOUSE_PASSWORD"), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool := retentionTestPool(t)
	ctx := context.Background()
	platformScope := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
		t.Fatal(err)
	}
	setSettings := func(settings string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO platform_system_cleanup_settings(platform_scope_id,revision,settings,updated_at)
			VALUES($1,1,$2::jsonb,now()) ON CONFLICT (platform_scope_id) DO UPDATE SET settings=EXCLUDED.settings`,
			platformScope, settings); err != nil {
			t.Fatal(err)
		}
	}
	worker, err := NewWorker(pool, audit.New(pool), Config{ClickHouse: clickHouse})
	if err != nil {
		t.Fatal(err)
	}
	ttl := func(table string) string {
		t.Helper()
		body, err := clickHouse.Exec(ctx, `SELECT extract(engine_full, 'TTL [^S]*') FROM system.tables
			WHERE database = currentDatabase() AND name = '`+table+`'`)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(body))
	}
	sync := func(wantChanges int) {
		t.Helper()
		changes, err := worker.SyncClickHouseTTL(ctx)
		if err != nil || len(changes) != wantChanges {
			t.Fatalf("changes = %+v (%v)", changes, err)
		}
	}
	// Start from the migration TTLs whatever an earlier run left behind.
	setSettings(`{"access_logs_days":30,"blacklist_history_days":90,"bandwidth_history_days":400}`)
	if _, err := worker.SyncClickHouseTTL(ctx); err != nil {
		t.Fatal(err)
	}
	var auditsBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1`, AuditTTLAction).Scan(&auditsBefore); err != nil {
		t.Fatal(err)
	}

	// 0 keeps forever: the TTL is removed.
	setSettings(`{"access_logs_days":7,"blacklist_history_days":0,"bandwidth_history_days":120}`)
	sync(len(ttlTargets))
	if got := ttl("access_events"); !strings.HasSuffix(got, "+ toIntervalDay(7)") {
		t.Fatalf("access_events TTL = %q", got)
	}
	if got := ttl("access_event_query_payload_state_v1"); !strings.HasSuffix(got, "+ toIntervalDay(7)") {
		t.Fatalf("access payload TTL = %q", got)
	}
	if got := ttl("security_events"); got != "" {
		t.Fatalf("security_events TTL = %q", got)
	}
	if got := ttl("access_hourly_facts_v1"); got != "TTL hour + toIntervalDay(120)" {
		t.Fatalf("hourly TTL = %q", got)
	}
	var changed int
	if err := pool.QueryRow(ctx, `SELECT jsonb_array_length(changes) FROM audit_events
		WHERE action=$1 AND scope_id=$2 ORDER BY stream_position DESC LIMIT 1`, AuditTTLAction, platformScope).Scan(&changed); err != nil ||
		changed != len(ttlTargets) {
		t.Fatalf("audited changes = %d (%v)", changed, err)
	}
	// Nothing differs any more: no ALTER, no audit.
	sync(0)
	// Back to the migration values, re-adding the removed TTL.
	setSettings(`{"access_logs_days":30,"blacklist_history_days":90,"bandwidth_history_days":400}`)
	sync(len(ttlTargets))
	if got := ttl("security_events"); got != `TTL toDateTime(occurred_at, \'UTC\') + toIntervalDay(90)` {
		t.Fatalf("restored security_events TTL = %q", got)
	}
	var auditsAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1`, AuditTTLAction).Scan(&auditsAfter); err != nil ||
		auditsAfter != auditsBefore+2 {
		t.Fatalf("ttl audits %d -> %d (%v)", auditsBefore, auditsAfter, err)
	}
	// RunOnce reports the sync as its own result.
	results := worker.RunOnce(ctx)
	if last := results[len(results)-1]; last.Table != clickHouseTTLTable || last.Err != nil {
		t.Fatalf("run once = %+v", results)
	}
}
