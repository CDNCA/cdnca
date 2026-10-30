package sitetrafficlimit_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/sitetrafficlimit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	schema := "site_traffic_limit_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

type fakeUsage struct {
	mu    sync.Mutex
	bytes uint64
	calls []time.Time
}

func (usage *fakeUsage) SiteTraffic(_ context.Context, _, _ uuid.UUID, from, _ time.Time) (uint64, error) {
	usage.mu.Lock()
	defer usage.mu.Unlock()
	usage.calls = append(usage.calls, from)
	return usage.bytes, nil
}

type fixture struct {
	pool          *pgxpool.Pool
	scope, owner  uuid.UUID
	site          uuid.UUID
	now           time.Time
	usage         *fakeUsage
	store         *sitetrafficlimit.Service
	evaluator     *sitetrafficlimit.Evaluator
	tenantActor   sitetrafficlimit.Actor
	requestNumber int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := integrationPool(t)
	value := &fixture{pool: pool, scope: uuid.New(), owner: uuid.New(), site: uuid.New(),
		now: time.Date(2026, 10, 18, 4, 0, 0, 0, time.UTC), usage: &fakeUsage{}}
	clock := func() time.Time { return value.now }
	value.store = sitetrafficlimit.NewService(sitetrafficlimit.NewStore(pool, clock))
	evaluator, err := sitetrafficlimit.NewEvaluator(pool, value.usage, time.Minute, 10, clock)
	if err != nil {
		t.Fatal(err)
	}
	value.evaluator = evaluator
	value.tenantActor = sitetrafficlimit.Actor{UserID: value.owner, ScopeID: value.scope, ScopeKind: "tenant"}
	tenantID := uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'traffic-limit-tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{value.scope, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'traffic-limit-owner','owner','x')`, []any{value.owner}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{value.scope, value.owner}},
	} {
		if _, err := pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(statement.sql)[0:3], err)
		}
	}
	// A site needs its origin pool in the same transaction (deferred check).
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id) VALUES($1,1,$2,$3,'limit.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`,
			value.site, value.scope, value.owner); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, value.site); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, value.site)
		return err
	}); err != nil {
		t.Fatalf("insert site: %v", err)
	}
	return value
}

func (value *fixture) put(t *testing.T, setting sitetrafficlimit.Setting) sitetrafficlimit.State {
	t.Helper()
	current, err := value.store.Get(t.Context(), value.tenantActor, value.site)
	if err != nil {
		t.Fatal(err)
	}
	value.requestNumber++
	state, err := value.store.Update(t.Context(), value.tenantActor, sitetrafficlimit.UpdateRequest{
		SiteID: value.site, ExpectedRevision: current.Version, Setting: setting,
		IdempotencyKey: "key-" + uuid.NewString(), RequestID: "request-" + uuid.NewString(), SourceIP: "198.51.100.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (value *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var count int
	if err := value.pool.QueryRow(t.Context(), sql, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (value *fixture) tick(t *testing.T, at time.Time) bool {
	t.Helper()
	value.now = at
	changed, err := value.evaluator.RunOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func ptr(value int64) *int64 { return &value }

// 设置上限 → 当月用量超限 → 发布系统重发 + 审计 → 次月自动恢复；重放同一请求不重复写。
func TestSiteTrafficLimitExceedsAndNextMonthRestores(t *testing.T) {
	value := newFixture(t)
	state := value.put(t, sitetrafficlimit.Setting{Enabled: true, MonthlyBytes: ptr(1 << 30), TimeZone: "Asia/Shanghai",
		NoticeHTML: "<p>本月流量已用完</p>"})
	if state.Version != 2 || !state.Setting.Enabled || state.ExceededPeriod != "" {
		t.Fatalf("state = %+v", state)
	}
	if value.count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2 AND payload->>'ip'='198.51.100.7'`,
		value.scope, sitetrafficlimit.AuditUpdate) != 1 {
		t.Fatal("update audit missing")
	}

	value.usage.bytes = 512 << 20
	if value.tick(t, value.now.Add(2*time.Minute)) {
		t.Fatal("within the cap changed the decision")
	}
	// The month start in Asia/Shanghai is 2026-09-30T16:00Z.
	if len(value.usage.calls) != 1 || !value.usage.calls[0].Equal(time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("usage windows = %v", value.usage.calls)
	}

	value.usage.bytes = 2 << 30
	if !value.tick(t, value.now.Add(2*time.Minute)) {
		t.Fatal("over the cap did not decide")
	}
	current, err := value.store.Get(t.Context(), value.tenantActor, value.site)
	if err != nil || current.ExceededPeriod != "monthly" || current.ExceededAt == nil {
		t.Fatalf("exceeded state = %+v %v", current, err)
	}
	if value.count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2`, value.scope, sitetrafficlimit.AuditExceeded) != 1 {
		t.Fatal("exceeded audit missing")
	}
	// A manual scope is republished through the system channel at once.
	if value.count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`, value.scope) != 1 {
		t.Fatal("no system republication queued")
	}
	if value.tick(t, value.now.Add(2*time.Minute)) {
		t.Fatal("a repeated tick changed the decision again")
	}

	// 2026-11-01 00:30 in Shanghai: the new month's usage is what counts.
	value.usage.bytes = 10 << 20
	if !value.tick(t, time.Date(2026, 10, 31, 16, 30, 0, 0, time.UTC)) {
		t.Fatal("the new month did not restore")
	}
	restored, err := value.store.Get(t.Context(), value.tenantActor, value.site)
	if err != nil || restored.ExceededPeriod != "" {
		t.Fatalf("still exceeded in the next month: %+v %v", restored, err)
	}
	if value.count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2`, value.scope, sitetrafficlimit.AuditRestored) != 1 {
		t.Fatal("restored audit missing")
	}
	if last := value.usage.calls[len(value.usage.calls)-1]; !last.Equal(time.Date(2026, 10, 31, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("new month window starts %s", last)
	}
}

// 关闭上限立即清除超限；提高上限后下一次评估恢复。
func TestSiteTrafficLimitDisableAndRaise(t *testing.T) {
	value := newFixture(t)
	value.put(t, sitetrafficlimit.Setting{Enabled: true, DailyBytes: ptr(100), TimeZone: "UTC"})
	value.usage.bytes = 200
	value.tick(t, value.now.Add(2*time.Minute))
	if state, _ := value.store.Get(t.Context(), value.tenantActor, value.site); state.ExceededPeriod != "daily" {
		t.Fatalf("not exceeded: %+v", state)
	}
	raised := value.put(t, sitetrafficlimit.Setting{Enabled: true, DailyBytes: ptr(1000), TimeZone: "UTC"})
	if raised.ExceededPeriod != "" {
		t.Fatalf("a changed cap kept the old decision: %+v", raised)
	}
	value.tick(t, value.now.Add(2*time.Minute))
	if state, _ := value.store.Get(t.Context(), value.tenantActor, value.site); state.ExceededPeriod != "" {
		t.Fatalf("raised cap still exceeded: %+v", state)
	}
	value.usage.bytes = 5000
	value.tick(t, value.now.Add(2*time.Minute))
	disabled := value.put(t, sitetrafficlimit.Setting{Enabled: false, DailyBytes: ptr(1000), TimeZone: "UTC"})
	if disabled.ExceededPeriod != "" {
		t.Fatalf("disabled limit still exceeded: %+v", disabled)
	}
	if value.tick(t, value.now.Add(2*time.Minute)) {
		t.Fatal("a disabled limit was evaluated")
	}
}

// 同一幂等键重放返回原响应，不同内容冲突；锁定站点租户不可改。
func TestSiteTrafficLimitIdempotencyAndLock(t *testing.T) {
	value := newFixture(t)
	request := sitetrafficlimit.UpdateRequest{SiteID: value.site, ExpectedRevision: 1,
		Setting:        sitetrafficlimit.Setting{Enabled: true, TotalBytes: ptr(1 << 40), TimeZone: "UTC"},
		IdempotencyKey: "same-key", RequestID: "request-1"}
	first, err := value.store.Update(t.Context(), value.tenantActor, request)
	if err != nil || first.TotalSince == nil {
		t.Fatalf("first = %+v %v", first, err)
	}
	again, err := value.store.Update(t.Context(), value.tenantActor, request)
	if err != nil || again.Version != first.Version {
		t.Fatalf("replay = %+v %v", again, err)
	}
	request.Setting.TotalBytes = ptr(1 << 41)
	if _, err := value.store.Update(t.Context(), value.tenantActor, request); err == nil {
		t.Fatal("a different request with the same key was accepted")
	}
	if _, err := value.pool.Exec(t.Context(), `UPDATE sites SET locked_at=clock_timestamp(),lock_reason='abuse',
		locked_by_user_id=$2 WHERE id=$1`, value.site, value.owner); err != nil {
		t.Fatal(err)
	}
	current, _ := value.store.Get(t.Context(), value.tenantActor, value.site)
	_, err = value.store.Update(t.Context(), value.tenantActor, sitetrafficlimit.UpdateRequest{SiteID: value.site,
		ExpectedRevision: current.Version, Setting: sitetrafficlimit.Setting{TimeZone: "UTC"},
		IdempotencyKey: "locked-key", RequestID: "request-2"})
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked site write = %v", err)
	}
	if value.count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2 AND result='denied'
		AND payload->>'reason_code'='site_locked'`, value.scope, sitetrafficlimit.AuditUpdate) != 1 {
		t.Fatal("denied audit missing")
	}
}
