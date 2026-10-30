package originfailover_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/originfailover"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	schema := "origin_failover_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

type fixture struct {
	pool         *pgxpool.Pool
	store        *originfailover.Store
	service      *originfailover.Service
	scope, owner uuid.UUID
	site         uuid.UUID
	now          time.Time
}

// newFixture: a site with primary 192.0.2.10, backup 1 192.0.2.11, backup 2
// 192.0.2.12 (one per level) in failback mode mode.
func newFixture(t *testing.T, mode string) *fixture {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := integrationPool(t)
	value := &fixture{pool: pool, scope: uuid.New(), owner: uuid.New(), site: uuid.New(),
		now: time.Date(2026, 10, 20, 4, 0, 0, 0, time.UTC)}
	alerts, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	value.store = originfailover.NewStore(pool, alerts, func() time.Time { return value.now })
	value.service = originfailover.NewService(originfailover.NewStore(pool, nil, func() time.Time { return value.now }))
	tenantID := uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'origin-failover-tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{value.scope, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash,email) VALUES($1,'of-owner','owner','x','owner@example.test')`, []any{value.owner}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{value.scope, value.owner}},
	} {
		if _, err := pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(statement.sql)[0:3], err)
		}
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id) VALUES($1,1,$2,$3,'failover.example.test',
			ARRAY['192.0.2.10','192.0.2.11','192.0.2.12'],ARRAY['192.0.2.10','192.0.2.11','192.0.2.12'],$3,$3)`,
			value.site, value.scope, value.owner); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id,failback_mode,health_check_path)
			VALUES($1,$2,'/healthz')`, value.site, mode); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,level)
			VALUES($1,1,'192.0.2.10',80,0),($1,2,'192.0.2.11',80,1),($1,3,'192.0.2.12',80,2)`, value.site)
		return err
	}); err != nil {
		t.Fatalf("insert site: %v", err)
	}
	return value
}

// round records one probe round: up[i] is the outcome of level i's origin.
func (value *fixture) round(t *testing.T, up ...bool) {
	t.Helper()
	value.now = value.now.Add(30 * time.Second)
	pools, err := value.store.DuePools(t.Context(), 10)
	if err != nil || len(pools) != 1 || len(pools[0].Origins) != 3 || pools[0].HealthCheckPath != "/healthz" {
		t.Fatalf("due pools %+v %v", pools, err)
	}
	outcomes := map[string]originfailover.Outcome{}
	for index, origin := range pools[0].Origins {
		outcomes[origin.Host+"|80"] = originfailover.Outcome{OK: up[index], Voted: true, Reason: map[bool]string{false: "connect"}[up[index]]}
	}
	if err := value.store.Record(t.Context(), pools[0], outcomes); err != nil {
		t.Fatal(err)
	}
}

func (value *fixture) rounds(t *testing.T, n int, up ...bool) {
	t.Helper()
	for range n {
		value.round(t, up...)
	}
}

func (value *fixture) status(t *testing.T) originfailover.PoolStatus {
	t.Helper()
	status, err := value.service.PoolStatus(t.Context(), value.site)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func (value *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var count int
	if err := value.pool.QueryRow(context.Background(), sql, args...).Scan(&count); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return count
}

func (value *fixture) audits(t *testing.T, action string) int {
	return value.count(t, `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2`, action, value.site.String())
}

func (value *fixture) notices(t *testing.T, eventType string) int {
	return value.count(t, `SELECT count(*) FROM notification_events WHERE event_type=$1 AND scope_id=$2`, eventType, value.scope)
}

func TestOriginFailoverAutoWalksLevelsAndFailsBack(t *testing.T) {
	value := newFixture(t, "auto")
	value.rounds(t, 2, true, true, true)
	if status := value.status(t); status.ActiveLevel != 0 || status.Overall != "healthy" || status.Levels[0].Status != "healthy" {
		t.Fatalf("healthy start %+v", status)
	}
	revision := value.count(t, `SELECT revision FROM sites WHERE id=$1`, value.site)

	// primary down: 3 failures make it unhealthy, then backup 1
	value.rounds(t, 2, false, true, true)
	if status := value.status(t); status.ActiveLevel != 0 {
		t.Fatalf("switched before the debounce %+v", status)
	}
	value.round(t, false, true, true)
	status := value.status(t)
	if status.ActiveLevel != 1 || status.SwitchedAt == nil || status.Origins[0].Status != "unhealthy" || status.Origins[0].Reason != "connect" {
		t.Fatalf("primary down %+v", status)
	}
	if got := value.count(t, `SELECT revision FROM sites WHERE id=$1`, value.site); got != revision+1 {
		t.Fatalf("site revision %d, want %d", got, revision+1)
	}
	if value.audits(t, originfailover.AuditFailover) != 1 || value.notices(t, originfailover.EventFailover) != 1 {
		t.Fatalf("audit %d notice %d", value.audits(t, originfailover.AuditFailover), value.notices(t, originfailover.EventFailover))
	}
	// manual scope (no automatic policy): the system channel is asked
	if value.count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1 AND 'origin_failover'=ANY(triggers)`, value.scope) != 1 {
		t.Fatal("no origin_failover system republication")
	}

	// backup 1 down too: backup 2
	value.rounds(t, 3, false, false, true)
	if status := value.status(t); status.ActiveLevel != 2 {
		t.Fatalf("backup 1 down %+v", status)
	}
	// all down: the level is kept, one all-down notice per level state
	value.rounds(t, 4, false, false, false)
	status = value.status(t)
	if status.ActiveLevel != 2 || status.Overall != "unhealthy" {
		t.Fatalf("all down %+v", status)
	}
	if got := value.notices(t, originfailover.EventFailover); got != 3 {
		t.Fatalf("notices after all down %d, want 2 switches + 1 all-down", got)
	}
	// the primary recovers (2 successes): auto switches straight back to it
	value.round(t, true, false, false)
	if status := value.status(t); status.ActiveLevel != 2 {
		t.Fatalf("recovered before the debounce %+v", status)
	}
	value.round(t, true, false, false)
	if status := value.status(t); status.ActiveLevel != 0 || status.FailbackReady {
		t.Fatalf("auto failback %+v", status)
	}
	if value.audits(t, originfailover.AuditFailover) != 3 {
		t.Fatalf("failover audits %d", value.audits(t, originfailover.AuditFailover))
	}
	// the edge reads the active level from the failover state
	if value.count(t, `SELECT active_level FROM site_origin_failover_states WHERE site_id=$1`, value.site) != 0 {
		t.Fatal("state not back at 0")
	}
}

func TestOriginFailoverManualHoldsUntilFailback(t *testing.T) {
	value := newFixture(t, "manual")
	actor := originfailover.Actor{UserID: value.owner, ScopeID: value.scope, ScopeKind: "tenant"}
	if _, err := value.service.Failback(t.Context(), actor, value.site, "key-0"); !errors.Is(err, originfailover.ErrFailbackUnavailable) {
		t.Fatalf("failback without a switch: %v", err)
	}
	value.rounds(t, 3, false, true, true)
	if status := value.status(t); status.ActiveLevel != 1 || status.FailbackReady {
		t.Fatalf("failover %+v", status)
	}
	// the primary recovers: manual keeps level 1, marks it ready, alerts once
	value.rounds(t, 4, true, true, true)
	status := value.status(t)
	if status.ActiveLevel != 1 || !status.FailbackReady || status.Overall != "healthy" {
		t.Fatalf("manual hold %+v", status)
	}
	if got := value.notices(t, originfailover.EventRecovered); got != 1 {
		t.Fatalf("recovered notices %d, want 1", got)
	}
	// another tenant's member does not see the site
	other := originfailover.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	if _, err := value.service.Status(t.Context(), other, value.site); !errors.Is(err, originfailover.ErrNotFound) {
		t.Fatalf("foreign status: %v", err)
	}
	if _, err := value.service.Failback(t.Context(), other, value.site, "key-x"); !errors.Is(err, originfailover.ErrNotFound) {
		t.Fatalf("foreign failback: %v", err)
	}
	status, err := value.service.Failback(t.Context(), actor, value.site, "key-1")
	if err != nil || status.ActiveLevel != 0 || status.FailbackReady {
		t.Fatalf("failback %+v %v", status, err)
	}
	// the same key replays without a second switch
	if status, err := value.service.Failback(t.Context(), actor, value.site, "key-1"); err != nil || status.ActiveLevel != 0 {
		t.Fatalf("replay %+v %v", status, err)
	}
	if value.audits(t, originfailover.AuditFailback) != 1 {
		t.Fatalf("failback audits %d", value.audits(t, originfailover.AuditFailback))
	}
	if value.count(t, `SELECT count(*) FROM audit_events WHERE action=$1 AND actor_user_id=$2`, originfailover.AuditFailback, value.owner) != 1 {
		t.Fatal("failback audit without the actor")
	}
	// a new key with nothing higher to go to
	if _, err := value.service.Failback(t.Context(), actor, value.site, "key-2"); !errors.Is(err, originfailover.ErrFailbackUnavailable) {
		t.Fatalf("second failback: %v", err)
	}
}

func TestOriginStatusOfDisabledAndDeletedSites(t *testing.T) {
	value := newFixture(t, "auto")
	if _, err := value.pool.Exec(t.Context(), `UPDATE site_origins SET enabled=false WHERE site_id=$1 AND position=3`, value.site); err != nil {
		t.Fatal(err)
	}
	status := value.status(t)
	if len(status.Origins) != 3 || status.Origins[2].Enabled || status.Origins[2].Status != "unknown" || len(status.Levels) != 2 ||
		status.Overall != "unknown" || status.CheckedAt != nil || status.SwitchedAt != nil {
		t.Fatalf("initial %+v", status)
	}
	if _, err := value.pool.Exec(t.Context(), `UPDATE sites SET deleted_at=now() WHERE id=$1`, value.site); err != nil {
		t.Fatal(err)
	}
	if _, err := value.service.PoolStatus(t.Context(), value.site); !errors.Is(err, originfailover.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if pools, err := value.store.DuePools(t.Context(), 10); err != nil || len(pools) != 0 {
		t.Fatalf("deleted site still probed %+v %v", pools, err)
	}
}
