package marketsupply

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSyncProvisionsRenewsAndNeverCancels(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)

	now := time.Date(2026, time.October, 15, 8, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := newTestService(t, pool, clock)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatalf("ensure service actor: %v", err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)

	path := []uuid.UUID{uuid.New(), uuid.New()}
	day := func(g uuid.UUID, notAfter time.Time) grant.Grant {
		return grant.Grant{
			Schema: grant.SchemaV2, GrantID: g, LeafMemberID: uuid.New(), SubscriptionPath: path,
			NodePoolRef: poolID.String(), Limits: spec.LimitSet{{Metric: spec.MetricDomains, Cap: 3, Action: spec.ActionRejectNew}},
			LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
			Allocation: spec.Allocation{HTTPPorts: 2, WebSocket: true},
			Compliance: spec.Compliance{RequireICP: true},
			IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(),
			NotAfter: notAfter.Unix(), GraceSeconds: int64((6 * time.Hour).Seconds()),
		}
	}
	first := day(uuid.New(), now.Add(24*time.Hour))
	outcomes := mustSync(t, svc, first)
	if outcomes[0].Action != "opened" {
		t.Fatalf("first sync = %+v", outcomes[0])
	}
	sub := loadSub(t, pool, outcomes[0].SubscriptionID)
	if want := now.Add(30 * time.Hour); !sub.endsAt.Equal(want) {
		t.Fatalf("ends_at = %s, want not_after+grace %s", sub.endsAt, want)
	}
	if sub.siteLimit != 3 || sub.domainLimit != 3 || sub.trafficLimit != -1 {
		t.Fatalf("limits = %+v", sub)
	}
	var published bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM package_offer_publication_heads head
		JOIN package_subscriptions s ON s.product_id = head.product_id WHERE s.id=$1)`,
		sub.id).Scan(&published); err != nil || published {
		t.Fatalf("market product must never be published for sale: %v %v", published, err)
	}

	if again := mustSync(t, svc, first); again[0].Action != "unchanged" || again[0].SubscriptionID != sub.id {
		t.Fatalf("idempotent re-sync = %+v", again[0])
	}
	// The tenant publishes automatically to the pool's serving node; an
	// unchanged node set adds no policy revision.
	var revisions int
	var mode string
	var targets []uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT count(*) OVER (), mode, node_ids FROM edge_automatic_publication_policy_facts
		WHERE target_scope_id=$1 ORDER BY revision DESC LIMIT 1`, outcomes[0].TenantScopeID).Scan(&revisions, &mode, &targets); err != nil ||
		revisions != 1 || mode != "automatic" || len(targets) != 1 {
		t.Fatalf("delivery policy revisions=%d mode=%s nodes=%v err=%v", revisions, mode, targets, err)
	}
	var poolNode uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT node_id FROM node_line_endpoints WHERE line_group_id=$1`, poolID).Scan(&poolNode); err != nil ||
		targets[0] != poolNode {
		t.Fatalf("delivery policy nodes=%v, want pool node %s (%v)", targets, poolNode, err)
	}

	// Daily re-issue: new grant id, same external key, later not_after.
	renewed := day(uuid.New(), now.Add(48*time.Hour))
	out := mustSync(t, svc, first, renewed)
	if len(out) != 1 || out[0].Action != "renewed" || out[0].SubscriptionID != sub.id {
		t.Fatalf("renewal = %+v", out)
	}
	if got := loadSub(t, pool, sub.id); !got.endsAt.Equal(now.Add(54*time.Hour)) || got.revision != sub.revision+1 {
		t.Fatalf("after renewal = %+v", got)
	}

	// Usage is metered on the renewed grant's subscription.
	usage, err := svc.UsageTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, target := range usage {
		if target.SubscriptionID == sub.id {
			found = target.GrantID == renewed.GrantID && target.TenantScopeID == outcomes[0].TenantScopeID && !target.Since.IsZero()
		}
	}
	if !found {
		t.Fatalf("usage targets = %+v, want subscription %s under grant %s", usage, sub.id, renewed.GrantID)
	}

	// The market returning nothing must not touch the subscription.
	if out := mustSync(t, svc); len(out) != 0 {
		t.Fatalf("empty sync = %+v", out)
	}
	if got := loadSub(t, pool, sub.id); got.status != "active" {
		t.Fatalf("empty sync changed subscription: %+v", got)
	}

	var tenants int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username=$1`,
		tenantPrefix+Key(first)).Scan(&tenants); err != nil || tenants != 1 {
		t.Fatalf("market tenants = %d, %v", tenants, err)
	}

	bad := day(uuid.New(), now.Add(24*time.Hour))
	bad.SubscriptionPath = []uuid.UUID{uuid.New()}
	bad.NodePoolRef = uuid.NewString()
	if out := mustSync(t, svc, bad); out[0].Action != "failed" || !strings.Contains(out[0].Error, "node_pool_ref") {
		t.Fatalf("unknown pool = %+v", out[0])
	}
	expired := day(uuid.New(), now.Add(-7*time.Hour))
	expired.SubscriptionPath = []uuid.UUID{uuid.New()}
	if out := mustSync(t, svc, expired); out[0].Action != "skipped" {
		t.Fatalf("expired grant = %+v", out[0])
	}
	t.Run("service account", func(t *testing.T) { checkServiceAccount(t, pool) })
}

// Shares the schema of the sync test: one migration run costs minutes.
func checkServiceAccount(t *testing.T, pool *pgxpool.Pool) {
	ctx := t.Context()
	now := time.Date(2026, time.October, 16, 8, 0, 0, 0, time.UTC)
	svc := newTestService(t, pool, func() time.Time { return now })
	first, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := svc.ensureActor(ctx); again.sessionID != first.sessionID {
		t.Fatal("a fresh session must be reused")
	}
	if first.userID != mustUser(t, pool) {
		t.Fatal("a second process must reuse the existing service account")
	}
	now = now.Add(55 * time.Minute)
	second, err := svc.ensureActor(ctx)
	if err != nil || second.sessionID == first.sessionID || second.userID != first.userID {
		t.Fatalf("rotation: %+v %v", second, err)
	}
	var live int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL`,
		first.userID).Scan(&live); err != nil || live != 1 {
		t.Fatalf("live sessions = %d, %v", live, err)
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, first.userID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if identity.VerifyPassword(hash, "") || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatal("service account must have an unusable random password")
	}
	var perms []string
	if err := pool.QueryRow(ctx, `SELECT array_agg(p.permission_name ORDER BY p.permission_name)
		FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id WHERE a.user_id=$1`,
		first.userID).Scan(&perms); err != nil {
		t.Fatal(err)
	}
	if strings.Join(perms, ",") != "dns.manage,dns.read,package_subscriptions.manage,package_subscriptions.read,sites.manage,sites.read" {
		t.Fatalf("service account must hold only market permissions, got %v", perms)
	}
}

func platformScope(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	exec(t, pool, `INSERT INTO access_scopes (id, kind) SELECT $1,'platform'
		WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, uuid.New())
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// insertLineGroup builds a sealed one-endpoint node group, mirroring the
// edgepublish resolver fixture.
func insertLineGroup(t *testing.T, pool *pgxpool.Pool, scope, user uuid.UUID) uuid.UUID {
	t.Helper()
	group, node, endpoint := uuid.New(), uuid.New(), uuid.New()
	name := "market-pool-" + group.String()[:8]
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			  VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, []any{node, scope, name, user}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			  VALUES($1,$2,$3,1,$4,$4,now(),now())`, []any{group, scope, name, user}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			  failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			  VALUES($1,$2,1,$3,'lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$4,$5,now())`, []any{group, scope, name, make([]byte, 32), user}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			  VALUES($1,$2,$3,$4,1,'192.0.2.71',4,443,'','',0,1,true)`, []any{endpoint, node, scope, group}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
			  consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			  VALUES($1,$2,1,$3,'unknown',0,0,0,now(),1,now(),now())`, []any{scope, group, endpoint}},
			{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2`, []any{scope, group}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func mustUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM users WHERE username=$1`, ServiceUsername).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

type subRow struct {
	id                                   uuid.UUID
	endsAt                               time.Time
	siteLimit, domainLimit, trafficLimit int64
	revision                             int64
	status                               string
}

func loadSub(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) subRow {
	t.Helper()
	row := subRow{id: id}
	if err := pool.QueryRow(t.Context(), `SELECT ends_at, site_limit, domain_limit, traffic_limit_bytes, revision,
		lifecycle_status FROM package_subscriptions WHERE id=$1`, id).Scan(&row.endsAt, &row.siteLimit,
		&row.domainLimit, &row.trafficLimit, &row.revision, &row.status); err != nil {
		t.Fatal(err)
	}
	return row
}

func mustSync(t *testing.T, svc *Service, grants ...grant.Grant) []Outcome {
	t.Helper()
	out, err := svc.Sync(t.Context(), grants)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newTestService(t *testing.T, pool *pgxpool.Pool, now func() time.Time) *Service {
	t.Helper()
	tokens, err := identity.NewTokenManager(strings.Repeat("k", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	subs := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, now))
	return New(pool, ids, subs, Config{}).WithClock(now)
}

func exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

var shared struct {
	once  sync.Once
	pool  *pgxpool.Pool
	err   error
	close func()
}

func TestMain(m *testing.M) {
	code := m.Run()
	if shared.close != nil {
		shared.close()
	}
	os.Exit(code)
}

// marketSupplyPool migrates one schema per test process: a full migration
// takes many minutes on a loaded machine. MARKET_SUPPLY_TEST_SCHEMA keeps it
// between runs as well.
func marketSupplyPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	shared.once.Do(func() { shared.pool, shared.close, shared.err = openShared(databaseURL) })
	if shared.err != nil {
		t.Fatal(shared.err)
	}
	return shared.pool
}

func openShared(databaseURL string) (*pgxpool.Pool, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, nil, err
	}
	schema, keep := os.Getenv("MARKET_SUPPLY_TEST_SCHEMA"), true
	if schema == "" {
		schema, keep = "market_supply_test_"+strings.ReplaceAll(uuid.NewString(), "-", ""), false
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	closeAll := func(pool *pgxpool.Pool) func() {
		return func() {
			if pool != nil {
				pool.Close()
			}
			if !keep {
				_, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+identifier+" CASCADE")
			}
			admin.Close()
		}
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+identifier); err != nil {
		closeAll(nil)()
		return nil, nil, err
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		closeAll(nil)()
		return nil, nil, err
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		closeAll(nil)()
		return nil, nil, err
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		closeAll(pool)()
		return nil, nil, fmt.Errorf("migrate: %w", err)
	}
	return pool, closeAll(pool), nil
}
