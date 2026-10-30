package marketsubscribe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeMarket struct{ targets []marketclient.SupplyTarget }

func (f fakeMarket) SupplyTargets(context.Context) ([]marketclient.SupplyTarget, error) {
	return f.targets, nil
}

// fakeLeaf keeps the applied config per leaf; fail makes a leaf refuse.
type fakeLeaf struct {
	mu      sync.Mutex
	applied map[uuid.UUID]siteconf.Config
	sites   map[uuid.UUID]uuid.UUID
	block   map[uuid.UUID]bool
	failCom map[uuid.UUID]bool
	calls   []string
	// nodes is supply.site_status "nodes" per leaf (fix-mktsiteconf7 §1).
	nodes map[uuid.UUID]map[string]string
}

func (f *fakeLeaf) Call(_ context.Context, leaf Leaf, op string, _ []string, _ string, body any) (siteconf.Reply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+":"+leaf.LeafMemberID.String()[:4])
	switch op {
	case siteconf.OpPrepare:
		req := body.(siteconf.CommitRequest)
		if f.block[leaf.LeafMemberID] {
			return siteconf.Reply{Blockers: []siteconf.Blocker{{Code: "icp_unfiled"}}}, nil
		}
		return siteconf.Reply{OK: true, Digest: req.Config.Digest()}, nil
	case siteconf.OpCommit:
		req := body.(siteconf.CommitRequest)
		if f.failCom[leaf.LeafMemberID] {
			return siteconf.Reply{}, errors.New("leaf offline")
		}
		id, ok := f.sites[leaf.LeafMemberID]
		if !ok {
			id = uuid.New()
			f.sites[leaf.LeafMemberID] = id
		}
		f.applied[leaf.LeafMemberID] = req.Config
		return siteconf.Reply{OK: true, LeafSiteID: &id}, nil
	case siteconf.OpDelete:
		delete(f.applied, leaf.LeafMemberID)
		delete(f.sites, leaf.LeafMemberID)
		return siteconf.Reply{OK: true}, nil
	case siteconf.OpAbort:
		return siteconf.Reply{OK: true}, nil
	case siteconf.OpStatus:
		nodes, ok := f.nodes[leaf.LeafMemberID]
		if !ok {
			return siteconf.Reply{}, errors.New("leaf offline")
		}
		raw, _ := json.Marshal(map[string]any{"nodes": nodes})
		return siteconf.Reply{OK: true, Status: raw}, nil
	}
	return siteconf.Reply{}, errors.New("unexpected op " + op)
}

func TestApplyThreeStepWithRollback(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	platform, site := seedSite(t, pool)
	sub := uuid.New()
	leafA, leafB := uuid.New(), uuid.New()
	grantA, grantB := uuid.New(), uuid.New()
	market := fakeMarket{targets: []marketclient.SupplyTarget{
		{SubscriptionID: sub, Aggregate: true, FQDN: "g7k2abcdefgh.supply.example"},
		{SubscriptionID: sub, LeafMemberID: leafA, NodePoolRef: "pa", GrantID: &grantA},
		{SubscriptionID: sub, LeafMemberID: leafB, NodePoolRef: "pb", GrantID: &grantB},
	}}
	leaves := &fakeLeaf{applied: map[uuid.UUID]siteconf.Config{}, sites: map[uuid.UUID]uuid.UUID{},
		block: map[uuid.UUID]bool{}, failCom: map[uuid.UUID]bool{}}
	svc := New(pool, market, leaves)
	if n, err := svc.SyncTargets(ctx, platform); err != nil || n != 1 {
		t.Fatalf("sync = %d, %v", n, err)
	}
	var supply uuid.UUID
	var target string
	if err := pool.QueryRow(ctx, `SELECT id, target FROM site_supplies WHERE market_subscription_id=$1`, sub).Scan(&supply, &target); err != nil ||
		target != "g7k2abcdefgh.supply.example" {
		t.Fatalf("supply row: %q %v", target, err)
	}
	if _, err := svc.Apply(ctx, site, 1, config("203.0.113.1")); !errors.Is(err, ErrNoMarketBinding) {
		t.Fatalf("unbound site: %v", err)
	}
	if err := svc.Bind(ctx, site, supply, "primary", 10); err != nil {
		t.Fatal(err)
	}
	var effective int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_supply_bindings_effective WHERE site_id=$1 AND kind='market_subscription'`,
		site).Scan(&effective); err != nil || effective != 1 {
		t.Fatalf("effective market bindings = %d, %v", effective, err)
	}

	// Preview changes nothing and stores no revision.
	if p, err := svc.Preview(ctx, site, 1, config("203.0.113.1")); err != nil || p.Applied || len(p.Leaves) != 2 ||
		p.Leaves[0].State != "applied" || len(leaves.applied) != 0 {
		t.Fatalf("preview = %+v %v", p, err)
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_supply_config_revisions WHERE site_id=$1`, site).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("preview stored %d revisions, %v", stored, err)
	}
	if err := svc.Bind(ctx, uuid.New(), supply, "primary", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bind to unknown site: %v", err)
	}

	// Revision 1 everywhere.
	r1, err := svc.Apply(ctx, site, 1, config("203.0.113.1"))
	if err != nil || !r1.Applied || len(r1.Leaves) != 2 {
		t.Fatalf("revision 1 = %+v %v", r1, err)
	}

	// One leaf blocks at prepare: nothing changes anywhere.
	leaves.block[leafB] = true
	r2, err := svc.Apply(ctx, site, 2, config("203.0.113.2"))
	if err != nil || r2.Applied || r2.Leaves[1].State != "blocked" || r2.Leaves[0].State != "not_applied" {
		t.Fatalf("blocked revision = %+v %v", r2, err)
	}
	if leaves.applied[leafA].Origins[0].Host != "203.0.113.1" {
		t.Fatal("a blocked prepare must not touch any leaf")
	}
	leaves.block[leafB] = false

	// Leaf B fails at commit after A committed: A rolls back to revision 1.
	leaves.failCom[leafB] = true
	r3, err := svc.Apply(ctx, site, 3, config("203.0.113.3"))
	if err != nil || r3.Applied || r3.Leaves[0].State != "rolled_back" || r3.Leaves[1].State != "failed" {
		t.Fatalf("failed commit = %+v %v", r3, err)
	}
	if got := leaves.applied[leafA].Origins[0].Host; got != "203.0.113.1" {
		t.Fatalf("leaf A must be back on revision 1, runs %s", got)
	}
	var stateA string
	var revA int64
	if err := pool.QueryRow(ctx, `SELECT state, applied_revision FROM site_supply_leaf_sites WHERE site_id=$1 AND leaf_member_id=$2`,
		site, leafA).Scan(&stateA, &revA); err != nil || stateA != "applied" || revA != 1 {
		t.Fatalf("leaf A record = %s %d %v", stateA, revA, err)
	}
	leaves.failCom[leafB] = false
	if r, err := svc.Apply(ctx, site, 4, config("203.0.113.4")); err != nil || !r.Applied {
		t.Fatalf("recovery = %+v %v", r, err)
	}
	if _, err := svc.Apply(ctx, site, 3, config("203.0.113.3")); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("older revision accepted: %v", err)
	}

	// The market dropping the subscription suspends the supply but keeps bindings.
	svc.market = fakeMarket{}
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM site_supplies WHERE id=$1`, supply).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("supply status = %s %v", status, err)
	}
}

func TestFirstRevisionRollbackDeletesLeafSite(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	platform, site := seedSite(t, pool)
	sub, leafA, leafB, gA, gB := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	leaves := &fakeLeaf{applied: map[uuid.UUID]siteconf.Config{}, sites: map[uuid.UUID]uuid.UUID{},
		block: map[uuid.UUID]bool{}, failCom: map[uuid.UUID]bool{leafB: true}}
	svc := New(pool, fakeMarket{targets: []marketclient.SupplyTarget{
		{SubscriptionID: sub, Aggregate: true, FQDN: "x.supply.example"},
		{SubscriptionID: sub, LeafMemberID: leafA, NodePoolRef: "pa", GrantID: &gA},
		{SubscriptionID: sub, LeafMemberID: leafB, NodePoolRef: "pb", GrantID: &gB},
	}}, leaves)
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	var supply uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM site_supplies WHERE market_subscription_id=$1`, sub).Scan(&supply); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bind(ctx, site, supply, "primary", 10); err != nil {
		t.Fatal(err)
	}
	r, err := svc.Apply(ctx, site, 1, config("203.0.113.1"))
	if err != nil || r.Applied || r.Leaves[0].State != "rolled_back" {
		t.Fatalf("first revision = %+v %v", r, err)
	}
	if _, ok := leaves.sites[leafA]; ok {
		t.Fatal("first-revision rollback must delete the site on the leaf")
	}
	if !strings.Contains(strings.Join(leaves.calls, " "), siteconf.OpDelete) {
		t.Fatalf("calls = %v", leaves.calls)
	}
}

func config(origin string) siteconf.Config {
	return siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.subscriber.example"}, HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: origin, Port: 80}}}
}

func seedSite(t *testing.T, pool *pgxpool.Pool) (platform, site uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	tenant, scope, user := uuid.New(), uuid.New(), uuid.New()
	pkg, product := uuid.New(), uuid.New()
	site = uuid.New()
	domain := "s" + strings.ReplaceAll(site.String(), "-", "")[:12] + ".subscriber.example"
	type statement struct {
		q    string
		args []any
	}
	var statements []statement
	for _, st := range []statement{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'subscriber')`, []any{tenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scope, tenant}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'subscriber','hash')`,
			[]any{user, "sub" + strings.ReplaceAll(user.String(), "-", "")[:20]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scope, user}},
		// fix-nopkgpub4: a valid package, else the controller's subscriptions
		// take no push (TestNoValidPackageRefusesPlatformPush).
		{`SET LOCAL session_replication_role = replica`, nil},
		{`INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
			domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
			tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
		  VALUES($1,$2,$3,1,'{"revision":1,"name":"market","spec":{}}',100,100,100,0,now()-interval '1 hour',now()+interval '3650 days',
			'UTC','monthly',1,1,$4,$4,now(),now())`, []any{pkg, scope, product, user}},
		{`INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,created_at)
		  VALUES($1,1,$2,$3,'subscription_state',now())`, []any{pkg, scope, user}},
		{`SET LOCAL session_replication_role = origin`, nil},
		{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id,
			package_subscription_id,package_id)
		  VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,1,$5,$6)`,
			[]any{site, scope, user, domain, pkg, product}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{site}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{site}},
	} {
		statements = append(statements, st)
	}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, st := range statements {
			if _, err := tx.Exec(ctx, st.q, st.args...); err != nil {
				return fmt.Errorf("%.50s: %w", st.q, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return platform, site
}

// testPool needs a database already migrated through the site supply
// binding migration (MARKET_SUBSCRIBE_TEST_DATABASE_URL), e.g. a clone of a
// migrated template database; each test adds its own rows only.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("MARKET_SUBSCRIBE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MARKET_SUBSCRIBE_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var ok bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('site_supplies') IS NOT NULL`).Scan(&ok); err != nil || !ok {
		t.Skip("database is not migrated through site_supply_binding")
	}
	return pool
}

// singleLeaf binds a site to a one-leaf market supply.
func singleLeaf(t *testing.T, pool *pgxpool.Pool) (*Service, *fakeLeaf, uuid.UUID, uuid.UUID) {
	t.Helper()
	platform, site := seedSite(t, pool)
	sub, member, grant := uuid.New(), uuid.New(), uuid.New()
	leaves := &fakeLeaf{applied: map[uuid.UUID]siteconf.Config{}, sites: map[uuid.UUID]uuid.UUID{},
		block: map[uuid.UUID]bool{}, failCom: map[uuid.UUID]bool{}}
	svc := New(pool, fakeMarket{targets: []marketclient.SupplyTarget{
		{SubscriptionID: sub, Aggregate: true, FQDN: "one.supply.example"},
		{SubscriptionID: sub, LeafMemberID: member, NodePoolRef: "p1", GrantID: &grant},
	}}, leaves)
	if _, err := svc.SyncTargets(t.Context(), platform); err != nil {
		t.Fatal(err)
	}
	var supply uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM site_supplies WHERE market_subscription_id=$1`, sub).Scan(&supply); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bind(t.Context(), site, supply, "primary", 10); err != nil {
		t.Fatal(err)
	}
	return svc, leaves, site, member
}

// CORE-REV-01: one revision holds one config. The same content again reuses
// the confirmed result without any outbound call; other content under the
// same revision conflicts before anything is sent, and the stored snapshot,
// the receipt and the leaf all stay on the first content.
func TestSameRevisionHoldsOneConfig(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeaf(t, pool)
	if r, err := svc.Apply(t.Context(), site, 1, config("203.0.113.10")); err != nil || !r.Applied {
		t.Fatalf("first apply = %+v %v", r, err)
	}
	before := len(leaves.calls)
	if r, err := svc.Apply(t.Context(), site, 1, config("203.0.113.10")); err != nil || !r.Applied || len(leaves.calls) != before {
		t.Fatalf("same content replay = %+v %v, outbound %d", r, err, len(leaves.calls)-before)
	}
	if _, err := svc.Preview(t.Context(), site, 1, config("203.0.113.20")); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("preview with other content under revision 1: %v", err)
	}
	r, err := svc.Apply(t.Context(), site, 1, config("203.0.113.20"))
	if !errors.Is(err, ErrRevisionConflict) || r.Applied || len(leaves.calls) != before {
		t.Fatalf("other content under revision 1 = %+v %v, outbound %d", r, err, len(leaves.calls)-before)
	}
	var stored, receipt string
	if err := pool.QueryRow(t.Context(), `SELECT r.digest, l.applied_digest FROM site_supply_config_revisions r
		JOIN site_supply_leaf_sites l ON l.site_id=r.site_id AND l.leaf_member_id=$2 WHERE r.site_id=$1 AND r.revision=1`,
		site, member).Scan(&stored, &receipt); err != nil || stored != receipt {
		t.Fatalf("snapshot %s receipt %s %v", stored, receipt, err)
	}
	if got := leaves.applied[member].Origins[0].Host; got != "203.0.113.10" {
		t.Fatalf("leaf runs %s", got)
	}
}

// CORE-REV-01: two concurrent applies of one revision with different content:
// exactly one claims it.
func TestConcurrentSameRevisionOneWins(t *testing.T) {
	pool := testPool(t)
	svc, _, site, _ := singleLeaf(t, pool)
	errs := make(chan error, 2)
	for _, origin := range []string{"203.0.113.11", "203.0.113.12"} {
		go func() {
			_, err := svc.Apply(t.Context(), site, 1, config(origin))
			errs <- err
		}()
	}
	var ok, conflict int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrRevisionConflict):
			conflict++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("ok %d conflict %d", ok, conflict)
	}
}

// injectReceiptCheck makes site_supply_leaf_sites refuse rows of site that
// match cond; the returned func removes it (also on cleanup).
func injectReceiptCheck(t *testing.T, pool *pgxpool.Pool, site uuid.UUID, cond string) func() {
	t.Helper()
	name := "receipt_fail_" + strings.ReplaceAll(site.String(), "-", "")
	if _, err := pool.Exec(t.Context(), fmt.Sprintf(`ALTER TABLE site_supply_leaf_sites ADD CONSTRAINT %s CHECK (site_id <> '%s'::uuid OR NOT (%s))`,
		name, site, cond)); err != nil {
		t.Fatal(err)
	}
	dropped := false
	drop := func() {
		if !dropped {
			dropped = true
			if _, err := pool.Exec(context.Background(), "ALTER TABLE site_supply_leaf_sites DROP CONSTRAINT "+name); err != nil {
				t.Errorf("drop injected check: %v", err)
			}
		}
	}
	t.Cleanup(drop)
	return drop
}

// CORE-RECEIPT-02: when no receipt can be written at all, nothing is sent.
func TestReceiptIntentFailureSendsNothing(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, _ := singleLeaf(t, pool)
	injectReceiptCheck(t, pool, site, "true")
	if r, err := svc.Apply(t.Context(), site, 1, config("203.0.113.31")); err == nil || r.Applied || len(leaves.calls) != 0 {
		t.Fatalf("apply without receipts = %+v %v, calls %v", r, err, leaves.calls)
	}
}

// CORE-RECEIPT-02: the leaf commits but the final receipt cannot be saved.
// Apply must not report success: the leaf shows receipt_pending with its leaf
// site and the error is ErrReceiptPending. Once receipts can be written, the
// same revision and content completes it without a second leaf site.
func TestReceiptWriteFailureIsPending(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeaf(t, pool)
	drop := injectReceiptCheck(t, pool, site, "state = 'applied'")
	r, err := svc.Apply(t.Context(), site, 1, config("203.0.113.30"))
	if !errors.Is(err, ErrReceiptPending) || r.Applied || r.Reason != "receipt_pending" || len(r.Leaves) != 1 ||
		r.Leaves[0].State != "receipt_pending" || r.Leaves[0].LeafSiteID == nil || *r.Leaves[0].LeafSiteID != leaves.sites[member] {
		t.Fatalf("receipt failure = %+v %v", r, err)
	}
	leafSite := leaves.sites[member]
	drop()
	if r, err := svc.Apply(t.Context(), site, 1, config("203.0.113.30")); err != nil || !r.Applied {
		t.Fatalf("retry after receipt recovers = %+v %v", r, err)
	}
	var stored uuid.UUID
	var state string
	if err := pool.QueryRow(t.Context(), `SELECT leaf_site_id, state FROM site_supply_leaf_sites WHERE site_id=$1 AND leaf_member_id=$2`,
		site, member).Scan(&stored, &state); err != nil || stored != leafSite || state != "applied" || len(leaves.sites) != 1 {
		t.Fatalf("leaf site %s, stored %s %s %v", leafSite, stored, state, err)
	}
}
