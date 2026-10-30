package marketsubscribe

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeSites serves a saved site; the test edits it between calls.
type fakeSites struct{ current site.Site }

func (f *fakeSites) Get(_ context.Context, _ site.Actor, id uuid.UUID) (site.Site, error) {
	if id != f.current.ID {
		return site.Site{}, site.ErrNotFound
	}
	return f.current, nil
}

// MC12 E2: choosing a site compiles its saved version; the revision number
// and digest come from the server, apply sends exactly what preview showed,
// and the apply is audited.
func TestSiteRolloutCompilesSavedSite(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	platform, siteID := seedSite(t, pool)
	sub, leaf, grant := uuid.New(), uuid.New(), uuid.New()
	market := fakeMarket{targets: []marketclient.SupplyTarget{
		{SubscriptionID: sub, Aggregate: true, FQDN: "s2rollout.supply.example"},
		{SubscriptionID: sub, LeafMemberID: leaf, NodePoolRef: "pa", GrantID: &grant},
	}}
	leaves := &fakeLeaf{applied: map[uuid.UUID]siteconf.Config{}, sites: map[uuid.UUID]uuid.UUID{},
		block: map[uuid.UUID]bool{}, failCom: map[uuid.UUID]bool{}}
	saved := baseSite()
	saved.ID, saved.Domain, saved.Domains = siteID, "shop.example.test", []string{"shop.example.test"}
	sites := &fakeSites{current: saved}
	svc := New(pool, market, leaves).WithSites(sites)
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	var supply uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM site_supplies WHERE market_subscription_id=$1`, sub).Scan(&supply); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bind(ctx, siteID, supply, "primary", 10); err != nil {
		t.Fatal(err)
	}
	bindings, err := svc.SiteBindings(ctx, siteID)
	if err != nil || len(bindings) != 1 || bindings[0].SupplyID != supply || bindings[0].Role != "primary" || bindings[0].Leaves != 1 {
		t.Fatalf("bindings = %+v %v", bindings, err)
	}
	// audit_events.actor_user_id references users: act as the seeded owner.
	actor := site.Actor{ScopeID: platform, ScopeKind: "platform"}
	if err := pool.QueryRow(ctx, `SELECT owner_user_id FROM sites WHERE id=$1`, siteID).Scan(&actor.UserID); err != nil {
		t.Fatal(err)
	}

	preview, err := svc.PreviewSite(ctx, actor, siteID)
	if err != nil || preview.Result == nil || preview.Plan.Revision != 1 || preview.Plan.SiteVersion != 7 ||
		len(preview.Plan.Unsupported) != 0 || len(leaves.applied) != 0 {
		t.Fatalf("preview = %+v %v", preview, err)
	}
	// The site is saved again after the preview: apply refuses the old one.
	sites.current.Revision = 8
	sites.current.OriginPool.Origins[0].Host = "203.0.113.99"
	if out, err := svc.ApplySite(ctx, actor, siteID, 7, preview.Plan.Digest); !errors.Is(err, ErrSiteChanged) ||
		out.Plan.SiteVersion != 8 || len(leaves.applied) != 0 {
		t.Fatalf("stale apply = %+v %v", out.Plan, err)
	}
	fresh, err := svc.PreviewSite(ctx, actor, siteID)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := svc.ApplySite(ctx, actor, siteID, 8, fresh.Plan.Digest)
	// siteconf sorts origins by host:port (Normalize), so look the edited one up.
	if err != nil || applied.Result == nil || !applied.Result.Applied ||
		!slices.ContainsFunc(leaves.applied[leaf].Origins, func(o siteconf.Origin) bool { return o.Host == "203.0.113.99" }) {
		t.Fatalf("apply = %+v %v", applied, err)
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='site.market_rollout.apply' AND resource_id=$1
		AND result='success'`, siteID.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audit events = %d, %v", audited, err)
	}
	// Same saved site again: same revision (idempotent), not a new one.
	again, err := svc.PlanSite(ctx, actor, siteID)
	if err != nil || again.Revision != 1 || again.Digest != fresh.Plan.Digest {
		t.Fatalf("unchanged plan = %+v %v", again, err)
	}
	sites.current.Revision = 9
	sites.current.OriginPool.ConnectTimeoutMS = 5000
	if next, err := svc.PlanSite(ctx, actor, siteID); err != nil || next.Revision != 2 {
		t.Fatalf("changed plan = %+v %v", next, err)
	}

	// A disabled site still blocks: no leaf asked. (Local cache rules,
	// ACL/CC policies and conditional origins are compiled, fix-mktsiteconf:
	// compile_local_test.go.)
	sites.current.Enabled = false
	calls := len(leaves.calls)
	blocked, err := svc.PreviewSite(ctx, actor, siteID)
	if err != nil || blocked.Result != nil || len(blocked.Plan.Unsupported) != 1 || blocked.Plan.Unsupported[0].Code != "site_disabled" ||
		len(leaves.calls) != calls {
		t.Fatalf("blocked = %+v %v", blocked.Plan, err)
	}
	if _, err := svc.PreviewSite(ctx, actor, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown site: %v", err)
	}
}

// auditTx appends to audit_events in the caller's tx (fixture only).
type auditTx struct{}

func (auditTx) Append(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	_, err := audit.AppendTx(ctx, tx, event)
	return err
}

// fix-mktsiteconf: the site's local cache policy is compiled into the
// revision's cache block instead of blocking the rollout.
func TestSiteRolloutCompilesLocalCachePolicy(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	_, siteID := seedSite(t, pool)
	saved := baseSite()
	saved.ID, saved.Domain, saved.Domains = siteID, "cache.example.test", []string{"cache.example.test"}
	svc := New(pool, fakeMarket{}, &fakeLeaf{}).WithSites(&fakeSites{current: saved})
	var scope, tenant, owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT s.scope_id,a.tenant_id,s.owner_user_id FROM sites s JOIN access_scopes a ON a.id=s.scope_id
		WHERE s.id=$1`, siteID).Scan(&scope, &tenant, &owner); err != nil {
		t.Fatal(err)
	}
	document := cachecontrol.PolicyDocument{SchemaVersion: cachecontrol.PolicySchemaV2, Mode: cachecontrol.PolicyOverride,
		QueryMode: cachecontrol.QueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: 1 << 30,
		Rules: []cachecontrol.Rule{{Order: 1, Extensions: []string{".css"}, Action: cachecontrol.RuleActionCache, TTLSeconds: 600}}}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := cachecontrol.CreateForNewSiteTx(ctx, tx, auditTx{}, cachecontrol.Actor{UserID: owner, ScopeID: scope, ActorScopeID: scope},
			tenant, siteID, document, "fix-mktsiteconf-cache", time.Now())
		return err
	}); err != nil {
		t.Fatalf("cache policy fixture: %v", err)
	}
	plan, err := svc.PlanSite(ctx, site.Actor{UserID: owner, ScopeID: scope, ScopeKind: "tenant"}, siteID)
	if err != nil || len(plan.Unsupported) != 0 {
		t.Fatalf("plan = %+v %v", plan, err)
	}
	cache, err := plan.Config.DecodeCache()
	if err != nil || cache == nil || cache.Mode != "override" || len(cache.Rules) != 1 || cache.Rules[0].Extensions[0] != ".css" ||
		cache.Rules[0].TTLSeconds != 600 {
		t.Fatalf("cache = %+v %v", cache, err)
	}
}

// fix-mktsiteconf2 ①: the site access settings are compiled into
// site_access; basic auth blocks the rollout (its secrets are site hashes).
func TestSiteRolloutCompilesSiteAccess(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	_, siteID := seedSite(t, pool)
	saved := baseSite()
	saved.ID, saved.Domain, saved.Domains = siteID, "access.example.test", []string{"access.example.test"}
	svc := New(pool, fakeMarket{}, &fakeLeaf{}).WithSites(&fakeSites{current: saved})
	var scope, owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scope_id,owner_user_id FROM sites WHERE id=$1`, siteID).Scan(&scope, &owner); err != nil {
		t.Fatal(err)
	}
	write := func(settings string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO site_access_settings(scope_id,site_id,settings,updated_by_user_id,updated_at)
			VALUES($1,$2,$3,$4,now()) ON CONFLICT(site_id) DO UPDATE SET settings=EXCLUDED.settings`,
			scope, siteID, settings, owner); err != nil {
			t.Fatal(err)
		}
	}
	actor := site.Actor{UserID: owner, ScopeID: scope, ScopeKind: "tenant"}
	write(`{"compression":{"enabled":true,"types":["text/html"]}}`)
	// Compression always carries min_length_bytes (edgeconfig.SiteCompression,
	// 0 = node default); the planned block is canonical JSON (sorted keys).
	plan, err := svc.PlanSite(ctx, actor, siteID)
	if err != nil || len(plan.Unsupported) != 0 || string(plan.Config.SiteAccess) != `{"compression":{"enabled":true,"min_length_bytes":0,"types":["text/html"]}}` {
		t.Fatalf("plan = %+v access=%s %v", plan.Unsupported, plan.Config.SiteAccess, err)
	}
	// fix-mktsiteconf4: basic auth travels as the stored salted hashes.
	// Written in jsonb key order (salt, sha256, username) so the substring check
	// below matches the stored settings carried as they are.
	user := `{"salt":"` + strings.Repeat("a", 32) + `","sha256":"` + strings.Repeat("b", 64) + `","username":"u"}`
	write(`{"basic_auth":{"realm":"r","users":[` + user + `]}}`)
	if plan, err = svc.PlanSite(ctx, actor, siteID); err != nil || len(plan.Unsupported) != 0 ||
		!strings.Contains(string(plan.Config.SiteAccess), user) {
		t.Fatalf("basic auth plan = %+v access=%s %v", plan.Unsupported, plan.Config.SiteAccess, err)
	}
}

// fix-mktsiteconf3 ③: the site's enabled HTTP policy is compiled into
// http_policy instead of blocking the rollout.
func TestSiteRolloutCompilesHTTPPolicy(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	_, siteID := seedSite(t, pool)
	saved := baseSite()
	saved.ID, saved.Domain, saved.Domains = siteID, "http.example.test", []string{"http.example.test"}
	svc := New(pool, fakeMarket{}, &fakeLeaf{}).WithSites(&fakeSites{current: saved})
	var scope, owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scope_id,owner_user_id FROM sites WHERE id=$1`, siteID).Scan(&scope, &owner); err != nil {
		t.Fatal(err)
	}
	// The system site write records the owner as the revision actor (056 wants
	// http_policies.manage): the seeded owner gets a tenant_owner system role
	// (056's roles trigger grants the HTTP policy permissions).
	role := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`,
		role, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scope, owner, role); err != nil {
		t.Fatal(err)
	}
	config, err := httppolicycontrol.NewSitePolicyConfig(1<<20, []httppolicycontrol.HeaderAction{{Kind: "set", Name: "X-From", Values: []string{"cdn"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := httppolicycontrol.NewStore(pool).SetSiteSystem(ctx, httppolicycontrol.SystemSiteWrite{ScopeID: scope, SiteID: siteID,
		OwnerUserID: owner, Config: &config, RequestID: "fix-mktsiteconf3-http", ActorRef: "job:test"}); err != nil {
		t.Fatalf("http policy fixture: %v", err)
	}
	plan, err := svc.PlanSite(ctx, site.Actor{UserID: owner, ScopeID: scope, ScopeKind: "tenant"}, siteID)
	if err != nil || len(plan.Unsupported) != 0 || !strings.Contains(string(plan.Config.HTTPPolicy), `"name":"x-from"`) { // header names are stored lower-case
		t.Fatalf("plan = %+v http=%s %v", plan.Unsupported, plan.Config.HTTPPolicy, err)
	}
}
