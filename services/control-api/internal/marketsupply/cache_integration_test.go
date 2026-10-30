package marketsupply

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestApplyCachePublishesAsTenantOwnerOnce drives the real cachecontrol store
// on a site of a market tenant: the first commit publishes, a retried or
// unchanged commit does not stack revisions, a change publishes again, and a
// config without cache leaves the policy alone.
func TestApplyCachePublishesAsTenantOwnerOnce(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, func() time.Time { return now })
	store, err := cachecontrol.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	svc.WithCache(store)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(), Limits: spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}
	leafSite := insertTenantSite(t, tenant, "cache-"+uuid.NewString()[:8]+".example.cn")

	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.cn"}, HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: "203.0.113.20", Port: 80}},
		Cache: json.RawMessage(`{"mode":"override","rules":[{"extensions":["jpg","png"],"action":"cache","ttl_seconds":3600,
			"browser_ttl_seconds":600},{"path_prefix":"/api/","action":"no_cache"}],"query_mode":"ignore"}`)}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if blockers := svc.cacheBlockers(cfg); len(blockers) != 0 {
		t.Fatalf("valid cache blocked: %+v", blockers)
	}
	request := siteconf.CommitRequest{SiteID: uuid.New(), Revision: 1, Config: cfg}
	if err := svc.applyCache(ctx, tenant, leafSite, request); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	owner := cachecontrol.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ActorScopeID: tenant.scopeID}
	policy, err := store.GetPolicy(ctx, owner, leafSite, 0)
	if err != nil || policy.Revision != 1 || policy.Document.Mode != cachecontrol.PolicyOverride ||
		len(policy.Document.Rules) != 2 || policy.Document.Rules[0].Extensions[0] != ".jpg" ||
		policy.Document.QueryMode != cachecontrol.QueryIgnore || policy.Document.DiskQuotaBytes != defaultCacheQuota {
		t.Fatalf("published %+v %v", policy, err)
	}
	// A retried commit and a later revision with the same cache do not publish.
	for _, revision := range []int64{1, 2} {
		request.Revision = revision
		if err := svc.applyCache(ctx, tenant, leafSite, request); err != nil {
			t.Fatalf("repeat apply %d: %v", revision, err)
		}
	}
	if policy, _ := store.GetPolicy(ctx, owner, leafSite, 0); policy.Revision != 1 {
		t.Fatalf("unchanged cache stacked revisions: %d", policy.Revision)
	}
	changed := cfg
	changed.Cache = json.RawMessage(`{"mode":"follow_origin"}`)
	if err := changed.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := svc.applyCache(ctx, tenant, leafSite, siteconf.CommitRequest{SiteID: request.SiteID, Revision: 3, Config: changed}); err != nil {
		t.Fatalf("change: %v", err)
	}
	if policy, _ := store.GetPolicy(ctx, owner, leafSite, 0); policy.Revision != 2 || policy.Document.Mode != cachecontrol.PolicyFollowOrigin {
		t.Fatalf("changed policy %+v", policy)
	}
	unmanaged := cfg
	unmanaged.Cache = nil
	if err := svc.applyCache(ctx, tenant, leafSite, siteconf.CommitRequest{SiteID: request.SiteID, Revision: 4, Config: unmanaged}); err != nil {
		t.Fatal(err)
	}
	if policy, _ := store.GetPolicy(ctx, owner, leafSite, 0); policy.Revision != 2 {
		t.Fatalf("absent cache touched the policy: %d", policy.Revision)
	}

	invalid := cfg
	invalid.Cache = json.RawMessage(`{"mode":"override"}`) // override needs at least one rule
	if err := invalid.Normalize(); err != nil {
		t.Fatal(err)
	}
	if blockers := svc.cacheBlockers(invalid); len(blockers) != 1 || blockers[0].Code != "cache_invalid" {
		t.Fatalf("invalid cache blockers %+v", blockers)
	}
	svc.cache = nil
	if blockers := svc.cacheBlockers(cfg); len(blockers) != 1 || blockers[0].Code != "unsupported_cache" {
		t.Fatalf("cache without a writer %+v", blockers)
	}
	if err := svc.applyCache(ctx, tenant, leafSite, request); err == nil {
		t.Fatal("apply without a writer succeeded")
	}
	// A site this tenant does not own is out of reach.
	svc.cache = store
	if err := svc.applyCache(ctx, tenant, uuid.New(), request); !errors.Is(err, cachecontrol.ErrNotFound) {
		t.Fatalf("unknown site: %v", err)
	}
}

// insertTenantSite adds a minimal active site to the tenant's scope, the way
// the cachecontrol fixtures do; site creation itself is covered elsewhere.
func insertTenantSite(t *testing.T, tenant tenantRef, domain string) uuid.UUID {
	t.Helper()
	pool := marketSupplyPool(t)
	id := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `WITH display AS (
				INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
				ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1
				RETURNING next_value-1 AS value)
			INSERT INTO sites (id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,
			origin_hosts,https_enabled,enabled,status,created_by_user_id,updated_by_user_id,display_id)
			SELECT $1,$2,$3,$4,$5,$6,$7,$7,false,true,'active',$3,$3,display.value FROM display`,
			id, tenant.scopeID, tenant.userID, domain,
			[]string{"80"}, []string{}, []string{"203.0.113.20"}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools (site_id) VALUES ($1)`, id); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
			VALUES ($1,1,'203.0.113.20',80,1,true)`, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}
