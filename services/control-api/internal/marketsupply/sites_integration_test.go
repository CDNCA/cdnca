package marketsupply

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

type fakeSites struct {
	sites   map[uuid.UUID]site.Site
	creates []site.CreateRequest
	updates int
}

func (f *fakeSites) Create(_ context.Context, actor site.Actor, r site.CreateRequest) (site.WriteResult, error) {
	if actor.ScopeKind != "platform" || actor.SessionID == uuid.Nil {
		return site.WriteResult{}, site.ErrPermissionDenied
	}
	f.creates = append(f.creates, r)
	s := site.Site{ID: uuid.New(), ScopeID: r.TargetScopeID, Domains: r.Fields.Domains, Enabled: true, Revision: 1}
	f.sites[s.ID] = s
	return site.WriteResult{Site: s}, nil
}

func (f *fakeSites) Update(_ context.Context, _ site.Actor, r site.UpdateRequest) (site.WriteResult, error) {
	s := f.sites[r.ID]
	if s.Revision != r.ExpectedRevision {
		return site.WriteResult{}, site.ErrRevisionConflict
	}
	s.Revision++
	s.Domains = r.Fields.Domains
	f.sites[r.ID] = s
	f.updates++
	return site.WriteResult{Site: s}, nil
}

func (f *fakeSites) UpdateOrigin(_ context.Context, _ site.Actor, r site.UpdateOriginRequest) (site.WriteResult, error) {
	s := f.sites[r.ID]
	if s.Revision != r.ExpectedRevision {
		return site.WriteResult{}, site.ErrRevisionConflict
	}
	s.Revision++
	f.sites[r.ID] = s
	return site.WriteResult{Site: s}, nil
}

func (f *fakeSites) Delete(_ context.Context, _ site.Actor, r site.DeleteRequest) (site.DeleteResult, error) {
	delete(f.sites, r.ID)
	return site.DeleteResult{}, nil
}

func (f *fakeSites) Get(_ context.Context, _ site.Actor, id uuid.UUID) (site.Site, error) {
	s, ok := f.sites[id]
	if !ok {
		return site.Site{}, site.ErrNotFound
	}
	return s, nil
}

func TestHandleSiteLifecycle(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Date(2026, time.October, 17, 8, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fake := &fakeSites{sites: map[uuid.UUID]site.Site{}}
	filed := map[string]bool{"www.example.cn": true}
	svc := newTestService(t, pool, clock)
	svc.cfg.CNAMEDomain = "cdn.leaf.example.net"
	svc.WithSites(fake, func(_ context.Context, host string) (bool, error) { return filed[host], nil })
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 2}, Compliance: spec.Compliance{RequireICP: true},
		IssuedAt: now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	if out := mustSync(t, svc, g); out[0].Action != "opened" {
		t.Fatalf("sync = %+v", out[0])
	}

	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.cn"}, HTTPPorts: []int{80},
		HTTPSPorts: []int{443}, Origins: []siteconf.Origin{{Host: "203.0.113.20", Port: 8080}}}
	siteID := uuid.New()
	call := func(op string, domains []string, body any) siteconf.Reply {
		t.Helper()
		raw, _ := json.Marshal(body)
		reply, err := svc.Handle(ctx, envelope.Header{MessageID: uuid.New(), GrantID: g.GrantID, Operation: op,
			Domains: domains}, raw)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return reply
	}

	if r := call(siteconf.OpPrepare, []string{"other.example.cn"},
		siteconf.CommitRequest{SiteID: siteID, Revision: 1, Config: cfg}); r.OK || r.Error != ErrHeaderDomains.Error() {
		t.Fatalf("header mismatch = %+v", r)
	}
	cached := cfg
	cached.Cache = json.RawMessage(`{"mode":"follow_origin"}`)
	if r := call(siteconf.OpPrepare, cached.Domains, siteconf.CommitRequest{SiteID: siteID, Revision: 1, Config: cached}); r.OK ||
		codes(r.Blockers) != "unsupported_cache" {
		t.Fatalf("cache without a cache writer = %+v", r)
	}
	unfiled := cfg
	unfiled.Domains = []string{"www.example.cn", "shop.example.cn"}
	unfiled.WebSocket = true
	r := call(siteconf.OpPrepare, unfiled.Domains, siteconf.CommitRequest{SiteID: siteID, Revision: 1, Config: unfiled})
	if r.OK || codes(r.Blockers) != "icp_unfiled,websocket_not_allowed" {
		t.Fatalf("blocked prepare = %+v", r)
	}

	prep := call(siteconf.OpPrepare, cfg.Domains, siteconf.CommitRequest{SiteID: siteID, Revision: 1, Config: cfg})
	if !prep.OK || prep.Digest == "" {
		t.Fatalf("prepare = %+v", prep)
	}
	if r := call(siteconf.OpCommit, cfg.Domains,
		siteconf.CommitRequest{SiteID: siteID, Revision: 1, Digest: "x", Config: cfg}); r.Error != ErrDigest.Error() {
		t.Fatalf("wrong digest = %+v", r)
	}
	commit := call(siteconf.OpCommit, cfg.Domains,
		siteconf.CommitRequest{SiteID: siteID, Revision: 1, Digest: prep.Digest, Config: cfg})
	if !commit.OK || commit.LeafSiteID == nil || len(fake.creates) != 1 {
		t.Fatalf("commit = %+v creates=%d", commit, len(fake.creates))
	}
	created := fake.creates[0]
	if created.Fields.PackageSubscriptionID == nil || created.Fields.NodeGroupID == nil || *created.Fields.NodeGroupID != poolID ||
		!created.Fields.HTTPSEnabled || created.Fields.Origins[0] != "203.0.113.20:8080" {
		t.Fatalf("site fields = %+v", created.Fields)
	}
	var tenantScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_scope_id FROM package_subscriptions WHERE id=$1`,
		*created.Fields.PackageSubscriptionID).Scan(&tenantScope); err != nil || tenantScope != created.TargetScopeID {
		t.Fatalf("site must land in the grant's tenant: %v %v", tenantScope, err)
	}

	next := cfg
	next.Origins = []siteconf.Origin{{Host: "203.0.113.21", Port: 80}}
	prep2 := call(siteconf.OpPrepare, next.Domains, siteconf.CommitRequest{SiteID: siteID, Revision: 2, Config: next})
	if r := call(siteconf.OpCommit, next.Domains, siteconf.CommitRequest{SiteID: siteID, LeafSiteID: commit.LeafSiteID,
		Revision: 2, Digest: prep2.Digest, Config: next}); !r.OK || *r.LeafSiteID != *commit.LeafSiteID || fake.updates != 1 {
		t.Fatalf("update commit = %+v", r)
	}

	foreign := site.Site{ID: uuid.New(), ScopeID: uuid.New(), Revision: 1}
	fake.sites[foreign.ID] = foreign
	if r := call(siteconf.OpDelete, nil, siteconf.SiteRef{SiteID: uuid.New(), LeafSiteID: foreign.ID}); r.Error != ErrForeignSite.Error() {
		t.Fatalf("foreign delete = %+v", r)
	}
	if r := call(siteconf.OpStatus, nil, siteconf.SiteRef{SiteID: siteID, LeafSiteID: *commit.LeafSiteID}); !r.OK || len(r.Status) == 0 {
		t.Fatalf("status = %+v", r)
	} else {
		// fix-mktsiteconf7 §1: the fake site has no sync status, so it is on its way.
		var status struct{ Nodes NodeDelivery }
		if err := json.Unmarshal(r.Status, &status); err != nil || status.Nodes.State != NodeDeliveryDelivering ||
			status.Nodes.Reason != NodeReasonSiteSyncing {
			t.Fatalf("status nodes = %+v, %v", status.Nodes, err)
		}
	}
	if r := call(siteconf.OpDelete, nil, siteconf.SiteRef{SiteID: siteID, LeafSiteID: *commit.LeafSiteID}); !r.OK {
		t.Fatalf("delete = %+v", r)
	}
	if _, ok := fake.sites[*commit.LeafSiteID]; ok {
		t.Fatal("site not deleted")
	}
	if r := call(siteconf.OpPurge, nil, siteconf.PurgeRequest{}); r.Error != ErrUnsupportedOp.Error() {
		t.Fatalf("purge = %+v", r)
	}

	now = now.Add(25 * time.Hour)
	if r := call(siteconf.OpPrepare, cfg.Domains, siteconf.CommitRequest{SiteID: siteID, Revision: 3, Config: cfg}); r.Error != ErrGrantInactive.Error() {
		t.Fatalf("expired grant = %+v", r)
	}
	if r, _ := svc.Handle(ctx, envelope.Header{GrantID: uuid.New(), Operation: siteconf.OpPrepare}, nil); r.Error != ErrUnknownGrant.Error() {
		t.Fatalf("unknown grant = %+v", r)
	}
}

func codes(in []siteconf.Blocker) string {
	out := make([]string, len(in))
	for i, b := range in {
		out[i] = b.Code
	}
	return strings.Join(out, ",")
}
