//go:build integration

package marketsupply

import (
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSupplyGroupSellerL2: the seller names one of its
// own usable L2 configurations on a supply group (any region: the group has
// none), never an unusable or foreign one; an edit that leaves l2_config_id
// out keeps it, "" clears it. The pool report marks the supply's nodes l2,
// the site of a subscription on the supply reaches the seller's L2 node, and
// a revision following the package on a supply without L2 is told it goes
// straight to the origin.
func TestSupplyGroupSellerL2(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	seller := seedSeller(t, pool, platform)
	caps := capabilitySnapshot(t, map[agentv1.CapabilityName]uint32{agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE: 1})
	l1 := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.5.1", "CN", "电信", caps, false)
	l2 := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.5.2", "CN", "联通", caps, false)
	other := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.5.3", "CN", "移动", caps, false)
	now := time.Now().UTC()
	config := func(name, region string, member *uuid.UUID, enabled bool) uuid.UUID {
		t.Helper()
		id := uuid.New()
		exec(t, pool, `INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'global','rr',$5,$5,$6,$6)`,
			id, platform, name, region, seller.UserID, now)
		if member != nil {
			exec(t, pool, `INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,enabled,created_by_user_id,updated_by_user_id,
				created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6,$7,$7)`, uuid.New(), platform, id, *member, enabled, seller.UserID, now)
		}
		return id
	}
	usable := config("supply-l2 华南", "华南", &l2, true)
	disabled := config("supply-l2 停用成员", "", &other, false)
	empty := config("supply-l2 无成员", "", nil, false)
	text := func(id uuid.UUID) *string { v := id.String(); return &v }

	groups := NewSupplyGroups(pool, nodescheduler.NewService(pool, time.Now), staticFeatures{})
	for _, bad := range []uuid.UUID{disabled, empty, uuid.New()} {
		if _, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "supply-l2", NodeIDs: []uuid.UUID{l1}, L2ConfigID: text(bad),
			IdempotencyKey: "supply-l2-bad-" + bad.String(), RequestID: "supply-l2-bad"}); !errors.Is(err, ErrSupplyL2Unusable) {
			t.Fatalf("unusable L2 %s: %v", bad, err)
		}
	}
	junk := "not-a-uuid"
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "supply-l2", NodeIDs: []uuid.UUID{l1}, L2ConfigID: &junk,
		IdempotencyKey: "supply-l2-junk", RequestID: "supply-l2-junk"}); !errors.Is(err, ErrSupplyInvalid) {
		t.Fatalf("malformed L2 id: %v", err)
	}
	group, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "supply-l2", NodeIDs: []uuid.UUID{l1}, L2ConfigID: text(usable),
		IdempotencyKey: "supply-l2-create", RequestID: "supply-l2-create"})
	if err != nil || group.L2ConfigID == nil || *group.L2ConfigID != usable {
		t.Fatalf("create with L2: %+v %v", group, err)
	}
	// An edit without l2_config_id keeps it.
	group, err = groups.Put(ctx, seller, SupplyGroupWrite{GroupID: group.ID, ExpectedRevision: group.Revision, Name: "supply-l2 改名",
		NodeIDs: []uuid.UUID{l1}, IdempotencyKey: "supply-l2-rename", RequestID: "supply-l2-rename"})
	if err != nil || group.L2ConfigID == nil || *group.L2ConfigID != usable {
		t.Fatalf("rename keeps L2: %+v %v", group, err)
	}
	if got, err := groups.Get(ctx, seller, group.ID); err != nil || got.L2ConfigID == nil || *got.L2ConfigID != usable {
		t.Fatalf("get: %+v %v", got, err)
	}
	options, err := groups.L2Options(ctx, seller)
	if err != nil {
		t.Fatal(err)
	}
	usableOf := map[uuid.UUID]bool{}
	for _, o := range options {
		usableOf[o.ID] = o.Usable
	}
	if !usableOf[usable] || usableOf[disabled] || usableOf[empty] || len(usableOf) < 3 {
		t.Fatalf("options %+v", options)
	}

	// The pool report marks the supply's nodes l2.
	market := &inventoryMarket{offers: []marketclient.OwnOffer{{Status: "listed", Components: []struct {
		Kind        string `json:"kind"`
		NodePoolRef string `json:"node_pool_ref"`
	}{{Kind: "own_pool", NodePoolRef: group.ID.String()}}}}}
	probe := marketprobe.New(pool, market, nil, marketprobe.Config{Plugins: groups, L2: groups}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	report := func() []marketclient.PoolNode {
		t.Helper()
		if err := probe.SyncInventory(ctx); err != nil {
			t.Fatal(err)
		}
		return market.reports[group.ID.String()]
	}
	if got := report(); len(got) != 1 || !got[0].L2 {
		t.Fatalf("report with L2 %+v", got)
	}

	// A subscription on the supply: its site reaches the seller's L2 node.
	svc := newTestService(t, pool, time.Now)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(), SubscriptionPath: []uuid.UUID{uuid.New()},
		NodePoolRef: group.ID.String(), LoadThresholds: spec.DefaultLoadFloor,
		Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared}, Allocation: spec.Allocation{HTTPPorts: 1, WebSocket: true},
		IssuedAt: now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	out := mustSync(t, svc, g)
	if out[0].Action != "opened" {
		t.Fatalf("sync %+v", out[0])
	}
	var owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, tenantPrefix+out[0].Key).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	site := uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,package_subscription_id,package_id) VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites),
			$2,$3,'supply-l2.market.example.test',ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3,$4,
			(SELECT product_id FROM package_subscriptions WHERE id=$4))`, site, out[0].TenantScopeID, owner, out[0].SubscriptionID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id,l2_mode) VALUES($1,'package')`, site); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,level) VALUES($1,1,'192.0.2.10',80,0)`, site)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	targets := func() []uuid.UUID {
		t.Helper()
		var nodes []uuid.UUID
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			nodes, err = edgeautopublish.SiteTargetNodeIDsTx(ctx, tx, out[0].TenantScopeID, site)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return nodes
	}
	if got := targets(); !slices.Contains(got, l1) || !slices.Contains(got, l2) {
		t.Fatalf("site targets %v, want L1 %s and the seller's L2 %s", got, l1, l2)
	}
	follow := siteconf.Config{Schema: siteconf.SchemaV1}
	off := siteconf.Config{Schema: siteconf.SchemaV1, Forwarding: &siteconf.Forwarding{L2Off: true}}
	if advisory, err := svc.l2Advisory(ctx, actor, g, follow); err != nil || len(advisory) != 0 {
		t.Fatalf("supply with L2: advisory %v %v", advisory, err)
	}

	// The seller clears the supply's L2: nodes report no l2, the site loses
	// the L2 node, and following the package is answered l2_unavailable.
	group, err = groups.Put(ctx, seller, SupplyGroupWrite{GroupID: group.ID, ExpectedRevision: group.Revision, Name: "supply-l2 改名",
		NodeIDs: []uuid.UUID{l1}, L2ConfigID: new(string), IdempotencyKey: "supply-l2-clear", RequestID: "supply-l2-clear"})
	if err != nil || group.L2ConfigID != nil {
		t.Fatalf("clear L2: %+v %v", group, err)
	}
	if got := report(); len(got) != 1 || got[0].L2 {
		t.Fatalf("report without L2 %+v", got)
	}
	if got := targets(); slices.Contains(got, l2) {
		t.Fatalf("site targets %v still hold the L2 node", got)
	}
	if advisory, err := svc.l2Advisory(ctx, actor, g, follow); err != nil ||
		!slices.Equal(advisory, []siteconf.Blocker{{Code: BlockerL2Unavailable}}) {
		t.Fatalf("supply without L2: advisory %v %v", advisory, err)
	}
	if advisory, err := svc.l2Advisory(ctx, actor, g, off); err != nil || len(advisory) != 0 {
		t.Fatalf("L2 off: advisory %v %v", advisory, err)
	}

	// An ordinary line group keeps the 504 region rule (629 relaxes supply groups only).
	scheduler, admin := platformScheduler(t, pool, platform)
	general := func(region, key string) error {
		_, err := scheduler.PutGroup(ctx, admin, nodescheduler.PutGroupRequest{GroupID: uuid.New(), Name: key, Region: region,
			Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: []nodescheduler.Endpoint{{ID: uuid.New(), NodeID: l1,
				Address: "8.8.5.1", Port: 80, Weight: 1, Enabled: true}}, L2ConfigID: &usable, IdempotencyKey: key, RequestID: key})
		return err
	}
	if err := general("华北", "supply-l2-general-north"); !errors.Is(err, nodescheduler.ErrInvalidInput) {
		t.Fatalf("ordinary group of another region: %v", err)
	}
	if err := general("华南", "supply-l2-general-south"); err != nil {
		t.Fatalf("ordinary group of the configuration's region: %v", err)
	}
}
