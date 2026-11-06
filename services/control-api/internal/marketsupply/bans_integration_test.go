package marketsupply

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
)

type banCarrier struct{ published [][]byte }

func (c *banCarrier) PublishList(_ context.Context, _ string, _ uint64, encoded []byte) error {
	c.published = append(c.published, append([]byte(nil), encoded...))
	return nil
}
func (*banCarrier) NextReceipt(context.Context) (securityban.ReceiptDelivery, error) { return nil, nil }

type banReceipt struct{ report *agentv1.SecurityBanStatus }

func (r banReceipt) Status() *agentv1.SecurityBanStatus { return r.report }
func (banReceipt) Ack(context.Context) error             { return nil }
func (banReceipt) Nak(context.Context) error             { return nil }

// TestHandleBanSyncToLeafNodes: the subscriber's snapshot for its
// market site lands on the grant's own leaf site, goes to the platform node
// serving it, and the reply reports refusals and that node; another tenant's
// site, a leaf site other than the one the leaf recorded, a held supply and
// an ended subscription are refused, and the sweep lifts the subscriber's
// bans when its supply is held or its subscription ended.
func TestHandleBanSyncToLeafNodes(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	svc := newTestService(t, pool, clock)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		IssuedAt: now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}
	leafSite := insertTenantSite(t, tenant, "bans-"+uuid.NewString()[:8]+".example.cn")
	exec(t, pool, `UPDATE sites SET node_group_id=$2 WHERE id=$1`, leafSite, poolID)
	var node uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT node_id FROM node_line_endpoints WHERE line_group_id=$1`, poolID).Scan(&node); err != nil {
		t.Fatal(err)
	}

	subscriberSite := uuid.New()
	revision := now.UnixMilli()
	ban := bansync.Ban{Ref: uuid.New(), Client: "198.51.100.60", Until: now.Add(10 * time.Minute).Unix(), Source: "manual", Reason: "scan"}
	call := func(leaf uuid.UUID, bans ...bansync.Ban) (siteconf.Reply, bansync.Status) {
		t.Helper()
		revision++
		raw, _ := json.Marshal(bansync.Request{SiteID: subscriberSite, LeafSiteID: leaf, Revision: revision, Bans: bans})
		reply, err := svc.Handle(ctx, envelope.Header{MessageID: uuid.New(), GrantID: g.GrantID, Operation: bansync.OpSync}, raw)
		if err != nil {
			t.Fatal(err)
		}
		var status bansync.Status
		if reply.OK && json.Unmarshal(reply.Status, &status) != nil {
			t.Fatalf("status %s", reply.Status)
		}
		return reply, status
	}
	if reply, _ := call(leafSite, ban); reply.OK || reply.Error != bansync.ErrCodeUnavailable {
		t.Fatalf("without a ban list = %+v", reply)
	}

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &banCarrier{}
	distributor, err := securityban.NewDistributor(securityban.DistributorConfig{Pool: pool, Transport: carrier, KeyID: "k",
		Sign: func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Minute, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	store := securityban.NewStore(pool, clock)
	svc.WithBanList(store, distributor)

	reply, status := call(leafSite, ban)
	if !reply.OK || reply.Revision != revision || status.Accepted != 1 || len(status.Refused) != 0 ||
		status.Nodes.State != bansync.NodesDelivering || status.Nodes.Total != 1 {
		t.Fatalf("first snapshot = %+v %+v", reply, status)
	}
	if err := distributor.PublishOnce(ctx); err != nil || len(carrier.published) != 1 {
		t.Fatalf("publish = %d, %v", len(carrier.published), err)
	}
	list, err := contract.Open(carrier.published[0], node.String(),
		func(id string) (ed25519.PublicKey, bool) { return public, id == "k" })
	if err != nil || len(list.Bans) != 1 || list.Bans[0].SiteID != leafSite.String() || list.Bans[0].Client != "198.51.100.60" {
		t.Fatalf("node list = %+v, %v", list, err)
	}
	distributor.HandleReceipt(ctx, banReceipt{&agentv1.SecurityBanStatus{NodeId: node.String(), Revision: list.Revision,
		ListSha256: contract.Digest(carrier.published[0]), Applied: true, Bans: 1}})
	if reply, status = call(leafSite, ban); !reply.OK || status.Nodes.State != bansync.NodesApplied || status.Nodes.Applied != 1 {
		t.Fatalf("after the receipt = %+v %+v", reply, status)
	}

	// Another tenant's site, or not the leaf site recorded for the subscriber site.
	otherTenant, err := svc.ensureTenant(ctx, actor, "0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	foreign := insertTenantSite(t, otherTenant, "foreign-"+uuid.NewString()[:8]+".example.cn")
	if reply, _ = call(foreign, ban); reply.OK || reply.Error != bansync.ErrCodeSiteNotFound {
		t.Fatalf("foreign site = %+v", reply)
	}
	sibling := insertTenantSite(t, tenant, "sibling-"+uuid.NewString()[:8]+".example.cn")
	if err := svc.saveApplied(ctx, tenant, subscriberSite, &sibling, 1, 1, 0); err != nil {
		t.Fatal(err)
	}
	if reply, _ = call(leafSite, ban); reply.OK || reply.Error != bansync.ErrCodeSiteNotFound {
		t.Fatalf("not the recorded leaf site = %+v", reply)
	}
	if err := svc.saveApplied(ctx, tenant, subscriberSite, &leafSite, 1, 1, 0); err != nil {
		t.Fatal(err)
	}
	active := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_ban_entries WHERE site_id=$1 AND source='market'
			AND released_at IS NULL AND banned_until > $2`, leafSite, now).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Paused supply: DNS only, the nodes still serve, so snapshots apply and bans stay.
	tag, err := pool.Exec(ctx, `UPDATE market_supply_limits SET hold_action='pause' WHERE tenant_scope_id=$1`, tenant.scopeID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("pause: %v rows=%d", err, tag.RowsAffected())
	}
	if reply, _ = call(leafSite, ban); !reply.OK {
		t.Fatalf("paused supply refused = %+v", reply)
	}
	if err := svc.sweepBans(ctx, nil); err != nil || active() != 1 {
		t.Fatalf("sweep of a paused supply: active=%d err=%v", active(), err)
	}

	// Stopped supply: refused, and the sweep lifts the subscriber's bans.
	tag, err = pool.Exec(ctx, `UPDATE market_supply_limits SET hold_action='stop' WHERE tenant_scope_id=$1`, tenant.scopeID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("hold: %v rows=%d", err, tag.RowsAffected())
	}
	if reply, _ = call(leafSite, ban); reply.OK || reply.Error != bansync.ErrCodePaused {
		t.Fatalf("held supply = %+v", reply)
	}
	if active() != 1 {
		t.Fatal("ban gone before the sweep")
	}
	if err := svc.sweepBans(ctx, nil); err != nil || active() != 0 {
		t.Fatalf("sweep of a held supply: active=%d err=%v", active(), err)
	}
	exec(t, pool, `UPDATE market_supply_limits SET hold_action=NULL WHERE tenant_scope_id=$1`, tenant.scopeID)
	if reply, status = call(leafSite, ban); !reply.OK || len(status.Refused) != 0 || active() != 1 {
		t.Fatalf("served again = %+v %+v active=%d", reply, status, active())
	}

	// The subscription's grant is gone from the market: refused and lifted.
	mustSync(t, svc)
	if reply, _ = call(leafSite, ban); reply.OK || reply.Error != bansync.ErrCodeEnded {
		t.Fatalf("ended subscription = %+v", reply)
	}
	if _, err := svc.RefreshLimits(ctx, nil); err != nil {
		t.Fatalf("refresh limits: %v", err)
	}
	if active() != 0 {
		t.Fatalf("ended subscription still bans: %d", active())
	}
}
