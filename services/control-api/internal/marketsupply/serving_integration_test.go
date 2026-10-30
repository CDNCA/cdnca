//go:build integration

package marketsupply

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// ML-11b: subscribers of a supply group, and a
// sold pool stays reported to the market after its offers are delisted.
func TestSupplyServingSubscribersOnlineAndDelisted(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	seller := seedSeller(t, pool, platform)
	caps := capabilitySnapshot(t, map[agentv1.CapabilityName]uint32{agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE: 1})
	a := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.5.1", "CN", "电信", caps, false)
	b := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.5.2", "CN", "联通", caps, false)
	exec(t, pool, `UPDATE node_presence SET status='offline', offline_since=now() WHERE node_id=$1`, b)
	groups := NewSupplyGroups(pool, nodescheduler.NewService(pool, time.Now), staticFeatures{})
	sold, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "ml11b 已售", NodeIDs: []uuid.UUID{a, b}, IdempotencyKey: "ml11b-sold", RequestID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	unsold, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "ml11b 未售", NodeIDs: []uuid.UUID{a}, IdempotencyKey: "ml11b-unsold", RequestID: "u"})
	if err != nil {
		t.Fatal(err)
	}

	// A market grant on the sold pool opens a hidden subscription.
	now := time.Now().UTC()
	svc := newTestService(t, pool, time.Now)
	outcomes := mustSync(t, svc, grant.Grant{
		Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(), SubscriptionPath: []uuid.UUID{uuid.New()},
		NodePoolRef: sold.ID.String(), LoadThresholds: spec.DefaultLoadFloor,
		Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared}, Allocation: spec.Allocation{HTTPPorts: 2},
		IssuedAt: now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix(),
	})
	if outcomes[0].Action != "opened" {
		t.Fatalf("sync %+v", outcomes[0])
	}
	if n, err := groups.PoolSubscribers(ctx, sold.ID); err != nil || n != 1 {
		t.Fatalf("sold subscribers %d %v", n, err)
	}
	if n, err := groups.PoolSubscribers(ctx, unsold.ID); err != nil || n != 0 {
		t.Fatalf("unsold subscribers %d %v", n, err)
	}

	// Both offers delisted: the sold pool keeps its nodes, the other is cleared.
	component := func(ref string) []struct {
		Kind        string `json:"kind"`
		NodePoolRef string `json:"node_pool_ref"`
	} {
		return []struct {
			Kind        string `json:"kind"`
			NodePoolRef string `json:"node_pool_ref"`
		}{{Kind: "own_pool", NodePoolRef: ref}}
	}
	market := &inventoryMarket{offers: []marketclient.OwnOffer{
		{Status: "delisted", Components: component(sold.ID.String())},
		{Status: "delisted", Components: component(unsold.ID.String())},
	}}
	probe := marketprobe.New(pool, market, nil, marketprobe.Config{Plugins: groups, Serving: groups}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := probe.SyncInventory(ctx); err != nil {
		t.Fatal(err)
	}
	// Not cleared: both nodes still reported (health is the market's DNS selection).
	if got := market.reports[sold.ID.String()]; len(got) != 2 {
		t.Fatalf("sold delisted pool %+v, want its nodes kept", got)
	}
	if got, reported := market.reports[unsold.ID.String()]; !reported || len(got) != 0 {
		t.Fatalf("unsold delisted pool %+v %v, want cleared", got, reported)
	}
}
