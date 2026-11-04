//go:build integration

package marketsupply

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// 节点列表要能看出节点还在隐藏的市场供货组里，删除被拒时说明是哪个供货组、
// 有几个有效订阅。两节点供货组 + 一个正常的本地市场订阅：节点清单（List/Get）带出去掉前缀的
// 供货组名；删除任一节点返回 market_supply 原因，normal_subscriptions=1、group_nodes=2。
func TestNodeListShowsMarketSupplyAndDeleteNamesIt(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	seller := seedSeller(t, pool, platform)
	caps := capabilitySnapshot(t, map[agentv1.CapabilityName]uint32{agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE: 1})
	first := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.6.1", "CN", "电信", caps, false)
	second := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.6.2", "CN", "联通", caps, false)
	outside := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.6.3", "CN", "移动", caps, false)
	groups := NewSupplyGroups(pool, nodescheduler.NewService(pool, time.Now), staticFeatures{})
	group, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "节点列表组", NodeIDs: []uuid.UUID{first, second},
		IdempotencyKey: "node-list-group", RequestID: "node-list-group"})
	if err != nil {
		t.Fatal(err)
	}
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(), SubscriptionPath: []uuid.UUID{uuid.New()},
		NodePoolRef: group.ID.String(), LoadThresholds: spec.DefaultLoadFloor,
		IssuedAt: time.Now().Add(-time.Hour).Unix(), NotBefore: time.Now().Add(-time.Hour).Unix(),
		NotAfter: time.Now().Add(24 * time.Hour).Unix()}
	if out := mustSync(t, newTestService(t, pool, time.Now), g); out[0].Action != "opened" {
		t.Fatalf("sync %+v", out)
	}

	inventory := nodepresence.NewInventory(pool, nil, time.Minute, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	listed, err := inventory.List(ctx, nodepresence.InventoryListRequest{ScopeID: platform, Limit: node.MaxListLimit})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID][]nodepresence.MarketSupplyGroupRef{}
	for _, item := range listed.Items {
		seen[item.ID] = item.MarketSupplyGroups
	}
	for _, id := range []uuid.UUID{first, second} {
		if got := seen[id]; len(got) != 1 || got[0].ID != group.ID || got[0].Name != "节点列表组" {
			t.Fatalf("listed supply groups of %s = %+v", id, got)
		}
	}
	if got, ok := seen[outside]; !ok || got != nil {
		t.Fatalf("node outside the supply listed with %+v (present %v)", got, ok)
	}
	single, err := inventory.Get(ctx, platform, first)
	if err != nil || len(single.MarketSupplyGroups) != 1 || single.MarketSupplyGroups[0].Name != "节点列表组" {
		t.Fatalf("get supply groups = %+v %v", single.MarketSupplyGroups, err)
	}

	nodes := node.NewService(node.NewStoreWithClock(pool, time.Now, nil))
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM nodes WHERE id=$1`, first).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	retired := node.StateRetired
	_, err = nodes.UpdateNode(ctx, node.Actor{UserID: seller.UserID, ScopeID: platform}, node.UpdateRequest{ID: first,
		ExpectedRevision: revision, Fields: node.UpdateFields{AdminState: &retired}, IdempotencyKey: "node-list-delete", RequestID: "node-list-delete"})
	var inUse *node.InUseError
	if !errors.As(err, &inUse) || len(inUse.Reasons) != 1 {
		t.Fatalf("delete supply node: %v", err)
	}
	reason := inUse.Reasons[0]
	if reason.Kind != node.InUseMarketSupply || reason.ID != group.ID.String() || reason.Name != "节点列表组" ||
		reason.NormalSubscriptions == nil || *reason.NormalSubscriptions != 1 || reason.GroupNodes == nil || *reason.GroupNodes != 2 {
		t.Fatalf("market supply reason = %+v", reason)
	}
}
