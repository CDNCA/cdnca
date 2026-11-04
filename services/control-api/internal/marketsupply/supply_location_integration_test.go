//go:build integration

package marketsupply

import (
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// TestSupplyGroupRefusesUnmappedCarrier (PG): a node had
// region CN and no ISP; its supply group was made with an empty carrier and
// the pool was never reported. Now the node is refused when added; once its
// IP 归属 has a carrier the same request succeeds and the endpoint carries it.
func TestSupplyGroupRefusesUnmappedCarrier(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	seller := seedSeller(t, pool, platform)
	caps := capabilitySnapshot(t, map[agentv1.CapabilityName]uint32{agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE: 1})
	node := seedSupplyNode(t, pool, platform, seller.UserID, "11.0.0.118", "CN", "", caps, false)
	groups := NewSupplyGroups(pool, nodescheduler.NewService(pool, time.Now), staticFeatures{})
	_, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "测试", NodeIDs: []uuid.UUID{node}, IdempotencyKey: "fpr-1", RequestID: "fpr-1"})
	var unmapped *LocationUnmappedError
	if !errors.As(err, &unmapped) || len(unmapped.Nodes) != 1 || unmapped.Nodes[0].NodeID != node || unmapped.Nodes[0].Fields[0] != "carrier" {
		t.Fatalf("empty carrier: %v", err)
	}
	exec(t, pool, `UPDATE nodes SET management_settings=jsonb_set(management_settings,'{ip_location,isp}','"中国电信"') WHERE id=$1`, node)
	group, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "测试", NodeIDs: []uuid.UUID{node}, IdempotencyKey: "fpr-2", RequestID: "fpr-2"})
	if err != nil || len(group.Nodes) != 1 || group.Nodes[0].Carrier != "中国电信" {
		t.Fatalf("after the carrier is set: %+v %v", group, err)
	}
}
