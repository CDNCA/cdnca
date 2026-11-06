package securityban

import (
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/google/uuid"
)

func TestDeliveryOfShowsTheWorstLeaf(t *testing.T) {
	entry := uuid.New()
	accepted := func(nodes string) LeafBanDelivery {
		return LeafBanDelivery{State: "accepted", Accepted: map[uuid.UUID]bool{entry: true}, Refused: map[uuid.UUID]string{},
			Nodes: bansync.Nodes{State: nodes}}
	}
	if got := deliveryOf(entry, 2, nil); got != nil {
		t.Fatalf("own nodes only = %+v", got)
	}
	if got := deliveryOf(entry, 0, nil); got == nil || got.State != DeliveryNoNodes {
		t.Fatalf("no nodes at all = %+v", got)
	}
	for name, c := range map[string]struct {
		leaves        []LeafBanDelivery
		state, reason string
		effective     int
	}{
		"all effective": {[]LeafBanDelivery{accepted(bansync.NodesApplied), accepted(bansync.NodesApplied)}, DeliveryEffective, "", 2},
		"one delivering": {[]LeafBanDelivery{accepted(bansync.NodesApplied), accepted(bansync.NodesDelivering)},
			DeliveryDelivering, "", 1},
		"never sent": {[]LeafBanDelivery{accepted(bansync.NodesApplied), {}}, DeliveryPending, "", 1},
		"refused wins": {[]LeafBanDelivery{{State: "accepted", Accepted: map[uuid.UUID]bool{},
			Refused: map[uuid.UUID]string{entry: bansync.RefuseTenantLimit}}, {State: "unsupported", Reason: "peer_unsupported"}},
			DeliveryRefused, bansync.RefuseTenantLimit, 0},
		"rate limited is pending": {[]LeafBanDelivery{{State: "accepted", Accepted: map[uuid.UUID]bool{},
			Refused: map[uuid.UUID]string{entry: bansync.RefuseRateLimited}}}, DeliveryPending, bansync.RefuseRateLimited, 0},
		"snapshot rate limited keeps nodes": {[]LeafBanDelivery{{State: "rejected", Reason: bansync.ErrCodeRateLimited,
			Accepted: map[uuid.UUID]bool{entry: true}, Nodes: bansync.Nodes{State: bansync.NodesApplied}}}, DeliveryEffective, "", 1},
		"paused": {[]LeafBanDelivery{{State: "rejected", Reason: bansync.ErrCodePaused}}, DeliveryRefused, bansync.ErrCodePaused, 0},
		"node failed": {[]LeafBanDelivery{{State: "accepted", Accepted: map[uuid.UUID]bool{entry: true},
			Nodes: bansync.Nodes{State: bansync.NodesFailed, Reason: "runtime_unavailable"}}}, DeliveryFailed, "runtime_unavailable", 0},
		"no leaf node": {[]LeafBanDelivery{accepted(bansync.NodesNone)}, DeliveryNoNodes, "", 0},
		"leaf distribution off": {[]LeafBanDelivery{accepted(bansync.NodesOff)}, DeliveryNoNodes, bansync.NodesOff, 0},
	} {
		got := deliveryOf(entry, 0, c.leaves)
		if got == nil || got.State != c.state || got.Reason != c.reason || got.Effective != c.effective || got.Leaves != len(c.leaves) {
			t.Errorf("%s: %+v", name, got)
		}
	}
}
