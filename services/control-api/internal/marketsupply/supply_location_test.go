package marketsupply

import (
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
)

// A node the seller adds whose IP 归属 has no market region
// or carrier is refused with the field to fix; a node already in the group
// is not checked again.
func TestUnmappedNodesNamesTheFieldsToFix(t *testing.T) {
	ok, noCarrier, noRegion, kept, hk := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	nodes := []SupplyGroupNode{
		{NodeID: ok, Region: "CN", Carrier: "中国电信"},
		// Outside the mainland the carrier is not needed (overseas line).
		{NodeID: hk, Region: "HK", Carrier: ""},
		{NodeID: noCarrier, Name: "118", Region: "CN", Carrier: ""},
		{NodeID: noRegion, Region: "", Carrier: "Cogent"},
		{NodeID: kept, Region: "CN", Carrier: ""},
	}
	got := unmappedNodes(nodes, func(id uuid.UUID) bool { return id != kept })
	if len(got) != 2 || got[0].NodeID != noCarrier || !slices.Equal(got[0].Fields, []string{"carrier"}) || got[0].Name != "118" ||
		got[1].NodeID != noRegion || !slices.Equal(got[1].Fields, []string{"region"}) {
		t.Fatalf("unmapped %+v", got)
	}
	err := error(&LocationUnmappedError{Nodes: got})
	var typed *LocationUnmappedError
	if !errors.Is(err, ErrSupplyLocationUnmapped) || !errors.As(err, &typed) || len(typed.Nodes) != 2 {
		t.Fatalf("error %v", err)
	}
}
