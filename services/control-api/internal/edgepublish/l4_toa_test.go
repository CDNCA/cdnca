package edgepublish

import (
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A toa stream requires tcp v8 (agents before it decode toa strictly) and
// L4_TOA v1 (the node's TOA probe passed) on both publication paths, and a
// target without them is refused before anything is persisted, naming every
// such node.
func TestL4TOARequiresL4TOAAndNamesEveryNodeWithoutIt(t *testing.T) {
	stream := l4V2ContractStream("tcp")
	stream.ProxyProtocolOutbound, stream.ProxyProtocolInbound = false, false
	stream.Geo.TrustedProxyCIDRs = []string{}
	stream.TOA = true
	if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, stream); err != nil {
		t.Fatal(err)
	}
	versions := map[agentv1.CapabilityName]uint32{}
	for _, capability := range siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{stream}) {
		versions[capability.Name] = capability.ApiVersion
	}
	if versions[agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA] != 1 || versions[agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY] != 12 {
		t.Fatalf("toa capabilities = %v, want L4_TOA v1 and tcp v12", versions)
	}
	if feature, gated := gatedFeature(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 8}); !gated ||
		!strings.Contains(feature, "TOA") {
		t.Fatalf("tcp v8 gated feature = %q, %v", feature, gated)
	}
	plain := stream
	plain.TOA = false
	for _, capability := range siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{plain}) {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA {
			t.Fatal("stream without toa requires L4_TOA")
		}
	}

	document := siteRuntimeV2Document{}
	bindSiteRuntimeV2Streams(&document, uuid.MustParse(stream.TenantID), []snapshotStream{{RuntimeV2: &stream}}, nil)
	if !slices.Contains(document.RequiredCapabilities, siteRuntimeV2Capability{Name: "l4_toa", APIVersion: 1}) ||
		!slices.Contains(document.RequiredCapabilities, siteRuntimeV2Capability{Name: "tcp", APIVersion: 12}) {
		t.Fatalf("site runtime toa capabilities = %v", document.RequiredCapabilities)
	}
	if name, ok := siteruntimecap.Name("l4_toa"); !ok || name != agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA {
		t.Fatalf("l4_toa maps to %v, %v", name, ok)
	}

	withTOA := append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA, ApiVersion: 1})
	first, second, ready := uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		uuid.MustParse("00000000-0000-4000-8000-000000000002"), uuid.MustParse("00000000-0000-4000-8000-000000000003")
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA, ApiVersion: 1}}
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		first:  {AgentVersion: "1.0.35", Features: edge134Features()},
		second: {AgentVersion: "1.0.35", Features: edge134Features()},
		ready:  {AgentVersion: "1.0.35", Features: withTOA},
	}
	err := capabilityTargetsError([]uuid.UUID{ready, first, second}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || refusal.NodeID != first ||
		len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != second ||
		!strings.Contains(err.Error(), "TOA") || !strings.Contains(err.Error(), "PROXY protocol") ||
		strings.Contains(err.Error(), ready.String()) {
		t.Fatalf("toa on two nodes without L4_TOA: %v (%+v)", err, refusal)
	}
	if err := capabilityTargetsError([]uuid.UUID{ready}, required, sessions); err != nil {
		t.Fatalf("toa on an L4_TOA node: %v", err)
	}
}
