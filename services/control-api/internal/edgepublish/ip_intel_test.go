package edgepublish

import (
	"errors"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// IP_INTEL v2 (signed library format v2) is a gated capability: a release
// requiring it names every target node that does not declare it.
func TestIPIntelV2IsGatedAndNamesNodesWithoutIt(t *testing.T) {
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: IPIntelAPIVersion}}
	if feature, gated := gatedFeature(required[0]); !gated || !strings.Contains(feature, "IP 情报库") {
		t.Fatalf("IP_INTEL v2 gated=%v feature=%q", gated, feature)
	}
	withIPIntel := append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 2})
	withV1 := append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 1})
	first, second, ready := uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		uuid.MustParse("00000000-0000-4000-8000-000000000002"), uuid.MustParse("00000000-0000-4000-8000-000000000003")
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		first:  {AgentVersion: "1.0.35", Features: edge134Features()},
		second: {AgentVersion: "1.0.35", Features: withV1},
		ready:  {AgentVersion: "1.0.36", Features: withIPIntel},
	}
	err := capabilityTargetsError([]uuid.UUID{ready, first, second}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || refusal.NodeID != first ||
		refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL || refusal.Required != IPIntelAPIVersion ||
		len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != second || strings.Contains(err.Error(), ready.String()) {
		t.Fatalf("IP_INTEL release on nodes without v2: %v (%+v)", err, refusal)
	}
	if err := capabilityTargetsError([]uuid.UUID{ready}, required, sessions); err != nil {
		t.Fatalf("IP_INTEL release on an IP_INTEL v2 node: %v", err)
	}
}

// The library readiness check only runs for releases requiring IP_INTEL; any
// other release never reads node deployments.
func TestIPIntelReadinessSkippedWithoutIPIntelRequirement(t *testing.T) {
	if requiresIPIntel([]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_JA4, ApiVersion: 1}}) {
		t.Fatal("a JA4-only release requires the IP intelligence library")
	}
	if !requiresIPIntel([]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: IPIntelAPIVersion}}) {
		t.Fatal("an IP_INTEL release does not require the IP intelligence library")
	}
}
