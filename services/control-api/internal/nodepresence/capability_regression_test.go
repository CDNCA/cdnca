package nodepresence

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func capabilitySet(agentVersion string, values map[agentv1.CapabilityName]uint32) *agentv1.AgentCapabilities {
	result := &agentv1.AgentCapabilities{AgentVersion: agentVersion}
	for name, version := range values {
		result.Features = append(result.Features, &agentv1.Capability{Name: name, ApiVersion: version})
	}
	return result
}

// What a 1.0.33 agent declares (tcp/udp v3, CC v2, no CRS) and what 1.0.34
// declares (tcp/udp v4, CC v3, CRS).
var (
	declared133 = map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY: 3, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY: 3,
		agentv1.CapabilityName_CAPABILITY_NAME_CC: 2, agentv1.CapabilityName_CAPABILITY_NAME_WAF: 1,
	}
	declared134 = map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY: 4, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY: 4,
		agentv1.CapabilityName_CAPABILITY_NAME_CC: 3, agentv1.CapabilityName_CAPABILITY_NAME_WAF: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE: 1,
	}
)

// TestCapabilityRegressionAfterAgentRollback: a node whose last healthy
// deployment used TLS passthrough (tcp v4) and proof-of-work CC (CC v3), now
// on a 1.0.33 agent, reports both features with the declared versions; the
// same deployment on a 1.0.34 agent reports nothing, and ungated
// requirements never count.
func TestCapabilityRegressionAfterAgentRollback(t *testing.T) {
	scope, deployment, version := uuid.New(), uuid.New(), uuid.New()
	required := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 4},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 4},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 3},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 4},
	}
	got := capabilityRegressions(scope, deployment, version, required, capabilitySet("1.0.33", declared133))
	if len(got) != 2 {
		t.Fatalf("regressions = %+v", got)
	}
	l4, cc := got[0], got[1]
	if l4.Feature != FeatureL4TLSPassthrough || l4.Capability != "CAPABILITY_NAME_TCP_PROXY" || l4.Required != 4 || l4.Declared != 3 ||
		l4.AgentVersion != "1.0.33" || l4.ScopeID != scope || l4.DeploymentID != deployment || l4.ConfigVersionID != version {
		t.Fatalf("L4 regression = %+v", l4)
	}
	if cc.Feature != FeatureCCProofOfWork || cc.Required != 3 || cc.Declared != 2 {
		t.Fatalf("CC regression = %+v", cc)
	}
	if got := capabilityRegressions(scope, deployment, version, required, capabilitySet("1.0.34", declared134)); len(got) != 0 {
		t.Fatalf("1.0.34 node reported %+v", got)
	}
	crs := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 3}}
	if got := capabilityRegressions(scope, deployment, version, crs, capabilitySet("1.0.33", declared133)); len(got) != 1 ||
		got[0].Feature != FeatureWAFCRSModule || got[0].Declared != 0 {
		t.Fatalf("CRS regression = %+v", got)
	}
	extra := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 3}}
	if got := capabilityRegressions(scope, deployment, version, extra, capabilitySet("1.0.29", map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY: 2})); len(got) != 1 || got[0].Feature != FeatureL4AdditionalListeners {
		t.Fatalf("additional listener regression = %+v", got)
	}
}

// A node whose kernel or OpenResty stops passing the TOA probe no longer
// declares L4_TOA; a deployment that required it is reported.
func TestCapabilityRegressionWhenL4TOAIsLost(t *testing.T) {
	scope, deployment, version := uuid.New(), uuid.New(), uuid.New()
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 2}}
	got := capabilityRegressions(scope, deployment, version, required, capabilitySet("1.0.35", declared134))
	if len(got) != 1 || got[0].Feature != FeatureL4TOA || got[0].Required != 1 || got[0].Declared != 0 {
		t.Fatalf("TOA regression = %+v", got)
	}
	withTOA := map[agentv1.CapabilityName]uint32{agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA: 1}
	for name, value := range declared134 {
		withTOA[name] = value
	}
	if got := capabilityRegressions(scope, deployment, version, required, capabilitySet("1.0.35", withTOA)); len(got) != 0 {
		t.Fatalf("TOA node reported %+v", got)
	}
}
