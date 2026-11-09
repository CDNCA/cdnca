package gatewayclient

import (
	"sort"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestAgentCapabilityLimitIsShared128(t *testing.T) {
	features := func(count int) []*agentv1.Capability {
		values := make([]*agentv1.Capability, 0, count)
		for name := 1; name <= count; name++ {
			values = append(values, &agentv1.Capability{Name: agentv1.CapabilityName(name), ApiVersion: 1})
		}
		return values
	}
	// All 71 named capabilities (what 1.0.35 nodes report) must pass config
	// validation and still leave room for the two capabilities the client adds.
	config := testClientConfig(t.TempDir())
	config.Capabilities.Features = knownCapabilities()
	if err := config.validate(); err != nil {
		t.Fatalf("71 capabilities rejected: %v", err)
	}
	// Without the two client-added capabilities the node still reports 70,
	// above the old 64 cutoff: both must be appended, ending at 76 (CHALLENGE_POW 81, SITE_SELECTION 82, PACKAGING_TOOLSET_REPORT 83).
	capabilities := &agentv1.AgentCapabilities{}
	for _, feature := range knownCapabilities() {
		if feature.Name != agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY &&
			feature.Name != agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT {
			capabilities.Features = append(capabilities.Features, feature)
		}
	}
	if err := ensureActiveConfigIdentityCapability(capabilities); err != nil {
		t.Fatalf("active identity capability not added beyond 64: %v", err)
	}
	if err := ensureDeploymentStatusAckReceiptCapability(capabilities); err != nil {
		t.Fatalf("ack receipt capability not added beyond 64: %v", err)
	}
	if len(capabilities.Features) != 76 {
		t.Fatalf("capabilities=%d, want 76", len(capabilities.Features))
	}
	config.Capabilities.Features = features(agentv1.MaxCapabilities + 1)
	if err := config.validate(); err == nil {
		t.Fatal("129 capabilities accepted")
	}
	full := &agentv1.AgentCapabilities{Features: features(agentv1.MaxCapabilities)}
	for _, feature := range full.Features {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY {
			feature.Name = agentv1.CapabilityName(1000)
		}
	}
	if err := ensureActiveConfigIdentityCapability(full); err == nil {
		t.Fatal("capability appended past the shared limit")
	}
}

// knownCapabilities lists every named capability; 1.0.35 nodes report all 71.
func knownCapabilities() []*agentv1.Capability {
	names := make([]int, 0, len(agentv1.CapabilityName_name))
	for name := range agentv1.CapabilityName_name {
		if name != 0 {
			names = append(names, int(name))
		}
	}
	sort.Ints(names)
	features := make([]*agentv1.Capability, 0, len(names))
	for _, name := range names {
		features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName(name), ApiVersion: 1})
	}
	return features
}
