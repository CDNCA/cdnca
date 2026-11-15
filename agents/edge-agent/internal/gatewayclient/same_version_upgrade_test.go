package gatewayclient

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type sameVersionTestUpgrades struct{ UpgradeRuntime }

// The capability and installed_release_sequence reach only a
// Gateway that listed SAME_VERSION_UPGRADE; an older Gateway sees neither.
func TestSameVersionUpgradeDeclaredOnlyToKnowingGateway(t *testing.T) {
	client := &Client{upgrades: sameVersionTestUpgrades{}, installedReleaseSequence: 17}
	older := &agentv1.GatewayHello{KnownCapabilities: []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE}}
	if client.learnSameVersionUpgrade(older) {
		t.Fatal("learned from a Gateway that does not know the capability")
	}
	capabilities := &agentv1.AgentCapabilities{}
	client.declareSameVersionUpgrade(capabilities)
	if len(capabilities.Features) != 0 || capabilities.InstalledReleaseSequence != 0 {
		t.Fatalf("declared to an older Gateway: %v", capabilities)
	}
	knowing := &agentv1.GatewayHello{KnownCapabilities: []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_SAME_VERSION_UPGRADE}}
	if !client.learnSameVersionUpgrade(knowing) || client.learnSameVersionUpgrade(knowing) {
		t.Fatal("must learn exactly once (one reconnect)")
	}
	client.declareSameVersionUpgrade(capabilities)
	client.declareSameVersionUpgrade(capabilities)
	if len(capabilities.Features) != 1 || capabilities.Features[0].ApiVersion != 1 || capabilities.InstalledReleaseSequence != 17 {
		t.Fatalf("declared capabilities = %v", capabilities)
	}
	for name, other := range map[string]*Client{
		"no installed sequence": {upgrades: sameVersionTestUpgrades{}},
		"no upgrade runtime":    {installedReleaseSequence: 17},
	} {
		if other.learnSameVersionUpgrade(knowing) {
			t.Fatalf("%s: learned", name)
		}
	}
}
