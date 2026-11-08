package gateway

import (
	"sort"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// sequentialCapabilities returns count capabilities named 1..count (names past
// the known enum are fine: the size check runs before name validation).
func sequentialCapabilities(count int) []*agentv1.Capability {
	features := make([]*agentv1.Capability, 0, count)
	for name := 1; name <= count; name++ {
		features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName(name), ApiVersion: 1})
	}
	return features
}

func TestHelloCapabilityLimitIsShared128(t *testing.T) {
	if agentv1.MaxCapabilities != 128 || DefaultConfig().MaxCapabilities != agentv1.MaxCapabilities {
		t.Fatalf("gateway capability limit=%d shared=%d", DefaultConfig().MaxCapabilities, agentv1.MaxCapabilities)
	}
	gateway := testCacheGateway(t)
	const sizeError = "hello capabilities are missing or exceed their size limit"
	hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
	hello.Capabilities.Features = allNamedCapabilities()
	if err := gateway.validateHello(hello); err != nil && strings.Contains(err.Error(), sizeError) {
		t.Fatalf("74 capabilities hit the size limit: %v", err)
	}
	hello.Capabilities.Features = sequentialCapabilities(agentv1.MaxCapabilities + 1)
	if err := gateway.validateHello(hello); err == nil || !strings.Contains(err.Error(), sizeError) {
		t.Fatalf("129 capabilities accepted or wrong error: %v", err)
	}
}

func TestSessionFactsCapabilityLimit(t *testing.T) {
	hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
	hello.Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64", Features: allNamedCapabilities()}
	selected := versionRange(1, 0).Maximum
	if facts := newGatewaySessionFacts(nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, 1, selected, hello); facts == nil || len(facts.GetCapabilities().GetFeatures()) != 74 {
		t.Fatal("74 capabilities did not produce session facts")
	}
	hello.Capabilities.Features = sequentialCapabilities(agentv1.MaxCapabilities + 1)
	if facts := newGatewaySessionFacts(nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, 1, selected, hello); facts != nil {
		t.Fatal("129 capabilities produced session facts")
	}
}

// allNamedCapabilities lists every named capability; 1.0.35 nodes report all 74 (CHALLENGE_POW 81).
func allNamedCapabilities() []*agentv1.Capability {
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
