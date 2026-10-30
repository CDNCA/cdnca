package controlupgrade

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestRolloutCohortRequiresHomogeneousUpgradeCapableNodes(t *testing.T) {
	facts := []rolloutNodeCapabilityFact{
		rolloutCapabilityFact(t, planID(1), "1.4.0", "linux", "amd64", 2),
		rolloutCapabilityFact(t, planID(2), "1.4.0", "linux", "amd64", 2),
	}
	want := RolloutTargetCohort{Platform: "linux", Architecture: "amd64", CurrentVersion: "1.4.0",
		ProtocolVersion: 2, Targets: []PlanTarget{{NodeID: planID(1), AgentVersion: "1.4.0", ProtocolVersion: 2},
			{NodeID: planID(2), AgentVersion: "1.4.0", ProtocolVersion: 2}}}
	got, err := rolloutCohortFromFacts(facts)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("rolloutCohortFromFacts() = (%#v,%v), want %#v", got, err, want)
	}

	for _, test := range []struct {
		name   string
		mutate func([]rolloutNodeCapabilityFact)
	}{
		{"presence mismatch", func(values []rolloutNodeCapabilityFact) { values[1].PresenceVersion = "1.4.1" }},
		{"os mismatch", func(values []rolloutNodeCapabilityFact) {
			values[1] = rolloutCapabilityFact(t, planID(2), "1.4.0", "freebsd", "amd64", 3)
		}},
		{"architecture mismatch", func(values []rolloutNodeCapabilityFact) {
			values[1] = rolloutCapabilityFact(t, planID(2), "1.4.0", "linux", "arm64", 2)
		}},
		{"protocol mismatch", func(values []rolloutNodeCapabilityFact) {
			values[1] = rolloutCapabilityFact(t, planID(2), "1.4.0", "linux", "amd64", 1)
		}},
		{"digest mismatch", func(values []rolloutNodeCapabilityFact) { values[1].CapabilitySHA256[0] ^= 0xff }},
		{"missing upgrade capability", func(values []rolloutNodeCapabilityFact) {
			values[1] = rolloutCapabilityFactWithFeatures(t, planID(2), "1.4.0", "linux", "amd64", 2,
				[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}})
		}},
		{"upgrade capability v2", func(values []rolloutNodeCapabilityFact) {
			values[1] = rolloutCapabilityFactWithFeatures(t, planID(2), "1.4.0", "linux", "amd64", 2,
				[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 2}})
		}},
		{"duplicate capability", func(values []rolloutNodeCapabilityFact) {
			values[1] = rolloutCapabilityFactWithFeatures(t, planID(2), "1.4.0", "linux", "amd64", 2,
				[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1},
					{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := make([]rolloutNodeCapabilityFact, len(facts))
			for index := range facts {
				candidate[index] = facts[index]
				candidate[index].CapabilityBytes = append([]byte(nil), facts[index].CapabilityBytes...)
				candidate[index].CapabilitySHA256 = append([]byte(nil), facts[index].CapabilitySHA256...)
			}
			test.mutate(candidate)
			if _, err := rolloutCohortFromFacts(candidate); !errors.Is(err, ErrCohortIncompatible) {
				t.Fatalf("incompatible cohort error = %v", err)
			}
		})
	}
}

func rolloutCapabilityFact(t *testing.T, nodeID, version, platform, architecture string,
	protocol uint32) rolloutNodeCapabilityFact {
	t.Helper()
	return rolloutCapabilityFactWithFeatures(t, nodeID, version, platform, architecture, protocol,
		[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}})
}

func rolloutCapabilityFactWithFeatures(t *testing.T, nodeID, version, platform, architecture string,
	protocol uint32, features []*agentv1.Capability) rolloutNodeCapabilityFact {
	t.Helper()
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&agentv1.AgentCapabilities{
		AgentVersion: version, BuildId: "build-1", OperatingSystem: platform,
		Architecture: architecture, Features: features})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return rolloutNodeCapabilityFact{NodeID: nodeID, PresenceVersion: version,
		ProtocolVersion: protocol, CapabilityBytes: encoded, CapabilitySHA256: digest[:]}
}
