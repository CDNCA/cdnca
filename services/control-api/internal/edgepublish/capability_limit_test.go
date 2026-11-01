package edgepublish

import (
	"crypto/sha256"
	"errors"
	"sort"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestNodePublicationCapabilitiesLimit(t *testing.T) {
	decode := func(features []*agentv1.Capability) error {
		value := &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "limit", OperatingSystem: "linux", Architecture: "amd64"}
		value.Features = features
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		_, err = decodeNodePublicationCapabilities(encoded, digest[:])
		return err
	}
	if err := decode(knownCapabilities()); err != nil {
		t.Fatalf("71 capabilities rejected: %v", err)
	}
	if err := decode(sequential(agentv1.MaxCapabilities + 1)); !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("129 capabilities accepted: %v", err)
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

func sequential(count int) []*agentv1.Capability {
	features := make([]*agentv1.Capability, 0, count)
	for name := 1; name <= count; name++ {
		features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName(name), ApiVersion: 1})
	}
	return features
}
