package edgepublish

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestNodePublicationCapabilitiesDecode(t *testing.T) {
	valid := &agentv1.AgentCapabilities{
		AgentVersion: "1.0.0", BuildId: "publication-test", OperatingSystem: "linux", Architecture: "amd64",
		Features: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		},
	}
	slices.SortFunc(valid.Features, func(a, b *agentv1.Capability) int { return int(a.Name - b.Name) })
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 100, protowire.VarintType), 1)
	for _, test := range []struct {
		name   string
		mutate func(*agentv1.AgentCapabilities)
	}{
		{"valid", func(*agentv1.AgentCapabilities) {}},
		{"unknown_root", func(v *agentv1.AgentCapabilities) { v.ProtoReflect().SetUnknown(unknown) }},
		{"unknown_feature", func(v *agentv1.AgentCapabilities) { v.Features[0].ProtoReflect().SetUnknown(unknown) }},
		{"unknown_enum", func(v *agentv1.AgentCapabilities) { v.Features[1].Name = 10000 }},
		{"unspecified", func(v *agentv1.AgentCapabilities) { v.Features[0].Name = 0 }},
		{"zero_version", func(v *agentv1.AgentCapabilities) { v.Features[0].ApiVersion = 0 }},
		{"duplicate", func(v *agentv1.AgentCapabilities) { v.Features[1] = proto.Clone(v.Features[0]).(*agentv1.Capability) }},
		{"unsorted", func(v *agentv1.AgentCapabilities) { slices.Reverse(v.Features) }},
		{"no_features", func(v *agentv1.AgentCapabilities) { v.Features = nil }},
		{"no_version", func(v *agentv1.AgentCapabilities) { v.AgentVersion = "" }},
		{"blank_build", func(v *agentv1.AgentCapabilities) { v.BuildId = " " }},
		{"oversize", func(v *agentv1.AgentCapabilities) { v.OpenrestyVersion = string(make([]byte, 65537)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := proto.Clone(valid).(*agentv1.AgentCapabilities)
			test.mutate(value)
			encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(encoded)
			decoded, err := decodeNodePublicationCapabilities(encoded, digest[:])
			if test.name == "valid" {
				if err != nil || !proto.Equal(decoded, valid) {
					t.Fatalf("valid decode: %v", err)
				}
			} else if !errors.Is(err, ErrTargetIneligible) {
				t.Fatalf("invalid decode accepted: %v", err)
			}
		})
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	digest[0] ^= 1
	if _, err := decodeNodePublicationCapabilities(encoded, digest[:]); !errors.Is(err, ErrTargetIneligible) {
		t.Fatal("wrong hash accepted")
	}
	// A second identical scalar field has the same decoded value, but is not canonical wire data.
	encoded = append(encoded, protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), valid.AgentVersion)...)
	digest = sha256.Sum256(encoded)
	if _, err := decodeNodePublicationCapabilities(encoded, digest[:]); !errors.Is(err, ErrTargetIneligible) {
		t.Fatal("noncanonical protobuf accepted")
	}
}
