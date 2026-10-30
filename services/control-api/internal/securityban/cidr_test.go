package securityban

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

// fix-cidrban: a manual ban may name a network; it is stored as the masked
// inet and shown as "<network>/<bits>", an address as the bare address.
func TestCanonicalClientNetwork(t *testing.T) {
	for raw, want := range map[string]string{
		" 203.0.113.9/24 ": "203.0.113.0/24", "203.0.113.9": "203.0.113.9", "203.0.113.9/32": "203.0.113.9",
		"2001:db8:5::7/48": "2001:db8:5::/48",
	} {
		prefix, ok := canonicalClient(raw)
		if !ok || clientText(prefix) != want {
			t.Errorf("canonicalClient(%q) = %v %v, want %s", raw, prefix, ok, want)
		}
		if back, ok := clientPrefix(want); !ok || back != prefix {
			t.Errorf("clientPrefix(%q) = %v, want %v", want, back, prefix)
		}
	}
	for _, raw := range []string{"203.0.0.0/7", "2001::/31", "127.0.0.0/24", "fe80::/64"} {
		if _, ok := canonicalClient(raw); ok {
			t.Errorf("canonicalClient(%q) accepted", raw)
		}
	}
}

// Only a node whose session declares BAN_CIDR v1 gets network entries.
func TestDeclaresBanCIDR(t *testing.T) {
	snapshot := func(features ...*agentv1.Capability) []byte {
		raw, err := proto.Marshal(&agentv1.AgentCapabilities{Features: features})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if !declaresBanCIDR(snapshot(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_BAN_CIDR, ApiVersion: 1})) {
		t.Fatal("BAN_CIDR v1 not recognized")
	}
	for name, raw := range map[string][]byte{
		"none":    nil,
		"garbage": {0xff},
		"other":   snapshot(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 2}),
		"v0":      snapshot(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_BAN_CIDR}),
	} {
		if declaresBanCIDR(raw) {
			t.Errorf("%s declares BAN_CIDR", name)
		}
	}
}
