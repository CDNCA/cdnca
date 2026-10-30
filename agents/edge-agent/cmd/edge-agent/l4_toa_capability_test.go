package main

import (
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/toa"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// L4_TOA v1 is declared only when the TOA programs passed their self-test;
// a failed probe (old kernel, unpatched OpenResty, no permission) keeps the
// node without it so the control plane refuses TOA streams for it.
func TestL4TOACapabilityRequiresReadyProbe(t *testing.T) {
	capabilities := agentCapabilities("1.31.1.1")
	addL4TOACapability(capabilities, toa.Status{Reason: "kernel lacks sockops TCP header options"})
	if hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA) {
		t.Fatal("L4_TOA advertised after a failed probe")
	}
	addL4TOACapability(capabilities, toa.Status{Ready: true})
	addL4TOACapability(capabilities, toa.Status{Ready: true})
	count := 0
	for _, capability := range capabilities.Features {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA {
			count++
			if capability.ApiVersion != 1 {
				t.Fatalf("L4_TOA api version = %d, want 1", capability.ApiVersion)
			}
		}
	}
	if count != 1 {
		t.Fatalf("L4_TOA declared %d times, want once", count)
	}
}

// tcp/udp v8 (toa) is declared by every agent of this release: it only
// means the stream field is understood; L4_TOA says the node can act on it.
// v9 (port_end / follow_port), v10 (guard_rules), v11 (origins, ip_hash,
// listen_ipv6) and v12 (streams without a website) include v8; v12 is current.
func TestAgentDeclaresTCPUDPV12ForTOAPortRangeGuardOriginAndStandaloneFields(t *testing.T) {
	for _, capability := range agentCapabilities("1.31.1.1").Features {
		if (capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
			capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.ApiVersion != 12 {
			t.Fatalf("%s v%d, want v12", capability.Name, capability.ApiVersion)
		}
	}
	if l4StreamAPIVersion != 12 {
		t.Fatalf("site runtime v2 validator would see tcp/udp v%d", l4StreamAPIVersion)
	}
}
