package main

import (
	"fmt"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/toa"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// probeL4TOA loads the TOA eBPF programs for the L4 OpenResty this agent
// spawns (it inherits the agent's cgroup). A failure only withholds L4_TOA;
// forwarding never depends on it.
func probeL4TOA(openRestyBinary string) *toa.Manager {
	manager := toa.Probe(toa.Options{OpenRestyBinary: openRestyBinary})
	status := manager.Status()
	if status.Ready {
		fmt.Fprintf(os.Stderr, "edge-agent: L4 TOA ready (kernel %s, cgroup %s)\n", status.Kernel, status.Cgroup)
	} else {
		fmt.Fprintf(os.Stderr, "edge-agent: L4 TOA unavailable, L4_TOA not declared: %s\n", status.Reason)
	}
	return manager
}

// addL4TOACapability declares L4_TOA v1 once the probe passed its self-test.
func addL4TOACapability(capabilities *agentv1.AgentCapabilities, status toa.Status) {
	if capabilities == nil || !status.Ready {
		return
	}
	for _, capability := range capabilities.Features {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA {
			return
		}
	}
	capabilities.Features = append(capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA, ApiVersion: 1,
	})
}
