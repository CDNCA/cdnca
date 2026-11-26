package main

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestAgentAdvertisesL4LifecycleV2(t *testing.T) {
	capabilities := agentCapabilities("test")
	for _, name := range []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY} {
		found := false
		for _, capability := range capabilities.Features {
			if capability.Name == name {
				found = capability.ApiVersion >= 2
			}
		}
		if !found {
			t.Fatalf("missing L4 lifecycle v2 capability: %v", name)
		}
	}
}
