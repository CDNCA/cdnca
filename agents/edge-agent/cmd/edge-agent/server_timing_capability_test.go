package main

import (
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// the agent decodes server_timing and the node
// answers Server-Timing (cdnca_filters slot 3b), so the daemon declares
// SITE_SERVER_TIMING v1 with the other site object capabilities (runDaemon
// builds that list inline; this pins the declaration).
func TestAgentDeclaresServerTiming(t *testing.T) {
	source, err := os.ReadFile("daemon.go")
	if err != nil {
		t.Fatal(err)
	}
	const declaration = "&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SERVER_TIMING, ApiVersion: siteobject.ServerTimingAPIVersion}"
	if strings.Count(string(source), declaration) != 1 || siteobject.ServerTimingAPIVersion != 1 {
		t.Fatal("daemon.go must declare SITE_SERVER_TIMING v1 exactly once")
	}
}
