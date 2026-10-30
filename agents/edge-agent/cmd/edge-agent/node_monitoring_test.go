package main

import (
	"testing"
)

func TestAssembleNodeMonitoringRequiresPrivateStateAndDefaultPort(t *testing.T) {
	settings := nodeMonitoringSettings{Enabled: true, StateDir: t.TempDir(), DefaultPort: 8080}
	bridge, runtime, err := assembleNodeMonitoring(settings, "01990000-0000-7000-8000-000000000007")
	if err != nil || bridge == nil || runtime == nil {
		t.Fatalf("assembleNodeMonitoring() = (%#v, %#v, %v)", bridge, runtime, err)
	}
	if _, _, err := assembleNodeMonitoring(nodeMonitoringSettings{Enabled: true, StateDir: settings.StateDir},
		"01990000-0000-7000-8000-000000000007"); err == nil {
		t.Fatal("zero default port was accepted")
	}
}
