package gateway

import "testing"

func TestDefaultNATSNodeMonitoringConfigUsesIsolatedStreamsAndSubjects(t *testing.T) {
	config := DefaultNATSNodeMonitoringBusConfig()
	if err := config.validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	if config.CommandStream != NodeMonitoringCommandStream || config.StatusStream != NodeMonitoringStatusStream ||
		config.CommandSubjectPrefix == config.StatusSubjectPrefix {
		t.Fatalf("default config = %#v", config)
	}
	nodeID := "01990000-0000-7000-8000-000000000007"
	if nodeMonitoringCommandSubject(config, nodeID) == nodeMonitoringStatusSubject(config, nodeID) {
		t.Fatal("command and status subjects collide")
	}
}
