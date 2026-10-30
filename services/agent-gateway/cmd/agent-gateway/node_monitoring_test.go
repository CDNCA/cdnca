package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/agent-gateway"
)

func TestConfigureNodeMonitoringRejectsMissingDependencies(t *testing.T) {
	if err := configureNodeMonitoring(nil, nil); err == nil {
		t.Fatal("missing node monitoring dependencies were accepted")
	}
	var service *gateway.Gateway
	if err := configureNodeMonitoring(service, nil); err == nil {
		t.Fatal("nil gateway was accepted")
	}
}
