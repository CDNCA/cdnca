package main

import (
	"os"
	"strings"
	"testing"
)

func TestOPS02ProductionCompositionUsesTheRealEdgePublisher(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	edgeRuntime := strings.Index(source, "sitePublicationRuntime, err := buildAndClearEdgePublishRuntime(")
	systemRuntime := strings.Index(source, "systemConfigurationHandlerFactory, err := buildSystemConfigurationHandlerFactory(")
	if edgeRuntime < 0 || systemRuntime < 0 || systemRuntime < edgeRuntime {
		t.Fatal("system configuration runtime must be composed after the production Edge publisher")
	}
	windowEnd := systemRuntime + 1600
	if windowEnd > len(source) {
		windowEnd = len(source)
	}
	window := source[systemRuntime:windowEnd]
	for _, required := range []string{
		"Publisher: systemConfigurationPublisher",
		"systemconfigpublish.New(",
		"SystemConfigurationHandlerFactory:   systemConfigurationHandlerFactory",
	} {
		if !strings.Contains(source, required) && !strings.Contains(window, required) {
			t.Errorf("production composition missing %q", required)
		}
	}
}
