package main

import (
	"os"
	"strings"
	"testing"
)

func TestNODE07NodeMetricsProductionComposition(t *testing.T) {
	mainSource := readNodeMetricsCompositionSource(t, "main.go")
	runtimeSource := readNodeMetricsCompositionSource(t, "node_metrics_runtime.go")
	helmSource := readNodeMetricsCompositionSource(t, "../../../../infra/helm/cdnca/templates/control-api.yaml")

	for _, required := range []string{
		"openNodeMetricsRuntime(ctx, cfg, pool, nats.Connect)",
		"NodeMetricsReader:                   nodeMetricsRuntime.reader",
		"runRequiredNodeMetricsRuntime(ctx, nodeMetricsRuntime, failures)",
		"nodeMetricsRuntime.Close()",
	} {
		if !strings.Contains(mainSource, required) {
			t.Errorf("main production composition missing %q", required)
		}
	}
	for _, required := range []string{
		"nodemetrics.NewNATSConsumer(connection, consumerConfig)",
		"nodemetrics.NewPostgresStore(pool)",
		"nodemetrics.NewPostgresReader(pool)",
		"runtime.processor.Process(ctx, delivery)",
		"runtime.connection.Drain()",
	} {
		if !strings.Contains(runtimeSource, required) {
			t.Errorf("node metrics runtime composition missing %q", required)
		}
	}
	for _, required := range []string{"name: EDGE_DEPLOYMENT_NATS_URL"} {
		if !strings.Contains(helmSource, required) {
			t.Errorf("control API Helm composition missing %q", required)
		}
	}
}

func readNodeMetricsCompositionSource(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}
