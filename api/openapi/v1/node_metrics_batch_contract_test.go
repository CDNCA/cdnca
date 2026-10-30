package v1

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNodeMetricsLatestBatchContract(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve OpenAPI contract path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "control.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Get struct {
				OperationID string `yaml:"operationId"`
				Description string
				Security    []map[string][]string
				Parameters  []struct {
					Name, In, Style string
					Required        bool
					Explode         bool
					Schema          map[string]any
				}
				Responses map[string]any
			}
		}
		Components struct {
			Schemas map[string]map[string]any
		}
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	operation := document.Paths["/v1/nodes/metrics/latest"].Get
	if operation.OperationID != "getLatestNodeMetricsBatch" || len(operation.Parameters) != 1 ||
		!reflect.DeepEqual(operation.Security, []map[string][]string{{"bearerAuth": {}}}) {
		t.Fatalf("batch operation or authentication drifted: %+v", operation)
	}
	parameter := operation.Parameters[0]
	if parameter.Name != "node_id" || parameter.In != "query" || !parameter.Required || parameter.Style != "form" || !parameter.Explode ||
		parameter.Schema["type"] != "array" || parameter.Schema["minItems"] != 1 || parameter.Schema["maxItems"] != 300 || parameter.Schema["uniqueItems"] != true {
		t.Fatalf("strict repeated node_id parameter drifted: %+v", parameter)
	}
	for _, status := range []string{"200", "400", "401", "403", "404", "500", "503"} {
		if operation.Responses[status] == nil {
			t.Errorf("missing response %s", status)
		}
	}
	for _, fact := range []string{"nodes.read", "one database snapshot", "node_metrics_not_found", "no partial results", "cover the request exactly", "host_metric is not a probe-health", "node_metrics_unavailable"} {
		if !strings.Contains(operation.Description, fact) {
			t.Errorf("missing public semantics %q", fact)
		}
	}
	schema := document.Components.Schemas["NodeMetricsLatestBatch"]
	if schema["type"] != "object" || schema["additionalProperties"] != false ||
		!reflect.DeepEqual(schema["required"], []any{"observed_at", "items", "not_reported_node_ids"}) {
		t.Fatalf("batch response envelope drifted: %+v", schema)
	}
	properties := schema["properties"].(map[string]any)
	if len(properties) != 3 || properties["observed_at"].(map[string]any)["format"] != "date-time" {
		t.Fatal("batch response must contain exactly read time and the two membership partitions")
	}
	items := properties["items"].(map[string]any)
	missing := properties["not_reported_node_ids"].(map[string]any)
	if items["maxItems"] != 300 || items["items"].(map[string]any)["$ref"] != "#/components/schemas/NodeMetricsLatest" ||
		missing["maxItems"] != 300 || missing["uniqueItems"] != true || missing["items"].(map[string]any)["format"] != "uuid" {
		t.Fatal("batch must reuse the existing latest DTO without rewriting telemetry or durable evidence")
	}
}
