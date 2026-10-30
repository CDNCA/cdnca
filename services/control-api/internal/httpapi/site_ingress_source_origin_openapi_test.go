package httpapi

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSITE08ConditionalOriginRequiresIngressSourceBoolean(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve sites OpenAPI path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../api/openapi/v1/sites.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	components, _ := document["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	schema, _ := schemas["ConditionalOriginDocument"].(map[string]any)
	properties, _ := schema["properties"].(map[string]any)
	property, _ := properties["ingress_source_enabled"].(map[string]any)
	required, _ := schema["required"].([]any)
	requiredIngressSource := false
	for _, name := range required {
		requiredIngressSource = requiredIngressSource || name == "ingress_source_enabled"
	}
	if property["type"] != "boolean" || !requiredIngressSource {
		t.Fatalf("ConditionalOriginDocument ingress_source_enabled = %+v, required=%v", property, required)
	}
}
