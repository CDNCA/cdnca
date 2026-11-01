package httpapi

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// omfix-a 7: NodeMetricsLatest / NodeTelemetry are additionalProperties:false, so
// every JSON field the handler can return must be a schema property, or a
// strict client rejects the whole response (xdp, ddos_protection and
// monthly_traffic were missing). Walks the Go response struct and the schema
// side by side, following $ref, arrays and pointers.
func TestNodeMetricsResponseMatchesOpenAPI(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	schemas := document.Components.Schemas
	resolve := func(schema map[string]any) map[string]any {
		for depth := 0; depth < 8; depth++ {
			ref, ok := schema["$ref"].(string)
			if !ok {
				return schema
			}
			schema = schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
		}
		return schema
	}
	var missing []string
	var walk func(path string, goType reflect.Type, schema map[string]any)
	walk = func(path string, goType reflect.Type, schema map[string]any) {
		for goType.Kind() == reflect.Pointer {
			goType = goType.Elem()
		}
		schema = resolve(schema)
		if goType.Kind() == reflect.Slice && goType.Elem().Kind() != reflect.Uint8 {
			items, _ := schema["items"].(map[string]any)
			if items == nil {
				missing = append(missing, path+"[] (no items schema)")
				return
			}
			walk(path+"[]", goType.Elem(), items)
			return
		}
		if goType.Kind() != reflect.Struct || goType == reflect.TypeOf(time.Time{}) {
			return
		}
		properties, _ := schema["properties"].(map[string]any)
		for index := 0; index < goType.NumField(); index++ {
			field := goType.Field(index)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" || name == "-" || !field.IsExported() {
				continue
			}
			property, ok := properties[name].(map[string]any)
			if !ok {
				missing = append(missing, path+"."+name)
				continue
			}
			walk(path+"."+name, field.Type, property)
		}
	}
	root := schemas["NodeMetricsLatest"]
	if root == nil {
		t.Fatal("NodeMetricsLatest schema missing")
	}
	walk("NodeMetricsLatest", reflect.TypeOf(nodeMetricsResponse{}), root)
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("Go response fields absent from OpenAPI:\n%s", strings.Join(missing, "\n"))
	}
}
