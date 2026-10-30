package auditloghttp

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"gopkg.in/yaml.v3"
)

// The log center fragment is mounted in control.yaml, its row schema lists
// exactly the JSON fields of audit.Rendered, and both category enums (the log
// center and the cleanup settings) equal audit.Categories().
func TestAuditLogsOpenAPIMatchesImplementation(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	root := filepath.Join(filepath.Dir(filename), "../../../../api")
	var canonical struct {
		Paths map[string]struct {
			Ref string `yaml:"$ref"`
		} `yaml:"paths"`
	}
	readOpenAPI(t, filepath.Join(root, "openapi/v1/control.yaml"), &canonical)
	var fragment struct {
		Paths      map[string]any `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Enum       []string       `yaml:"enum"`
				Required   []string       `yaml:"required"`
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	readOpenAPI(t, filepath.Join(root, "control-audit-logs.openapi.yaml"), &fragment)
	for _, path := range []string{"/v1/audit-logs", "/v1/audit-logs/export", "/v1/audit-logs/categories"} {
		want := "../../control-audit-logs.openapi.yaml#/paths/" + strings.ReplaceAll(path, "/", "~1")
		if canonical.Paths[path].Ref != want {
			t.Errorf("control.yaml %s ref = %q, want %q", path, canonical.Paths[path].Ref, want)
		}
		if _, ok := fragment.Paths[path]; !ok {
			t.Errorf("fragment omits %s", path)
		}
	}

	var jsonFields, required []string
	kind := reflect.TypeOf(audit.Rendered{})
	for index := 0; index < kind.NumField(); index++ {
		tag := kind.Field(index).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		jsonFields = append(jsonFields, name)
		if !strings.Contains(tag, "omitempty") {
			required = append(required, name)
		}
	}
	row := fragment.Components.Schemas["Row"]
	var properties []string
	for name := range row.Properties {
		properties = append(properties, name)
	}
	sort.Strings(jsonFields)
	sort.Strings(properties)
	sort.Strings(required)
	documented := append([]string(nil), row.Required...)
	sort.Strings(documented)
	if !reflect.DeepEqual(properties, jsonFields) {
		t.Errorf("Row properties = %v, audit.Rendered JSON fields = %v", properties, jsonFields)
	}
	if !reflect.DeepEqual(documented, required) {
		t.Errorf("Row required = %v, audit.Rendered non-omitempty fields = %v", documented, required)
	}

	var categories []string
	for _, info := range audit.Categories() {
		categories = append(categories, string(info.Category))
	}
	if got := fragment.Components.Schemas["Category"].Enum; !reflect.DeepEqual(got, categories) {
		t.Errorf("log center Category enum = %v, want %v", got, categories)
	}
	var cleanup struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string `yaml:"required"`
				Properties map[string]struct {
					PropertyNames struct {
						Enum []string `yaml:"enum"`
					} `yaml:"propertyNames"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	readOpenAPI(t, filepath.Join(root, "control-system-cleanup-settings.openapi.yaml"), &cleanup)
	settings := cleanup.Components.Schemas["Settings"]
	if got := settings.Properties["audit_retention_days"].PropertyNames.Enum; !reflect.DeepEqual(got, categories) {
		t.Errorf("cleanup audit_retention_days categories = %v, want %v", got, categories)
	}
	for _, legacy := range []string{"login_records_days", "operation_records_days"} {
		if _, ok := settings.Properties[legacy]; ok {
			t.Errorf("cleanup settings still documents %s", legacy)
		}
	}
}

func readOpenAPI(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, target); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
