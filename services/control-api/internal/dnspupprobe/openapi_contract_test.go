package dnspupprobe

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// api/control-probe-dnspup.openapi.yaml documents exactly the routes this
// handler serves beyond the 462 node-monitoring ones (those are in
// api/node-monitoring-latest.openapi.yaml), control.yaml references every one,
// and the plugin routes are API-key only with probes.dnspup.request.
func TestProbeDNSPupOpenAPIMatchesPatterns(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(filename), "../../../../api")
	read := func(path string, into any) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(raw, into); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	var fragment struct {
		Paths map[string]map[string]struct {
			Security    []map[string]any `yaml:"security"`
			Permissions []string         `yaml:"x-required-permissions"`
		} `yaml:"paths"`
	}
	read(filepath.Join(root, "control-probe-dnspup.openapi.yaml"), &fragment)
	var canonical struct {
		Paths map[string]struct {
			Ref string `yaml:"$ref"`
		} `yaml:"paths"`
	}
	read(filepath.Join(root, "openapi/v1/control.yaml"), &canonical)
	var documented []string
	for path, operations := range fragment.Paths {
		want := "../../control-probe-dnspup.openapi.yaml#/paths/" + strings.ReplaceAll(path, "/", "~1")
		if canonical.Paths[path].Ref != want {
			t.Errorf("control.yaml %s ref = %q, want %q", path, canonical.Paths[path].Ref, want)
		}
		for method, operation := range operations {
			documented = append(documented, strings.ToUpper(method)+" "+path)
			plugin := strings.HasPrefix(path, "/v1/probe-dnspup/plugin/")
			_, apiKey := operation.Security[0]["cdncaApiKey"]
			permission := PermissionManage
			if plugin {
				permission = PermissionPluginRequest
			}
			if len(operation.Security) != 1 || apiKey != plugin || !slices.Equal(operation.Permissions, []string{permission}) {
				t.Errorf("%s %s security %v permissions %v", method, path, operation.Security, operation.Permissions)
			}
		}
	}
	served := slices.Clone(Patterns[5:])
	sort.Strings(documented)
	sort.Strings(served)
	if strings.Join(documented, "\n") != strings.Join(served, "\n") {
		t.Fatalf("documented routes\n%s\nserved routes\n%s", strings.Join(documented, "\n"), strings.Join(served, "\n"))
	}
}

// the purposes PUT item and view document edge_health's probe
// type with exactly EdgeProbeTypes.
func TestProbeDNSPupOpenAPIEdgeProbeTypes(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../api/control-probe-dnspup.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	type property struct {
		Enum []string `yaml:"enum"`
	}
	type object struct {
		Properties map[string]property `yaml:"properties"`
	}
	var document struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Properties map[string]struct {
							Items object `yaml:"items"`
						} `yaml:"properties"`
					} `yaml:"schema"`
				} `yaml:"content"`
			} `yaml:"requestBody"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Items object `yaml:"items"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	input := document.Paths["/v1/admin/probe-dnspup/purposes"]["put"].RequestBody.Content["application/json"].Schema.
		Properties["purposes"].Items.Properties["probe_type"].Enum
	view := document.Components.Schemas["PurposesView"].Properties["purposes"].Items.Properties["probe_type"].Enum
	if !slices.Equal(input, EdgeProbeTypes) || !slices.Equal(view, EdgeProbeTypes) {
		t.Fatalf("probe_type enum input=%v view=%v, want %v", input, view, EdgeProbeTypes)
	}
}
