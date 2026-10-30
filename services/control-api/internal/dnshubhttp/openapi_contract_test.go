package dnshubhttp

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The fragment documents exactly the served routes (method and path), and
// control.yaml mounts every one of its paths.
func TestDNSHubOpenAPIMatchesPatterns(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
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
		Paths map[string]map[string]any `yaml:"paths"`
	}
	read(filepath.Join(root, "control-dns-hub.openapi.yaml"), &fragment)
	var canonical struct {
		Paths map[string]struct {
			Ref string `yaml:"$ref"`
		} `yaml:"paths"`
	}
	read(filepath.Join(root, "openapi/v1/control.yaml"), &canonical)
	var documented []string
	for path, operations := range fragment.Paths {
		for method := range operations {
			documented = append(documented, strings.ToUpper(method)+" "+path)
		}
		want := "../../control-dns-hub.openapi.yaml#/paths/" + strings.ReplaceAll(path, "/", "~1")
		if canonical.Paths[path].Ref != want {
			t.Errorf("control.yaml %s ref = %q, want %q", path, canonical.Paths[path].Ref, want)
		}
	}
	served := append([]string(nil), Patterns...)
	sort.Strings(documented)
	sort.Strings(served)
	if strings.Join(documented, "\n") != strings.Join(served, "\n") {
		t.Fatalf("documented routes\n%s\nserved routes\n%s", strings.Join(documented, "\n"), strings.Join(served, "\n"))
	}
	for _, pattern := range served {
		method, _, _ := strings.Cut(pattern, " ")
		switch method {
		case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete:
		default:
			t.Errorf("unexpected method in %s", pattern)
		}
	}
}
