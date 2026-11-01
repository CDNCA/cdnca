package theme

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The theme routes are documented and the control API index references each
// of them.
func TestThemeOpenAPIDocumentsEveryRoute(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	raw, err := os.ReadFile("../../../../api/control-themes.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for path, methods := range map[string][]string{
		"/v1/theme/current": {"get"}, "/v1/theme/theme.{sha}.css": {"get"}, "/v1/theme/theme.{sha}.json": {"get"},
		"/v1/theme/assets/{sha}": {"get"}, "/v1/admin/themes": {"get"},
		"/v1/theme/auth-style": {"get"}, "/v1/theme/auth-style/assets/{sha}": {"get"},
		"/v1/admin/themes/catalog/{theme_id}/download": {"post"}, "/v1/admin/themes/packages": {"post"},
		"/v1/admin/themes/packages/{sha}/activate": {"post"}, "/v1/admin/themes/packages/{sha}": {"get", "delete"},
	} {
		for _, method := range methods {
			if _, ok := spec.Paths[path][method]; !ok {
				t.Errorf("%s %s is not documented", method, path)
			}
		}
		ref := "control-themes.openapi.yaml#/paths/" + strings.ReplaceAll(path, "/", "~1")
		if !strings.Contains(string(index), ref) {
			t.Errorf("control.yaml does not reference %s", ref)
		}
	}
	if len(spec.Paths) != 11 {
		t.Errorf("documented %d theme paths", len(spec.Paths))
	}
}
