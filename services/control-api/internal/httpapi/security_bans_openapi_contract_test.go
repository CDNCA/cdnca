package httpapi

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"gopkg.in/yaml.v3"
)

// The ban list routes are in the control OpenAPI:
// every route server.go mounts, the Entry / Delivery / MarketOrigin fields as
// the Go types encode them, and the source and delivery state enums.
func TestSecurityBansOpenAPIContract(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-security-bans.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths      map[string]map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string                  `yaml:"required"`
				Properties map[string]map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	server, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(server), `for _, base := range []string{"/v1/security-bans", "/v1/admin/security-bans"} {`) {
		t.Fatal("server.go no longer mounts the ban list routes as this contract expects")
	}
	for path, methods := range map[string][]string{
		"/v1/security-bans": {"get", "post"}, "/v1/security-bans/{entry_id}/release": {"post"},
		"/v1/admin/security-bans": {"get", "post"}, "/v1/admin/security-bans/{entry_id}/release": {"post"},
	} {
		got := []string{}
		for method := range document.Paths[path] {
			got = append(got, method)
		}
		slices.Sort(got)
		if !slices.Equal(got, methods) {
			t.Errorf("%s methods = %v, want %v", path, got, methods)
		}
		escaped := strings.ReplaceAll(path, "/", "~1")
		if !strings.Contains(string(canonical), "'../../control-security-bans.openapi.yaml#/paths/"+escaped+"'") {
			t.Errorf("control.yaml does not aggregate %s", path)
		}
	}
	for name, value := range map[string]any{"Entry": securityban.Entry{}, "Delivery": securityban.Delivery{},
		"MarketOrigin": securityban.MarketOrigin{}} {
		fields := jsonFields(reflect.TypeOf(value))
		schema := document.Components.Schemas[name]
		if !slices.Equal(schema.Required, fields) {
			t.Errorf("%s required = %v, Go fields %v", name, schema.Required, fields)
		}
		if len(schema.Properties) != len(fields) {
			t.Errorf("%s has %d properties, Go %d", name, len(schema.Properties), len(fields))
		}
	}
	enum := func(schema, property string) []string {
		var out []string
		for _, value := range document.Components.Schemas[schema].Properties[property]["enum"].([]any) {
			out = append(out, value.(string))
		}
		return out
	}
	if got := enum("Entry", "source"); !slices.Equal(got, []string{securityban.SourceWAF, securityban.SourceCC,
		securityban.SourceManual, "autodefense", securityban.SourceMarket}) {
		t.Errorf("source enum = %v", got)
	}
	if got := enum("Delivery", "state"); !slices.Equal(got, []string{securityban.DeliveryEffective, securityban.DeliveryDelivering,
		securityban.DeliveryPending, securityban.DeliveryNoNodes, securityban.DeliveryUnsupported, securityban.DeliveryFailed,
		securityban.DeliveryRefused}) {
		t.Errorf("delivery state enum = %v", got)
	}
}

func jsonFields(typ reflect.Type) []string {
	var out []string
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}
