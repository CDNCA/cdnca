package httpapi

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// AUDIT-FINAL-1027 P1-②: POST /v1/sites/{id}/transfer is documented in
// sites.yaml with the request/response fields the handler actually uses and
// the error codes it returns.
func TestSiteTransferOpenAPIMatchesHandler(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve sites OpenAPI path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../api/openapi/v1/sites.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string       `yaml:"required"`
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	post, _ := document.Paths["/v1/sites/{id}/transfer"]["post"].(map[string]any)
	if post == nil || post["operationId"] != "transferSite" {
		t.Fatalf("POST /v1/sites/{id}/transfer missing or not operationId transferSite: %v", post)
	}
	responses, _ := post["responses"].(map[string]any)
	for _, status := range []string{"201", "400", "401", "403", "404", "409", "422"} {
		if responses[status] == nil {
			t.Errorf("transfer response %s is not documented", status)
		}
	}
	jsonFields := func(value any) []string {
		var names []string
		for _, field := range reflect.VisibleFields(reflect.TypeOf(value)) {
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			names = append(names, name)
		}
		slices.Sort(names)
		return names
	}
	schemaFields := func(name string) []string {
		schema, ok := document.Components.Schemas[name]
		if !ok {
			t.Fatalf("schema %s missing", name)
		}
		var names []string
		for property := range schema.Properties {
			names = append(names, property)
		}
		slices.Sort(names)
		return names
	}
	if got, want := schemaFields("TransferSiteRequest"), jsonFields(transferSiteRequest{}); !slices.Equal(got, want) {
		t.Errorf("TransferSiteRequest properties = %v, handler = %v", got, want)
	}
	if got, want := schemaFields("TransferSiteResponse"), jsonFields(transferSiteResponse{}); !slices.Equal(got, want) {
		t.Errorf("TransferSiteResponse properties = %v, handler = %v", got, want)
	}
	if required := document.Components.Schemas["TransferSiteResponse"].Required; !slices.Contains(required, "copied") ||
		!slices.Contains(required, "released") {
		t.Errorf("TransferSiteResponse required = %v, want copied and released", required)
	}
	text := string(source)
	for _, code := range []string{"site_transfer_target_invalid", "domain_verified_by_other", "domain_blocked",
		"domain_ownership_required", "site_locked", "version_conflict", "idempotency_conflict",
		"http_policy", "cache_policy", "certificate", "waf_policy", "cc_policy", "acl_policy", "auto_defense", "js_challenge"} {
		if !strings.Contains(text, code) {
			t.Errorf("sites.yaml does not mention %s", code)
		}
	}
}
