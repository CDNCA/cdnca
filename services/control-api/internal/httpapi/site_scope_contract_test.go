package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

func TestSiteDetailIncludesTenantScopeForScopedWorkflows(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	response := siteDetail(site.Site{ScopeID: scopeID})
	if response.ScopeID != scopeID {
		t.Fatalf("site detail scope = %s, want %s", response.ScopeID, scopeID)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["scope_id"] != scopeID.String() {
		t.Fatalf("site detail JSON scope_id = %#v, want %s", payload["scope_id"], scopeID)
	}
}

func TestSiteDetailOpenAPIRequiresTenantScope(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../api/openapi/v1/sites.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string `yaml:"required"`
				Properties map[string]struct {
					Type     any `yaml:"type"`
					Format   any `yaml:"format"`
					ReadOnly any `yaml:"readOnly"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("parse sites OpenAPI: %v", err)
	}
	detail := document.Components.Schemas["SiteDetail"]
	property, exists := detail.Properties["scope_id"]
	if !slices.Contains(detail.Required, "scope_id") || !exists ||
		property.Type != "string" || property.Format != "uuid" || property.ReadOnly != true {
		t.Fatalf("SiteDetail scope_id contract = required:%v property:%+v", detail.Required, property)
	}
}
