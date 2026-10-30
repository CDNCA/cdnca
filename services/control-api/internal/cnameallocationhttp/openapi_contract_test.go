package cnameallocationhttp

import (
	"os"
	"strings"
	"testing"
)

func TestOpenAPIContractAggregatesAllTenantAndAdminQueryRoutes(t *testing.T) {
	fragment, err := os.ReadFile("../../../../api/control-cname-allocations.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragmentText, canonicalText := string(fragment), string(canonical)
	paths := []string{
		"/v1/cname-allocations:", "/v1/cname-allocations/{allocation_id}:", "/v1/cname-allocations/diagnose:",
		"/v1/admin/cname-allocations:", "/v1/admin/cname-allocations/{allocation_id}:", "/v1/admin/cname-allocations/diagnose:",
	}
	for _, path := range paths {
		if strings.Count(fragmentText, "  "+path) != 1 {
			t.Errorf("fragment path %q count != 1", path)
		}
		escaped := strings.ReplaceAll(strings.TrimSuffix(path, ":"), "/", "~1")
		if !strings.Contains(canonicalText, "'../../control-cname-allocations.openapi.yaml#/paths/"+escaped+"'") {
			t.Errorf("canonical contract missing %s aggregation", path)
		}
	}
	for _, required := range []string{"x-required-permissions: [dns.read]", "x-required-permissions: [platform.admin]", "NoStore", "XContentTypeOptions", "RequestID", "400", "401", "403", "404", "405", "408", "503"} {
		if !strings.Contains(fragmentText, required) {
			t.Errorf("fragment missing %q", required)
		}
	}
	for _, forbidden := range []string{"hmac_key_id", "request_digest", "idempotency_key", "credential_material"} {
		if strings.Contains(fragmentText, forbidden) {
			t.Errorf("fragment exposes %q", forbidden)
		}
	}
}
