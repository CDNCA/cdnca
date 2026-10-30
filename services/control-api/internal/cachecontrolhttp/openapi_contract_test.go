package cachecontrolhttp

import (
	"os"
	"strings"
	"testing"
)

func TestCachePolicyOpenAPIDocumentsV1AndV2(t *testing.T) {
	content, err := os.ReadFile("../../../../api/control-cache-operations.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(content)
	for _, required := range []string{
		"PolicyDocumentV1:",
		"PolicyDocumentV2:",
		"PolicyRuleV1:",
		"PolicyRuleV2:",
		"schema_version: {type: integer, const: 2}",
		"required: [order, action, ttl_seconds, browser_ttl_seconds]",
		"action: {type: string, enum: [cache, no_cache]}",
		"ttl_seconds: {const: 0}",
		"browser_ttl_seconds: {const: 0}",
		"CachePolicyBindingMode: {type: string, enum: [inherit, override]}",
		"required: [definition_id, definition_revision]",
		"expected_definition_revision: {type: integer, format: int64, minimum: 0}",
		"required: [site_id, revision, binding_mode, definition_id, definition_revision, document, created_by_user_id, request_id, created_at]",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("cache policy OpenAPI missing %q", required)
		}
	}
	if !strings.Contains(contract, "{$ref: '#/components/schemas/PolicyDocumentV1'}") ||
		!strings.Contains(contract, "{$ref: '#/components/schemas/PolicyDocumentV2'}") {
		t.Fatal("cache policy document must expose explicit V1/V2 alternatives")
	}
}
