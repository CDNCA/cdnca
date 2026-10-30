package errorpagecontrol

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var (
	errorPageOpenAPIPathPattern      = regexp.MustCompile(`(?m)^  /v1/error-pages[^:]*:$`)
	errorPageOpenAPIMethodPattern    = regexp.MustCompile(`(?m)^    (get|post|put|patch|delete):$`)
	errorPageOpenAPIOperationPattern = regexp.MustCompile(`(?m)^      operationId: [A-Za-z][A-Za-z0-9]*$`)
	errorPageOpenAPIResponsePattern  = regexp.MustCompile(`^        '([0-9]{3})':`)
)

func TestErrorPageOpenAPIOperationMatrix(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-pages.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	tests := []struct {
		method      string
		path        string
		operationID string
		responses   []string
	}{
		{"post", "/v1/error-pages/assets/initiate", "initiateErrorPageAsset", []string{"201", "400", "401", "403", "405", "409", "422", "503"}},
		{"get", "/v1/error-pages/assets", "listErrorPageAssets", []string{"200", "400", "401", "403", "405", "503"}},
		{"get", "/v1/error-pages/assets/{asset_id}", "getErrorPageAsset", []string{"200", "400", "401", "403", "405", "404", "503"}},
		{"delete", "/v1/error-pages/assets/{asset_id}", "deleteErrorPageAsset", []string{"202", "400", "401", "403", "405", "404", "409", "412", "503"}},
		{"get", "/v1/error-pages/assets/{asset_id}/content", "getErrorPageAssetContent", []string{"200", "400", "401", "403", "405", "404", "409", "503"}},
		{"put", "/v1/error-pages/assets/{asset_id}/content", "uploadErrorPageAssetContent", []string{"200", "400", "401", "403", "405", "404", "409", "422", "503"}},
		{"post", "/v1/error-pages/assets/{asset_id}/finalize", "finalizeErrorPageAsset", []string{"200", "400", "401", "403", "405", "404", "409", "422", "503"}},
		{"get", "/v1/error-pages/slots", "listErrorPageSlots", []string{"200", "400", "401", "403", "405", "503"}},
		{"get", "/v1/error-pages/slots/{slot_key}", "getErrorPageSlot", []string{"200", "400", "401", "403", "404", "405", "409", "503"}},
		{"put", "/v1/error-pages/slots/{slot_key}", "bindErrorPageSlot", []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{"delete", "/v1/error-pages/slots/{slot_key}", "unbindErrorPageSlot", []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{"get", "/v1/error-pages/scope-overrides", "listErrorPageScopeOverrides", []string{"200", "400", "401", "403", "405", "503"}},
		{"post", "/v1/error-pages/scope-overrides", "createErrorPageScopeOverride", []string{"201", "400", "401", "403", "404", "405", "409", "503"}},
		{"get", "/v1/error-pages/scope-overrides/{override_display_id}", "getErrorPageScopeOverride", []string{"200", "400", "401", "403", "404", "405", "409", "503"}},
		{"patch", "/v1/error-pages/scope-overrides/{override_display_id}", "updateErrorPageScopeOverride", []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{"delete", "/v1/error-pages/scope-overrides/{override_display_id}", "deleteErrorPageScopeOverride", []string{"202", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{"get", "/v1/error-pages/rules", "listErrorPageRules", []string{"200", "400", "401", "403", "405", "503"}},
		{"post", "/v1/error-pages/rules", "createErrorPageRule", []string{"201", "400", "401", "403", "405", "404", "409", "422", "503"}},
		{"get", "/v1/error-pages/rules/{rule_id}", "getErrorPageRule", []string{"200", "400", "401", "403", "405", "404", "503"}},
		{"patch", "/v1/error-pages/rules/{rule_id}", "updateErrorPageRule", []string{"200", "400", "401", "403", "405", "404", "409", "412", "422", "503"}},
		{"delete", "/v1/error-pages/rules/{rule_id}", "deleteErrorPageRule", []string{"202", "400", "401", "403", "405", "404", "409", "412", "503"}},
		{"post", "/v1/error-pages/rules/{rule_id}/enable", "enableErrorPageRule", []string{"200", "400", "401", "403", "405", "404", "409", "412", "422", "503"}},
		{"post", "/v1/error-pages/rules/{rule_id}/disable", "disableErrorPageRule", []string{"200", "400", "401", "403", "405", "404", "409", "412", "503"}},
		{"get", "/v1/error-pages/publication-snapshot", "getErrorPagePublicationSnapshot", []string{"200", "400", "401", "403", "405", "404", "409", "503"}},
	}

	if paths := errorPageOpenAPIPathPattern.FindAllString(fragment, -1); len(paths) != 14 {
		t.Fatalf("OpenAPI paths = %d, want 14: %v", len(paths), paths)
	}
	if methods := errorPageOpenAPIMethodPattern.FindAllString(fragment, -1); len(methods) != len(tests) {
		t.Fatalf("OpenAPI operations = %d, want %d: %v", len(methods), len(tests), methods)
	}
	if operations := errorPageOpenAPIOperationPattern.FindAllString(fragment, -1); len(operations) != len(tests) {
		t.Fatalf("OpenAPI operationIds = %d, want %d: %v", len(operations), len(tests), operations)
	}

	for _, test := range tests {
		t.Run(test.operationID, func(t *testing.T) {
			pathBlock := errorPageOpenAPIPathBlock(t, fragment, test.path)
			operationBlock := errorPageOpenAPIMethodBlock(t, pathBlock, test.method)
			operationMarker := "      operationId: " + test.operationID
			if strings.Count(operationBlock, operationMarker) != 1 ||
				strings.Count(operationBlock, "      operationId: ") != 1 {
				t.Fatalf("%s %s operationId mismatch:\n%s", test.method, test.path, operationBlock)
			}
			var responses []string
			scanner := bufio.NewScanner(strings.NewReader(operationBlock))
			for scanner.Scan() {
				if match := errorPageOpenAPIResponsePattern.FindStringSubmatch(scanner.Text()); match != nil {
					responses = append(responses, match[1])
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(responses, test.responses) {
				t.Fatalf("%s %s response statuses = %v, want %v",
					test.method, test.path, responses, test.responses)
			}
		})
	}
}

func TestErrorPageOpenAPIMethodNotAllowedContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-pages.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	for _, required := range []string{
		"    MethodNotAllowed:",
		"        Allow: { $ref: '#/components/headers/Allow' }",
		"    Allow:",
		"                - method_not_allowed",
	} {
		if !strings.Contains(fragment, required) {
			t.Fatalf("OpenAPI method contract is missing %q", required)
		}
	}
}

func TestErrorPageOpenAPICorrelationContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-pages.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	if count := strings.Count(fragment, "#/components/parameters/OptionalRequestID"); count != 10 {
		t.Fatalf("optional GET request IDs = %d, want 10", count)
	}
	if count := strings.Count(fragment, "#/components/parameters/OptionalTraceID"); count != 10 {
		t.Fatalf("optional GET trace IDs = %d, want 10", count)
	}
	if count := strings.Count(fragment, "#/components/parameters/RequestID"); count != 14 {
		t.Fatalf("required mutation request IDs = %d, want 14", count)
	}
	if count := strings.Count(fragment, "#/components/parameters/TraceID"); count != 14 {
		t.Fatalf("required mutation trace IDs = %d, want 14", count)
	}
	if count := strings.Count(fragment, "X-Request-ID: { $ref: '#/components/headers/RequestID' }"); count != 32 {
		t.Fatalf("response request ID declarations = %d, want 32", count)
	}
	for _, required := range []string{
		"    OptionalRequestID:\n      name: X-Request-ID\n      in: header\n      required: false",
		"    OptionalTraceID:\n      name: X-Trace-ID\n      in: header\n      required: false",
		"    RequestID:\n      description: Accepted or generated request correlation token when available.",
	} {
		if !strings.Contains(fragment, required) {
			t.Fatalf("OpenAPI correlation contract is missing %q", required)
		}
	}
}

func TestErrorPageOpenAPIErrorResponseHasStableRequestID(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-pages.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	start := strings.Index(fragment, "    ErrorResponse:\n")
	if start < 0 {
		t.Fatal("OpenAPI ErrorResponse schema is missing")
	}
	block := fragment[start:]
	for _, required := range []string{
		"          required: [code, params, request_id]",
		"            request_id: { $ref: '#/components/schemas/CorrelationToken' }",
	} {
		if !strings.Contains(block, required) {
			t.Fatalf("OpenAPI ErrorResponse is missing %q:\n%s", required, block)
		}
	}
}

func TestErrorPageOpenAPIRequestSchemaContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-pages.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	for _, required := range []string{
		"required: [mime_type, size_bytes, sha256]",
		"description: Optional for tenant sessions and defaults to their own scope; required for platform sessions.",
		"required: [kind, scope_id]\n      allOf:\n        - if:\n            properties:\n              kind: { const: site }\n          then:\n            required: [site_id]\n          else:\n            not:\n              required: [site_id]",
		"required: [kind, from]\n      allOf:\n        - if:\n            properties:\n              kind: { const: range }\n          then:\n            required: [to]",
		"    EdgeMatch:\n      type: object\n      additionalProperties: false\n      oneOf:\n        - required: [codes]\n        - required: [ranges]",
		"    ScopeOverrideTargetInput:\n      type: object\n      additionalProperties: false\n      required: [kind, node_display_id, region]",
		"    ScopeOverrideBindingInput:\n      type: object\n      additionalProperties: false\n      required: [key, asset_id]",
	} {
		if !strings.Contains(fragment, required) {
			t.Fatalf("OpenAPI request schema contract is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"required: [scope_id, mime_type, size_bytes, sha256]",
		"required: [kind, from, to]",
	} {
		if strings.Contains(fragment, forbidden) {
			t.Fatalf("OpenAPI request schema retains over-restrictive contract %q", forbidden)
		}
	}
}

func TestErrorPageCanonicalOpenAPIBearerSecurity(t *testing.T) {
	repositoryRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "control.json")
	command := exec.Command("pnpm", "--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle",
		filepath.Join(repositoryRoot, "api/openapi/v1/control.yaml"), "--output", bundlePath)
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bundle canonical OpenAPI: %v\n%s", err, output)
	}

	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	source, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}

	methods := map[string]struct{}{"get": {}, "post": {}, "put": {}, "patch": {}, "delete": {}}
	operations := 0
	for path, item := range document.Paths {
		if !strings.HasPrefix(path, "/v1/error-pages") {
			continue
		}
		for method, raw := range item {
			if _, ok := methods[method]; !ok {
				continue
			}
			var operation struct {
				OperationID string                `json:"operationId"`
				Security    []map[string][]string `json:"security"`
			}
			if err := json.Unmarshal(raw, &operation); err != nil {
				t.Fatalf("decode %s %s: %v", method, path, err)
			}
			want := []map[string][]string{{"bearerAuth": {}}, {"cdncaApiKey": {}}}
			if !reflect.DeepEqual(operation.Security, want) {
				t.Errorf("%s %s (%s) security = %#v, want %#v",
					method, path, operation.OperationID, operation.Security, want)
			}
			operations++
		}
	}
	if operations != 24 {
		t.Fatalf("canonical error-page operations = %d, want 24", operations)
	}
}

func TestErrorPageOpenAPIUsesBearerSecurity(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-pages.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	if strings.Count(fragment, "\nsecurity:\n") != 1 || !strings.Contains(fragment,
		"\nsecurity:\n  - bearerAuth: []\n  - cdncaApiKey: []\ntags:\n") {
		t.Fatal("OpenAPI must declare exactly one global session/API-key requirement")
	}
	if count := strings.Count(fragment,
		"      security: [{bearerAuth: []}, {cdncaApiKey: []}]"); count != 24 {
		t.Fatalf("operation-level dual credential requirements = %d, want 24", count)
	}
	start := strings.Index(fragment, "    bearerAuth:\n")
	end := strings.Index(fragment, "\n  parameters:")
	if start < 0 || end <= start {
		t.Fatal("bearerAuth security scheme block not found")
	}
	block := fragment[start:end]
	if strings.Count(block, "      bearerFormat: ") != 1 {
		t.Fatalf("bearerAuth must declare exactly one bearerFormat: %s", block)
	}
	for _, required := range []string{
		"      type: http",
		"      scheme: bearer",
		"      bearerFormat: control-api-session",
		"identity.AuthenticateSession",
		"iamlock.AuthorizeSession inside the business PostgreSQL transaction",
	} {
		if !strings.Contains(block, required) {
			t.Fatalf("bearerAuth security scheme is missing %q: %s", required, block)
		}
	}
	apiKeyStart := strings.Index(fragment, "    cdncaApiKey:\n")
	if apiKeyStart < 0 || apiKeyStart >= end {
		t.Fatal("cdncaApiKey security scheme block not found")
	}
	apiKeyBlock := fragment[apiKeyStart:end]
	for _, required := range []string{
		"      type: apiKey",
		"      in: header",
		"      name: Authorization",
		"CdncaKey",
		"iamlock.AuthorizeAPIKey inside the business PostgreSQL transaction",
	} {
		if !strings.Contains(apiKeyBlock, required) {
			t.Fatalf("cdncaApiKey security scheme is missing %q: %s", required, apiKeyBlock)
		}
	}
}

func errorPageOpenAPIPathBlock(t *testing.T, source, path string) string {
	t.Helper()
	marker := "  " + path + ":\n"
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("OpenAPI path %q not found", path)
	}
	remainder := source[start+len(marker):]
	end := len(remainder)
	for _, boundary := range []string{"\n  /v1/error-pages", "\ncomponents:"} {
		if index := strings.Index(remainder, boundary); index >= 0 && index < end {
			end = index
		}
	}
	return remainder[:end]
}

func errorPageOpenAPIMethodBlock(t *testing.T, pathBlock, method string) string {
	t.Helper()
	marker := "    " + method + ":\n"
	start := strings.Index(pathBlock, marker)
	if start < 0 {
		t.Fatalf("OpenAPI method %q not found in path block", method)
	}
	remainder := pathBlock[start+len(marker):]
	end := len(remainder)
	for _, candidate := range []string{"get", "post", "put", "patch", "delete"} {
		if index := strings.Index(remainder, "\n    "+candidate+":"); index >= 0 && index < end {
			end = index
		}
	}
	return remainder[:end]
}
