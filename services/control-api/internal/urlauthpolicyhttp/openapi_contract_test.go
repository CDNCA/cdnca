package urlauthpolicyhttp

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
	openAPIPathPattern      = regexp.MustCompile(`^  (/[^:]+):$`)
	openAPIMethodPattern    = regexp.MustCompile(`^    (get|post|patch):$`)
	openAPIOperationPattern = regexp.MustCompile(`^      operationId: ([A-Za-z0-9]+)$`)
	openAPIStatusPattern    = regexp.MustCompile(`^        '([0-9]{3})':`)
)

type openAPIOperation struct {
	Method      string
	Path        string
	OperationID string
	Statuses    []string
}

func TestOpenAPIOperationMatrix(t *testing.T) {
	want := []openAPIOperation{
		{Method: "get", Path: "/v1/url-auth-policies", OperationID: "listURLAuthPolicies", Statuses: []string{"200", "400", "401", "403", "405", "422", "431", "503"}},
		{Method: "post", Path: "/v1/url-auth-policies", OperationID: "createURLAuthPolicy", Statuses: []string{"201", "400", "401", "403", "405", "409", "422", "431", "503"}},
		{Method: "get", Path: "/v1/url-auth-policies/{id}", OperationID: "getURLAuthPolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "431", "503"}},
		{Method: "patch", Path: "/v1/url-auth-policies/{id}", OperationID: "updateURLAuthPolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "431", "503"}},
		{Method: "post", Path: "/v1/url-auth-policies/{id}/enable", OperationID: "enableURLAuthPolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "431", "503"}},
		{Method: "post", Path: "/v1/url-auth-policies/{id}/disable", OperationID: "disableURLAuthPolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "431", "503"}},
		{Method: "post", Path: "/v1/url-auth-policies/{id}/rotate", OperationID: "rotateURLAuthPolicyKey", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "431", "503"}},
		{Method: "post", Path: "/v1/url-auth-policies/{id}/revoke", OperationID: "revokePreviousURLAuthPolicyKey", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "431", "503"}},
		{Method: "get", Path: "/v1/url-auth-policies/{id}/edge-snapshot", OperationID: "getURLAuthPolicyEdgeSnapshot", Statuses: []string{"200", "400", "401", "403", "404", "405", "431", "503"}},
	}
	if got := parseOpenAPIOperations(t, readOpenAPI(t)); !reflect.DeepEqual(got, want) {
		t.Fatalf("operations = %#v, want %#v", got, want)
	}
}

func TestOpenAPISecurityAndOneTimeSecretContract(t *testing.T) {
	source := readOpenAPI(t)
	for _, required := range []string{
		"security:\n  - bearerAuth: []\n  - cdncaKeyAuth: []",
		"User, membership, tenant status, and\n        current RBAC are re-read server-side on every request.",
		"Active key state, tenant, user, membership, current RBAC, and key scopes",
		"required: [policy, replayed]",
		"Present only on the first committed create or rotate response; absent on replay.",
		"schema_version: {type: string, const: cdnca.edge.urlauth/v1}",
		"algorithm: {type: string, const: hmac-sha256}",
		"Migration provenance only; never selects the runtime algorithm.",
		"Retry an unknown result only with this exact key and unchanged body and revision.",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("contract declaration %q is missing", required)
		}
	}
	secretBlock := schemaBlock(t, source, "SecretWriteResult")
	if strings.Count(secretBlock, "        secret:") != 1 || strings.Contains(secretBlock, "required: [policy, secret, replayed]") {
		t.Fatalf("one-time secret schema is not optional:\n%s", secretBlock)
	}
	for _, schema := range []string{"Policy", "PolicyList", "PolicyWriteResult", "EdgePolicy", "EdgeSnapshot", "Error"} {
		block := schemaBlock(t, source, schema)
		if strings.Contains(block, "        secret:") || strings.Contains(block, "ciphertext") || strings.Contains(block, "secret_digest") || strings.Contains(block, "kek_key_id") {
			t.Fatalf("%s leaks key material fields:\n%s", schema, block)
		}
	}
}

func TestOpenAPIPolicyResponseUsesNestedSiteOnly(t *testing.T) {
	source := readOpenAPI(t)
	fields := schemaBlock(t, source, "PolicyFields")
	if strings.Contains(fields, "site_id") {
		t.Fatalf("shared policy response fields still contain request-only site_id:\n%s", fields)
	}
	for _, schema := range []string{"CreatePolicyRequest", "UpdatePolicyRequest"} {
		block := schemaBlock(t, source, schema)
		if !strings.Contains(block, "required: [site_id]") || !strings.Contains(block, "site_id: {$ref: '#/components/schemas/CanonicalUUID'}") {
			t.Fatalf("%s does not require request site_id:\n%s", schema, block)
		}
	}
	policy := schemaBlock(t, source, "Policy")
	if strings.Contains(policy, "required: [site_id") || !strings.Contains(policy, "required: [id, scope_id, site, current_key, version, created_at, updated_at]") {
		t.Fatalf("policy response site contract is inconsistent:\n%s", policy)
	}
}

func TestOpenAPIBundlesAndKeepsOperationSecurity(t *testing.T) {
	repositoryRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	fragment := filepath.Join(repositoryRoot, "api/control-url-auth.openapi.yaml")
	bundle := filepath.Join(t.TempDir(), "control-url-auth.json")
	command := exec.Command("pnpm", "--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", fragment, "--output", bundle)
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bundle OpenAPI: %v\n%s", err, output)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	encoded, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Paths) != 7 {
		t.Fatalf("bundled paths = %d, want 7", len(document.Paths))
	}
	wantSecurity := []map[string][]string{{"bearerAuth": {}}, {"cdncaKeyAuth": {}}}
	for _, contract := range parseOpenAPIOperations(t, readOpenAPI(t)) {
		var operation struct {
			OperationID string                `json:"operationId"`
			Security    []map[string][]string `json:"security"`
		}
		raw := document.Paths[contract.Path][contract.Method]
		if err := json.Unmarshal(raw, &operation); err != nil {
			t.Fatal(err)
		}
		if operation.OperationID != contract.OperationID || !reflect.DeepEqual(operation.Security, wantSecurity) {
			t.Fatalf("%s %s operation=%q security=%#v", contract.Method, contract.Path, operation.OperationID, operation.Security)
		}
	}
}

func readOpenAPI(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("../../../../api/control-url-auth.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

func parseOpenAPIOperations(t *testing.T, source string) []openAPIOperation {
	t.Helper()
	var result []openAPIOperation
	var currentPath string
	var current *openAPIOperation
	finish := func() {
		if current != nil {
			result = append(result, *current)
			current = nil
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		line := scanner.Text()
		if match := openAPIPathPattern.FindStringSubmatch(line); match != nil {
			finish()
			currentPath = match[1]
			continue
		}
		if line == "components:" {
			finish()
			currentPath = ""
			continue
		}
		if match := openAPIMethodPattern.FindStringSubmatch(line); match != nil && currentPath != "" {
			finish()
			current = &openAPIOperation{Method: match[1], Path: currentPath}
			continue
		}
		if current == nil {
			continue
		}
		if match := openAPIOperationPattern.FindStringSubmatch(line); match != nil {
			current.OperationID = match[1]
		}
		if match := openAPIStatusPattern.FindStringSubmatch(line); match != nil {
			current.Statuses = append(current.Statuses, match[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	finish()
	return result
}

func schemaBlock(t *testing.T, source, name string) string {
	t.Helper()
	marker := "    " + name + ":\n"
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("schema %s not found", name)
	}
	remainder := source[start+len(marker):]
	end := len(remainder)
	if next := regexp.MustCompile(`(?m)^    [A-Za-z][A-Za-z0-9]*:$`).FindStringIndex(remainder); next != nil {
		end = next[0]
	}
	return remainder[:end]
}
