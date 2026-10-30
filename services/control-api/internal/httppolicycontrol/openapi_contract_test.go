package httppolicycontrol

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var (
	httpPolicyOpenAPIPathPattern      = regexp.MustCompile(`^  (/[^:]+):$`)
	httpPolicyOpenAPIMethodPattern    = regexp.MustCompile(`^    (get|post|patch|delete):$`)
	httpPolicyOpenAPIOperationPattern = regexp.MustCompile(`^      operationId: ([A-Za-z0-9]+)$`)
	httpPolicyOpenAPIStatusPattern    = regexp.MustCompile(`^        '([0-9]{3})':`)
)

type httpPolicyOpenAPIOperation struct {
	Method      string
	Path        string
	OperationID string
	Security    []map[string][]string
	Statuses    []string
}

func TestHTTPPolicyOpenAPIOperationContract(t *testing.T) {
	bearer := []map[string][]string{{"bearerAuth": {}}}
	want := []httpPolicyOpenAPIOperation{
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies", OperationID: "listHTTPPolicies", Security: bearer, Statuses: []string{"200", "400", "401", "403", "404", "405", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies", OperationID: "createHTTPPolicy", Security: bearer, Statuses: []string{"201", "400", "401", "403", "404", "405", "409", "422", "503"}},
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies/publication-preview", OperationID: "previewHTTPPolicyPublication", Security: bearer, Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "503"}},
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}", OperationID: "getHTTPPolicy", Security: bearer, Statuses: []string{"200", "400", "401", "403", "404", "405", "503"}},
		{Method: "patch", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}", OperationID: "updateHTTPPolicy", Security: bearer, Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{Method: "delete", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}", OperationID: "deleteHTTPPolicy", Security: bearer, Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/enable", OperationID: "enableHTTPPolicy", Security: bearer, Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/disable", OperationID: "disableHTTPPolicy", Security: bearer, Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
	}
	if got := parseHTTPPolicyOpenAPIOperations(t, readHTTPPolicyOpenAPI(t)); !reflect.DeepEqual(got, want) {
		t.Fatalf("operations = %#v, want %#v", got, want)
	}
}

func TestHTTPPolicyOpenAPISessionSecurityAndErrorContract(t *testing.T) {
	source := readHTTPPolicyOpenAPI(t)
	paths := strings.Index(source, "\npaths:\n")
	components := strings.Index(source, "\ncomponents:\n")
	if paths < 0 || components < paths {
		t.Fatal("OpenAPI paths/components sections not found")
	}
	if strings.Count(source[:paths], "\nsecurity:\n  - bearerAuth: []\n") != 1 {
		t.Fatal("global Bearer security is missing or duplicated")
	}
	if got := strings.Count(source[paths:components], "\n      security: [{bearerAuth: []}]\n"); got != 8 {
		t.Fatalf("operation-level Bearer security declarations = %d, want 8", got)
	}
	for _, required := range []string{
		"bearerFormat: control-api-session",
		"Exactly one Authorization header carrying a Bearer control-api access",
		"identity.AuthenticateSession",
		"iamlock.AuthorizeSession",
		"HTTP 503 with service_unavailable",
		"never expose SQLSTATE",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("OpenAPI contract is missing %q", required)
		}
	}
	lower := strings.ToLower(source[components:])
	for _, forbidden := range []string{"session-or-api-principal", "api-principal"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("OpenAPI security advertises unsupported credential %q", forbidden)
		}
	}
	for _, declaration := range []string{
		"complete ListResult JSON", "trailing response newline", "2 MiB byte budget",
		"single maximum schema-legal policy", "anchored to the last item emitted",
		"without gaps or duplicates",
	} {
		if !strings.Contains(source, declaration) {
			t.Fatalf("list contract is missing %q", declaration)
		}
	}
}

func TestHTTPPolicySimulatedCanonicalOpenAPISecurity(t *testing.T) {
	repositoryRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	temporaryDir := t.TempDir()
	fragmentPath := filepath.Join(repositoryRoot, "api/control-http-policies.openapi.yaml")
	fragmentReference, err := filepath.Rel(temporaryDir, fragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	fragmentReference = filepath.ToSlash(fragmentReference)
	syntheticPath := filepath.Join(temporaryDir, "control.yaml")
	synthetic := fmt.Sprintf(`openapi: 3.1.0
info:
  title: HTTP Policy Canonical Security Fixture
  version: 0.0.0
paths:
  /v1/tenant-scopes/{tenant_scope_id}/http-policies:
    $ref: '%[1]s#/paths/~1v1~1tenant-scopes~1{tenant_scope_id}~1http-policies'
  /v1/tenant-scopes/{tenant_scope_id}/http-policies/publication-preview:
    $ref: '%[1]s#/paths/~1v1~1tenant-scopes~1{tenant_scope_id}~1http-policies~1publication-preview'
  /v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}:
    $ref: '%[1]s#/paths/~1v1~1tenant-scopes~1{tenant_scope_id}~1http-policies~1{policy_id}'
  /v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/enable:
    $ref: '%[1]s#/paths/~1v1~1tenant-scopes~1{tenant_scope_id}~1http-policies~1{policy_id}~1enable'
  /v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/disable:
    $ref: '%[1]s#/paths/~1v1~1tenant-scopes~1{tenant_scope_id}~1http-policies~1{policy_id}~1disable'
components:
  securitySchemes:
    bearerAuth:
      $ref: '%[1]s#/components/securitySchemes/bearerAuth'
`, fragmentReference)
	if err := os.WriteFile(syntheticPath, []byte(synthetic), 0o600); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(temporaryDir, "control.json")
	command := exec.Command("pnpm", "--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle",
		syntheticPath, "--output", bundlePath)
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bundle canonical control OpenAPI: %v\n%s", err, output)
	}

	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	encoded, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}

	wantOperations := map[string]struct{}{
		"listHTTPPolicies": {}, "createHTTPPolicy": {}, "previewHTTPPolicyPublication": {},
		"getHTTPPolicy": {}, "updateHTTPPolicy": {}, "deleteHTTPPolicy": {},
		"enableHTTPPolicy": {}, "disableHTTPPolicy": {},
	}
	wantSecurity := []map[string][]string{{"bearerAuth": {}}}
	gotOperations := make(map[string]struct{}, len(wantOperations))
	for path, item := range document.Paths {
		for method, raw := range item {
			var operation struct {
				OperationID string                `json:"operationId"`
				Security    []map[string][]string `json:"security"`
			}
			if err := json.Unmarshal(raw, &operation); err != nil {
				continue
			}
			if _, ok := wantOperations[operation.OperationID]; !ok {
				continue
			}
			gotOperations[operation.OperationID] = struct{}{}
			if !reflect.DeepEqual(operation.Security, wantSecurity) {
				t.Errorf("canonical %s %s (%s) security = %#v, want %#v",
					method, path, operation.OperationID, operation.Security, wantSecurity)
			}
		}
	}
	if !reflect.DeepEqual(gotOperations, wantOperations) {
		t.Fatalf("canonical HTTP policy operations = %#v, want %#v", gotOperations, wantOperations)
	}
}

func readHTTPPolicyOpenAPI(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("../../../../api/control-http-policies.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

func parseHTTPPolicyOpenAPIOperations(t *testing.T, source string) []httpPolicyOpenAPIOperation {
	t.Helper()
	var operations []httpPolicyOpenAPIOperation
	var path string
	var current *httpPolicyOpenAPIOperation
	finish := func() {
		if current != nil {
			operations = append(operations, *current)
			current = nil
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "components:" {
			finish()
			break
		}
		if match := httpPolicyOpenAPIPathPattern.FindStringSubmatch(line); match != nil {
			finish()
			path = match[1]
			continue
		}
		if match := httpPolicyOpenAPIMethodPattern.FindStringSubmatch(line); match != nil && path != "" {
			finish()
			current = &httpPolicyOpenAPIOperation{Method: match[1], Path: path}
			continue
		}
		if current == nil {
			continue
		}
		if match := httpPolicyOpenAPIOperationPattern.FindStringSubmatch(line); match != nil {
			current.OperationID = match[1]
		}
		if line == "      security: [{bearerAuth: []}]" {
			current.Security = []map[string][]string{{"bearerAuth": {}}}
		}
		if match := httpPolicyOpenAPIStatusPattern.FindStringSubmatch(line); match != nil {
			current.Statuses = append(current.Statuses, match[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return operations
}
