package challengepolicy

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
	challengeOpenAPIPathPattern      = regexp.MustCompile(`^  (/[^:]+):$`)
	challengeOpenAPIMethodPattern    = regexp.MustCompile(`^    (get|put|post|delete|options|head|patch|trace):$`)
	challengeOpenAPIOperationPattern = regexp.MustCompile(`^      operationId: ([A-Za-z0-9]+)$`)
	challengeOpenAPIStatusPattern    = regexp.MustCompile(`^        '([0-9]{3})':`)
)

type challengeOpenAPIOperation struct {
	Method      string
	Path        string
	OperationID string
	Statuses    []string
}

func TestChallengePolicyOpenAPIOperationContract(t *testing.T) {
	source := readChallengeOpenAPI(t)
	want := []challengeOpenAPIOperation{
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies", OperationID: "listChallengePolicies", Statuses: []string{"200", "400", "401", "403", "404", "405", "422", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies", OperationID: "createChallengePolicy", Statuses: []string{"201", "400", "401", "403", "404", "405", "409", "422", "503"}},
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}", OperationID: "getChallengePolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "503"}},
		{Method: "patch", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}", OperationID: "updateChallengePolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{Method: "delete", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}", OperationID: "deleteChallengePolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/enable", OperationID: "enableChallengePolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/disable", OperationID: "disableChallengePolicy", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications", OperationID: "publishChallengePolicy", Statuses: []string{"202", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}", OperationID: "getChallengePolicyPublication", Statuses: []string{"200", "400", "401", "403", "404", "405", "503"}},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}/promote", OperationID: "promoteChallengePolicyPublication", Statuses: []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
	}
	if got := parseChallengeOpenAPIOperations(t, source); !reflect.DeepEqual(got, want) {
		t.Fatalf("operations = %#v, want %#v", got, want)
	}
}

func TestChallengePolicyOpenAPIGlobalSessionSecurity(t *testing.T) {
	source := readChallengeOpenAPI(t)
	paths := strings.Index(source, "\npaths:\n")
	if paths < 0 {
		t.Fatal("paths section not found")
	}
	header := source[:paths]
	if strings.Count(header, "\nsecurity:\n  - bearerAuth: []\n") != 1 {
		t.Fatal("global bearer security is missing or duplicated")
	}
	for _, declaration := range []string{
		"    bearerAuth:\n      type: http\n      scheme: bearer\n",
		"      bearerFormat: control-api-session\n",
		"Exactly one Bearer header carrying a live control-api session",
	} {
		if !strings.Contains(source, declaration) {
			t.Fatalf("session security declaration %q not found", declaration)
		}
	}
}

func TestChallengePolicyOpenAPIOperationBearerSecurity(t *testing.T) {
	repositoryRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	fragmentPath := filepath.Join(repositoryRoot, "api/control-challenge-policies.openapi.yaml")
	assertChallengePolicyBundledBearerSecurity(t, repositoryRoot, fragmentPath)

	temporaryDirectory := t.TempDir()
	relativeFragmentPath, err := filepath.Rel(temporaryDirectory, fragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	var canonical strings.Builder
	canonical.WriteString("openapi: 3.1.0\ninfo:\n  title: Challenge policy canonical security test\n  version: 1.0.0\n")
	canonical.WriteString("security:\n  - bearerAuth: []\npaths:\n")
	for _, path := range challengePolicyOpenAPIPaths() {
		canonical.WriteString("  " + path + ":\n")
		canonical.WriteString("    $ref: '" + filepath.ToSlash(relativeFragmentPath) + "#/paths/" +
			strings.ReplaceAll(path, "/", "~1") + "'\n")
	}
	canonical.WriteString("components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer\n")
	canonicalPath := filepath.Join(temporaryDirectory, "control.yaml")
	if err := os.WriteFile(canonicalPath, []byte(canonical.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	assertChallengePolicyBundledBearerSecurity(t, repositoryRoot, canonicalPath)
}

func assertChallengePolicyBundledBearerSecurity(t *testing.T, repositoryRoot, sourcePath string) {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), "control.json")
	command := exec.Command("pnpm", "--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle",
		sourcePath, "--output", bundlePath)
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bundle OpenAPI %s: %v\n%s", sourcePath, err, output)
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
	if len(document.Paths) != 7 {
		t.Fatalf("bundled challenge-policy paths = %d, want 7", len(document.Paths))
	}

	wantSecurity := []map[string][]string{{"bearerAuth": {}}}
	operations := 0
	for _, contract := range []challengeOpenAPIOperation{
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies", OperationID: "listChallengePolicies"},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies", OperationID: "createChallengePolicy"},
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}", OperationID: "getChallengePolicy"},
		{Method: "patch", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}", OperationID: "updateChallengePolicy"},
		{Method: "delete", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}", OperationID: "deleteChallengePolicy"},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/enable", OperationID: "enableChallengePolicy"},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/disable", OperationID: "disableChallengePolicy"},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications", OperationID: "publishChallengePolicy"},
		{Method: "get", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}", OperationID: "getChallengePolicyPublication"},
		{Method: "post", Path: "/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}/promote", OperationID: "promoteChallengePolicyPublication"},
	} {
		raw, ok := document.Paths[contract.Path][contract.Method]
		if !ok {
			t.Errorf("bundled %s %s is missing", contract.Method, contract.Path)
			continue
		}
		var operation struct {
			OperationID string                `json:"operationId"`
			Security    []map[string][]string `json:"security"`
		}
		if err := json.Unmarshal(raw, &operation); err != nil {
			t.Fatalf("decode %s %s: %v", contract.Method, contract.Path, err)
		}
		if operation.OperationID != contract.OperationID {
			t.Errorf("bundled %s %s operationId = %q, want %q",
				contract.Method, contract.Path, operation.OperationID, contract.OperationID)
		}
		if !reflect.DeepEqual(operation.Security, wantSecurity) {
			t.Errorf("bundled %s %s (%s) security = %#v, want %#v",
				contract.Method, contract.Path, operation.OperationID, operation.Security, wantSecurity)
		}
		operations++
	}
	if operations != 10 {
		t.Fatalf("bundled challenge-policy operations = %d, want 10", operations)
	}
}

func challengePolicyOpenAPIPaths() []string {
	return []string{
		"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies",
		"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}",
		"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/enable",
		"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/disable",
		"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications",
		"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}",
		"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}/promote",
	}
}

func TestChallengePolicyOpenAPIListBudgetContract(t *testing.T) {
	block := challengeOpenAPIOperationBlock(t, readChallengeOpenAPI(t), "listChallengePolicies")
	for _, declaration := range []string{
		"default 256 KiB response byte budget",
		"next_cursor resumes after the last",
		"emitted item",
		"'422': {$ref: '#/components/responses/UnprocessableEntity'}",
	} {
		if !strings.Contains(block, declaration) {
			t.Fatalf("list contract declaration %q not found", declaration)
		}
	}
}

func readChallengeOpenAPI(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("../../../../api/control-challenge-policies.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

func parseChallengeOpenAPIOperations(t *testing.T, source string) []challengeOpenAPIOperation {
	t.Helper()
	var result []challengeOpenAPIOperation
	var currentPath string
	var current *challengeOpenAPIOperation
	finish := func() {
		if current == nil {
			return
		}
		if current.OperationID == "" {
			t.Fatalf("%s %s has no operationId", current.Method, current.Path)
		}
		result = append(result, *current)
		current = nil
	}
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		line := scanner.Text()
		if match := challengeOpenAPIPathPattern.FindStringSubmatch(line); match != nil {
			finish()
			currentPath = match[1]
			continue
		}
		if line == "components:" {
			finish()
			currentPath = ""
			continue
		}
		if match := challengeOpenAPIMethodPattern.FindStringSubmatch(line); match != nil && currentPath != "" {
			finish()
			current = &challengeOpenAPIOperation{Method: match[1], Path: currentPath}
			continue
		}
		if current == nil {
			continue
		}
		if match := challengeOpenAPIOperationPattern.FindStringSubmatch(line); match != nil {
			if current.OperationID != "" {
				t.Fatalf("%s %s has duplicate operationId", current.Method, current.Path)
			}
			current.OperationID = match[1]
			continue
		}
		if match := challengeOpenAPIStatusPattern.FindStringSubmatch(line); match != nil {
			current.Statuses = append(current.Statuses, match[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	finish()
	return result
}

func challengeOpenAPIOperationBlock(t *testing.T, source, operationID string) string {
	t.Helper()
	marker := "      operationId: " + operationID
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("operationId %q not found", operationID)
	}
	remainder := source[start+len(marker):]
	end := len(remainder)
	for _, boundary := range []string{
		"\n    get:", "\n    put:", "\n    post:", "\n    delete:",
		"\n    options:", "\n    head:", "\n    patch:", "\n    trace:",
		"\n  /", "\ncomponents:",
	} {
		if index := strings.Index(remainder, boundary); index >= 0 && index < end {
			end = index
		}
	}
	return remainder[:end]
}
