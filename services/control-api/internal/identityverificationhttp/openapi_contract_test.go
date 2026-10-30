package identityverificationhttp

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

	"github.com/google/uuid"
)

type identityVerificationOpenAPIOperation struct {
	method      string
	path        string
	operationID string
	responses   []string
}

var identityVerificationResponsePattern = regexp.MustCompile(`^        '([0-9]{3})':`)

func TestIdentityVerificationOpenAPIExactlyMatchesHandlerMatrix(t *testing.T) {
	mutation := []string{"200", "400", "401", "403", "404", "405", "409", "422", "408", "503", "504"}
	want := []identityVerificationOpenAPIOperation{
		{"get", apiPrefix + "/status", "getMyIdentityVerificationStatus",
			[]string{"200", "400", "401", "403", "405", "408", "503", "504"}},
		{"post", apiPrefix + "/cases", "createMyIdentityVerificationDraft",
			[]string{"201", "200", "400", "401", "403", "405", "409", "422", "408", "503", "504"}},
		{"get", apiPrefix + "/cases/{case_id}", "getMyIdentityVerificationCase",
			[]string{"200", "400", "401", "403", "404", "405", "408", "503", "504"}},
		{"post", apiPrefix + "/cases/{case_id}/submit", "submitMyIdentityVerificationCase", mutation},
		{"post", apiPrefix + "/cases/{case_id}/withdraw", "withdrawMyIdentityVerificationCase", mutation},
		{"post", apiPrefix + "/cases/{case_id}/expire", "expireMyIdentityVerificationCase", mutation},
		{"get", apiPrefix + "/reviewer/cases", "listTenantIdentityVerificationCases",
			[]string{"200", "400", "401", "403", "405", "408", "503", "504"}},
		{"get", apiPrefix + "/reviewer/cases/{case_id}", "getTenantIdentityVerificationCase",
			[]string{"200", "400", "401", "403", "404", "405", "408", "503", "504"}},
		{"post", apiPrefix + "/reviewer/cases/{case_id}/claim", "claimTenantIdentityVerificationCase", mutation},
		{"post", apiPrefix + "/reviewer/cases/{case_id}/decision", "decideTenantIdentityVerificationCase", mutation},
		{"get", apiPrefix + "/admin/cases", "listPlatformIdentityVerificationCases",
			[]string{"200", "400", "401", "403", "405", "408", "503", "504"}},
		{"post", apiPrefix + "/provider-sessions", "startIdentityVerificationProviderSession",
			[]string{"201", "200", "400", "401", "403", "405", "409", "408", "503", "504"}},
		{"post", apiPrefix + "/provider-sessions/{session_id}/uploads", "createIdentityVerificationPrivateUpload",
			[]string{"201", "200", "400", "401", "403", "404", "405", "409", "408", "503", "504"}},
		{"post", apiPrefix + "/provider-sessions/{session_id}/uploads/{upload_id}/finalize", "finalizeIdentityVerificationPrivateUpload",
			[]string{"200", "400", "401", "403", "404", "405", "409", "422", "408", "503", "504"}},
		{"post", apiPrefix + "/provider-callbacks/{provider}", "acceptIdentityVerificationProviderCallback",
			[]string{"200", "400", "401", "405", "409", "408", "503", "504"}},
	}
	source := readIdentityVerificationOpenAPI(t)
	got := parseIdentityVerificationOpenAPIOperations(t, source, mutation)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenAPI operations = %#v, want %#v", got, want)
	}
	caseID := uuid.NewString()
	sessionID, uploadID := uuid.NewString(), uuid.NewString()
	for _, operation := range got {
		path := strings.ReplaceAll(operation.path, "{case_id}", caseID)
		path = strings.ReplaceAll(path, "{session_id}", sessionID)
		path = strings.ReplaceAll(path, "{upload_id}", uploadID)
		path = strings.ReplaceAll(path, "{provider}", "trusted-kyc")
		if strings.Contains(path, "/provider-") {
			route, matched := resolveProviderRoute(path)
			if !matched || strings.ToLower(route.method) != operation.method {
				t.Fatalf("provider handler route %s %s = %#v matched=%t", operation.method, path, route, matched)
			}
			continue
		}
		route, matched := resolveRoute(path)
		if !matched || strings.ToLower(route.method) != operation.method {
			t.Fatalf("case handler route %s %s = %#v matched=%t", operation.method, path, route, matched)
		}
	}
}

func TestIdentityVerificationOpenAPIResponsesAreConcreteObjects(t *testing.T) {
	source := readIdentityVerificationOpenAPI(t)
	if strings.Contains(source, "responses: {$ref: '#/components/x-responses/MutationResponses'}") {
		t.Fatal("an Operation responses field must be a Responses Object, not a Reference Object")
	}
}

func TestIAM10IdentityVerificationOpenAPIBindsDecisionReasonToTerminalStatus(t *testing.T) {
	source := readIdentityVerificationOpenAPI(t)
	for _, required := range []string{
		"decision_reason_code:", "const: approved", "const: rejected", "const: evidence_verified",
		"identity_mismatch", "evidence_incomplete", "evidence_unreadable", "organization_mismatch",
		"authorization_invalid", "suspected_fraud", "not: {required: [decision_reason_code]}",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("decision reason OpenAPI contract missing %q", required)
		}
	}
}

func TestIdentityVerificationOpenAPIErrorResponsesExposeRequestID(t *testing.T) {
	source := readIdentityVerificationOpenAPI(t)
	errorReferencePattern := regexp.MustCompile(`(?m)^        '[45][0-9]{2}': \{\$ref: '#/components/responses/([A-Za-z0-9]+)'\}$`)
	errorResponses := map[string]struct{}{}
	for _, match := range errorReferencePattern.FindAllStringSubmatch(source, -1) {
		errorResponses[match[1]] = struct{}{}
	}
	if len(errorResponses) == 0 {
		t.Fatal("no error response references found")
	}

	components := strings.Index(source, "\ncomponents:\n")
	if components < 0 {
		t.Fatal("OpenAPI components section not found")
	}
	responseOffset := strings.Index(source[components:], "\n  responses:\n")
	if responseOffset < 0 {
		t.Fatal("OpenAPI component responses section not found")
	}
	responseSection := source[components+responseOffset:]
	const requestIDHeader = "\n        X-Request-ID: {$ref: '#/components/headers/RequestID'}\n"
	nextResponsePattern := regexp.MustCompile(`(?m)^    [A-Za-z0-9]+:\n`)
	for name := range errorResponses {
		marker := "\n    " + name + ":\n"
		start := strings.Index(responseSection, marker)
		if start < 0 {
			t.Fatalf("component response %s not found", name)
		}
		block := responseSection[start+len(marker):]
		if end := nextResponsePattern.FindStringIndex(block); end != nil {
			block = block[:end[0]]
		}
		if !strings.Contains("\n"+block, requestIDHeader) {
			t.Fatalf("component response %s does not expose X-Request-ID", name)
		}
	}
}

func TestIdentityVerificationOpenAPIUsesOnlyControlSessionSecurity(t *testing.T) {
	source := readIdentityVerificationOpenAPI(t)
	paths := strings.Index(source, "\npaths:\n")
	components := strings.Index(source, "\ncomponents:\n")
	if paths < 0 || components <= paths {
		t.Fatal("OpenAPI paths/components sections not found")
	}
	if strings.Count(source[:paths], "\nsecurity:\n  - bearerAuth: []\n") != 1 {
		t.Fatal("global bearerAuth is missing or duplicated")
	}
	if got := strings.Count(source[paths:components], "\n      security: [{bearerAuth: []}]\n"); got != 14 {
		t.Fatalf("operation-level bearerAuth declarations = %d, want 14", got)
	}
	for _, required := range []string{
		"type: http", "scheme: bearer", "bearerFormat: control-api-session",
		"Exactly one Authorization header carrying a canonical Bearer control-api session",
		"API keys and client-supplied actor headers are rejected", "identity.AuthenticateSession",
		"live no-business-write IAM preflight", "that preflight is not final authority",
		"iamlock.AuthorizeSession inside the same business PostgreSQL transaction",
		"before idempotency, business row locks, DML, or audit append",
		"Allow: {$ref: '#/components/headers/Allow'}",
	} {
		if !strings.Contains(source[components:], required) {
			t.Fatalf("bearerAuth contract is missing %q", required)
		}
	}
}

func TestIdentityVerificationCanonicalOpenAPISecurity(t *testing.T) {
	repositoryRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "control.json")
	command := exec.Command("pnpm", "--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle",
		filepath.Join(repositoryRoot, "api/openapi/v1/control.yaml"), "--output", bundlePath)
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bundle canonical control OpenAPI: %v\n%s", err, output)
	}

	type operation struct {
		Security []map[string][]string `json:"security"`
	}
	type pathItem struct {
		Get  operation `json:"get"`
		Post operation `json:"post"`
	}
	var document struct {
		Paths map[string]pathItem `json:"paths"`
	}
	encoded, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}

	operations := map[string]string{
		apiPrefix + "/status":                            "get",
		apiPrefix + "/cases":                             "post",
		apiPrefix + "/cases/{case_id}":                   "get",
		apiPrefix + "/cases/{case_id}/submit":            "post",
		apiPrefix + "/cases/{case_id}/withdraw":          "post",
		apiPrefix + "/cases/{case_id}/expire":            "post",
		apiPrefix + "/reviewer/cases":                    "get",
		apiPrefix + "/reviewer/cases/{case_id}":          "get",
		apiPrefix + "/reviewer/cases/{case_id}/claim":    "post",
		apiPrefix + "/reviewer/cases/{case_id}/decision": "post",
		apiPrefix + "/admin/cases":                       "get",
	}
	for path, method := range operations {
		item := document.Paths[path]
		got := item.Get.Security
		if method == "post" {
			got = item.Post.Security
		}
		want := []map[string][]string{{"bearerAuth": {}}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("canonical %s %s security = %#v, want %#v", method, path, got, want)
		}
	}
}

func readIdentityVerificationOpenAPI(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("../../../../api/control-identity-verification.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

func parseIdentityVerificationOpenAPIOperations(t *testing.T, source string,
	mutationResponses []string,
) []identityVerificationOpenAPIOperation {
	t.Helper()
	var result []identityVerificationOpenAPIOperation
	var path string
	var current *identityVerificationOpenAPIOperation
	finish := func() {
		if current != nil {
			result = append(result, *current)
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
		if strings.HasPrefix(line, "  /v1/identity-verification/") && strings.HasSuffix(line, ":") {
			finish()
			path = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if (line == "    get:" || line == "    post:") && path != "" {
			finish()
			current = &identityVerificationOpenAPIOperation{method: strings.TrimSuffix(strings.TrimSpace(line), ":"), path: path}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "      operationId: ") {
			current.operationID = strings.TrimSpace(strings.TrimPrefix(line, "      operationId: "))
		}
		if match := identityVerificationResponsePattern.FindStringSubmatch(line); match != nil {
			current.responses = append(current.responses, match[1])
		}
		if line == "      responses: *mutationResponses" {
			current.responses = append([]string(nil), mutationResponses...)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}
