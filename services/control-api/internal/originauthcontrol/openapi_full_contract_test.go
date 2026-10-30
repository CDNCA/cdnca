package originauthcontrol

import (
	"bufio"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

type fullOpenAPIOperation struct {
	Method      string
	Path        string
	OperationID string
	Responses   []string
}

var (
	fullOpenAPIPathPattern     = regexp.MustCompile(`^  (/[^:]+):$`)
	fullOpenAPIMethodPattern   = regexp.MustCompile(`^    (get|post|put|patch|delete):$`)
	fullOpenAPIResponsePattern = regexp.MustCompile(`^        '([0-9]{3})':`)
)

func TestOpenAPIFullOperationContract(t *testing.T) {
	source := readFullOpenAPIFragment(t)
	want := []fullOpenAPIOperation{
		{"GET", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials", "listOriginAuthCredentials", []string{"200", "400", "401", "403", "404", "405", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials", "createOriginAuthCredential", []string{"201", "400", "401", "403", "404", "405", "409", "422", "503"}},
		{"GET", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}", "getOriginAuthCredential", []string{"200", "400", "401", "403", "404", "405", "503"}},
		{"DELETE", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}", "deleteOriginAuthCredential", []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}/replace", "replaceOriginAuthCredential", []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}/verify", "verifyOriginAuthCredential", []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}/disable", "disableOriginAuthCredential", []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{"GET", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules", "listOriginAuthRules", []string{"200", "400", "401", "403", "404", "405", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules", "createOriginAuthRule", []string{"201", "400", "401", "403", "404", "405", "409", "422", "503"}},
		{"GET", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}", "getOriginAuthRule", []string{"200", "400", "401", "403", "404", "405", "503"}},
		{"PATCH", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}", "updateOriginAuthRule", []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{"DELETE", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}", "deleteOriginAuthRule", []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}/enable", "enableOriginAuthRule", []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}/disable", "disableOriginAuthRule", []string{"200", "400", "401", "403", "404", "405", "409", "412", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}/rotate", "rotateOriginAuthRuleCredential", []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
		{"GET", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/publications", "getLatestOriginAuthPublication", []string{"200", "400", "401", "403", "404", "405", "503"}},
		{"POST", "/v1/tenant-scopes/{tenant_scope_id}/origin-auth/publications", "createOriginAuthPublication", []string{"201", "400", "401", "403", "404", "405", "409", "412", "422", "503"}},
	}
	got := parseFullOpenAPIOperations(t, source)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("operation contract = %#v, want %#v", got, want)
	}
}

func TestOpenAPIFullContractSecurityAndPublicationBounds(t *testing.T) {
	source := readFullOpenAPIFragment(t)
	header := fullOpenAPISection(t, source, "openapi:", "paths:")
	if strings.Count(header, "\nsecurity:\n") != 1 ||
		!strings.Contains(header, "\nsecurity:\n  - bearerAuth: []\n") {
		t.Fatalf("global Bearer security changed: %s", header)
	}
	paths := fullOpenAPISection(t, source, "paths:", "components:")
	if strings.Contains(paths, "\n      security:") {
		t.Fatal("an operation overrides the global Bearer security")
	}
	bearer := fullOpenAPISection(t, source, "    bearerAuth:\n", "\n  parameters:")
	for _, required := range []string{
		"type: http",
		"scheme: bearer",
		"bearerFormat: access-session",
		"Accepts only a Bearer access session",
		"identity.AuthenticateSession",
		"iamlock.AuthorizeSession",
	} {
		if !strings.Contains(bearer, required) {
			t.Fatalf("bearerAuth is missing %q: %s", required, bearer)
		}
	}
	lowerBearer := strings.ToLower(bearer)
	for _, forbidden := range []string{"session-or-api-principal", "api-principal", "api principal", "api key"} {
		if strings.Contains(lowerBearer, forbidden) {
			t.Fatalf("bearerAuth promises unsupported credential %q: %s", forbidden, bearer)
		}
	}

	publicationRule := fullOpenAPISection(t, source, "    PublicationRule:\n", "    PublicationSnapshot:\n")
	for _, constraint := range []string{
		"required: [rule_id, site_id, source_position, provider, algorithm, endpoint, bucket, path_prefix, region, service, signature_ttl_seconds, current_credential_revision_ref, activate_current_at_unix]",
		"source_position: {type: integer, minimum: 1, maximum: 32}",
		"provider: {$ref: '#/components/schemas/Provider'}",
		"enum: [aws4-hmac-sha256, oss4-hmac-sha256, cos-hmac-sha1]",
		"endpoint: {type: string, format: uri, maxLength: 512}",
		"bucket: {type: string, maxLength: 63}",
		"path_prefix: {type: string, minLength: 1, maxLength: 2048}",
		"region: {type: string, minLength: 2, maxLength: 64}",
		"service: {type: string, minLength: 2, maxLength: 64}",
		"signature_ttl_seconds: {type: integer, minimum: 1, maximum: 3600}",
		"activate_current_at_unix: {type: integer, minimum: 0}",
	} {
		if !strings.Contains(publicationRule, constraint) {
			t.Fatalf("PublicationRule is missing %q: %s", constraint, publicationRule)
		}
	}
	publicationSnapshot := fullOpenAPISection(t, source, "    PublicationSnapshot:\n", "    Publication:\n")
	if !strings.Contains(publicationSnapshot,
		"rules: {type: array, maxItems: 10000, items: {$ref: '#/components/schemas/PublicationRule'}}") {
		t.Fatalf("PublicationSnapshot rule bound changed: %s", publicationSnapshot)
	}
}

func TestOpenAPIMethodNotAllowedResponseContract(t *testing.T) {
	source := readFullOpenAPIFragment(t)
	response := fullOpenAPISection(t, source, "    MethodNotAllowed:\n", "    Conflict:\n")
	for _, required := range []string{
		"Request method is not allowed for this route.",
		"Allow:",
		"X-Request-ID: {$ref: '#/components/headers/RequestID'}",
		"X-Trace-ID: {$ref: '#/components/headers/TraceID'}",
		"application/json: {schema: {$ref: '#/components/schemas/APIError'}}",
	} {
		if !strings.Contains(response, required) {
			t.Fatalf("MethodNotAllowed is missing %q: %s", required, response)
		}
	}
}

func readFullOpenAPIFragment(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("../../../../api/control-origin-auth.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

func parseFullOpenAPIOperations(t *testing.T, source string) []fullOpenAPIOperation {
	t.Helper()
	var operations []fullOpenAPIOperation
	var path, method string
	inPaths := false
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "paths:" {
			inPaths = true
			continue
		}
		if line == "components:" {
			break
		}
		if !inPaths {
			continue
		}
		if match := fullOpenAPIPathPattern.FindStringSubmatch(line); match != nil {
			path, method = match[1], ""
			continue
		}
		if match := fullOpenAPIMethodPattern.FindStringSubmatch(line); match != nil {
			method = strings.ToUpper(match[1])
			continue
		}
		if strings.HasPrefix(line, "      operationId: ") {
			if path == "" || method == "" {
				t.Fatalf("operation without method or path: %q", line)
			}
			operations = append(operations, fullOpenAPIOperation{
				Method: method, Path: path,
				OperationID: strings.TrimPrefix(line, "      operationId: "),
			})
			continue
		}
		if match := fullOpenAPIResponsePattern.FindStringSubmatch(line); match != nil && len(operations) > 0 {
			operations[len(operations)-1].Responses = append(operations[len(operations)-1].Responses, match[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return operations
}

func fullOpenAPISection(t *testing.T, source, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("start marker %q not found", startMarker)
	}
	remainder := source[start:]
	end := strings.Index(remainder, endMarker)
	if end <= 0 {
		t.Fatalf("end marker %q not found after %q", endMarker, startMarker)
	}
	return remainder[:end]
}
