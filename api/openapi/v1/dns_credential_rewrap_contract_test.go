package v1

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDNSCredentialRewrapOpenAPIContract(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "dns-credential-rewrap.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("parse dns-credential-rewrap.yaml: %v", err)
	}
	if got := rewrapString(t, document, "openapi"); got != "3.1.0" {
		t.Fatalf("openapi = %q, want 3.1.0", got)
	}

	paths := rewrapMap(t, document, "paths")
	wantPaths := map[string]string{
		"/v1/admin/dns-credential-rewrap/jobs":          "post",
		"/v1/admin/dns-credential-rewrap/jobs/{job_id}": "get",
	}
	if len(paths) != len(wantPaths) {
		t.Fatalf("paths = %v, want exactly %v", rewrapSortedKeys(paths), rewrapSortedKeys(wantPaths))
	}
	operations := make(map[string]map[string]any, len(wantPaths))
	for path, method := range wantPaths {
		pathItem := rewrapMap(t, paths, path)
		if got := rewrapSortedKeys(pathItem); !reflect.DeepEqual(got, []string{method}) {
			t.Fatalf("%s methods = %v, want only %s", path, got, method)
		}
		operation := rewrapMap(t, pathItem, method)
		rewrapAssertAdminSessionOnly(t, method+" "+path, operation)
		operations[method] = operation
	}

	post := operations["post"]
	if got := rewrapString(t, post, "operationId"); got != "createDNSCredentialRewrapJob" {
		t.Fatalf("POST operationId = %q", got)
	}
	rewrapAssertResponseSet(t, "POST", post, "202", "400", "401", "403", "405", "409", "503")
	rewrapAssertParameterRefs(t, post,
		"#/components/parameters/IdempotencyKey",
		"#/components/parameters/RequestID",
	)
	requestSchema := rewrapMap(t, rewrapMap(t,
		rewrapMap(t, rewrapMap(t, post, "requestBody"), "content"), "application/json"), "schema")
	rewrapAssertClosedObject(t, "batch request", requestSchema, []string{"items"})
	items := rewrapMap(t, rewrapMap(t, requestSchema, "properties"), "items")
	if rewrapInt(t, items, "minItems") != 1 || rewrapInt(t, items, "maxItems") != 100 {
		t.Fatalf("items bounds = %v..%v, want 1..100", items["minItems"], items["maxItems"])
	}
	if unique, ok := items["uniqueItems"].(bool); !ok || !unique {
		t.Fatal("items must be unique")
	}
	itemSchema := rewrapMap(t, items, "items")
	rewrapAssertClosedObject(t, "batch item", itemSchema, []string{"expected_revision", "provider_id"})
	itemProperties := rewrapMap(t, itemSchema, "properties")
	if got := rewrapString(t, rewrapMap(t, itemProperties, "provider_id"), "format"); got != "uuid" {
		t.Fatalf("provider_id format = %q", got)
	}
	if got := rewrapInt(t, rewrapMap(t, itemProperties, "expected_revision"), "minimum"); got != 1 {
		t.Fatalf("expected_revision minimum = %d", got)
	}
	for _, forbidden := range []string{"item_idempotency_key", "scope_id", "tenant_id"} {
		if _, ok := itemProperties[forbidden]; ok {
			t.Fatalf("batch item exposes server-derived field %q", forbidden)
		}
	}

	get := operations["get"]
	if got := rewrapString(t, get, "operationId"); got != "getDNSCredentialRewrapJob" {
		t.Fatalf("GET operationId = %q", got)
	}
	rewrapAssertResponseSet(t, "GET", get, "202", "400", "401", "403", "404", "405", "503")
	rewrapAssertParameterRefs(t, get,
		"#/components/parameters/JobID",
		"#/components/parameters/RequestID",
	)

	for name, operation := range operations {
		response := rewrapMap(t, rewrapMap(t, operation, "responses"), "202")
		media := rewrapMap(t, rewrapMap(t, response, "content"), "application/json")
		if got := rewrapString(t, rewrapMap(t, media, "schema"), "$ref"); got != "#/components/schemas/RewrapJob" {
			t.Fatalf("%s success schema = %q", name, got)
		}
		rewrapAssertNoStore(t, name, response)
	}

	components := rewrapMap(t, document, "components")
	rewrapAssertHeaderParameter(t, rewrapMap(t, rewrapMap(t, components, "parameters"), "IdempotencyKey"), "Idempotency-Key")
	rewrapAssertHeaderParameter(t, rewrapMap(t, rewrapMap(t, components, "parameters"), "RequestID"), "X-Request-ID")

	schemas := rewrapMap(t, components, "schemas")
	job := rewrapMap(t, schemas, "RewrapJob")
	rewrapAssertClosedObject(t, "job", job, []string{
		"completed", "conflicted", "created_at", "failed", "items", "job_id",
		"replayed", "requested", "status", "succeeded", "updated_at",
	})
	jobProperties := rewrapMap(t, job, "properties")
	wantJobFields := []string{
		"completed", "completed_at", "conflicted", "created_at", "failed", "items",
		"job_id", "replayed", "requested", "status", "succeeded", "updated_at",
	}
	if got := rewrapSortedKeys(jobProperties); !reflect.DeepEqual(got, wantJobFields) {
		t.Fatalf("job fields = %v, want %v", got, wantJobFields)
	}
	if got := rewrapString(t, rewrapMap(t, jobProperties, "job_id"), "format"); got != "uuid" {
		t.Fatalf("job_id format = %q", got)
	}
	for _, field := range []string{"created_at", "updated_at", "completed_at"} {
		if got := rewrapString(t, rewrapMap(t, jobProperties, field), "format"); got != "date-time" {
			t.Fatalf("%s format = %q", field, got)
		}
	}
	jobStatus := rewrapMap(t, jobProperties, "status")
	if got := rewrapSortedStrings(t, jobStatus, "enum"); !reflect.DeepEqual(got, []string{"completed", "completed_with_errors", "processing"}) {
		t.Fatalf("job statuses = %v", got)
	}
	result := rewrapMap(t, schemas, "RewrapItemProgress")
	rewrapAssertClosedObject(t, "item progress", result, []string{"expected_revision", "provider_id", "status"})
	resultProperties := rewrapMap(t, result, "properties")
	wantItemFields := []string{"credential_version", "error_code", "expected_revision", "provider_id", "revision", "status"}
	if got := rewrapSortedKeys(resultProperties); !reflect.DeepEqual(got, wantItemFields) {
		t.Fatalf("item progress fields = %v, want %v", got, wantItemFields)
	}
	itemStatus := rewrapMap(t, resultProperties, "status")
	if got := rewrapSortedStrings(t, itemStatus, "enum"); !reflect.DeepEqual(got, []string{"completed", "conflict", "failed", "pending", "replayed"}) {
		t.Fatalf("item statuses = %v", got)
	}
	itemError := rewrapMap(t, resultProperties, "error_code")
	wantItemErrors := []string{
		"credential_unavailable", "idempotency_conflict", "operation_failed", "provider_not_found", "revision_conflict",
	}
	if got := rewrapSortedStrings(t, itemError, "enum"); !reflect.DeepEqual(got, wantItemErrors) {
		t.Fatalf("item error codes = %v, want %v", got, wantItemErrors)
	}

	errorSchema := rewrapMap(t, schemas, "Error")
	rewrapAssertClosedObject(t, "error", errorSchema, []string{"error"})
	errorObject := rewrapMap(t, rewrapMap(t, errorSchema, "properties"), "error")
	rewrapAssertClosedObject(t, "error body", errorObject, []string{"code"})
	wantCodes := []string{
		"dns_credential_rewrap_authentication_required",
		"dns_credential_rewrap_idempotency_conflict",
		"dns_credential_rewrap_invalid_request",
		"dns_credential_rewrap_job_not_found",
		"dns_credential_rewrap_method_not_allowed",
		"dns_credential_rewrap_permission_denied",
		"dns_credential_rewrap_unavailable",
	}
	if got := rewrapSortedStrings(t, rewrapMap(t, rewrapMap(t, errorObject, "properties"), "code"), "enum"); !reflect.DeepEqual(got, wantCodes) {
		t.Fatalf("stable error codes = %v, want %v", got, wantCodes)
	}

	for _, forbidden := range []string{"ciphertext", "credential_ciphertext", "credential_key_id", "credentials", "key_id", "secret"} {
		if rewrapContainsKey(document, forbidden) {
			t.Fatalf("response contract exposes forbidden field %q", forbidden)
		}
	}
	serialized := strings.ToLower(string(source))
	for _, forbidden := range []string{"api_token", "access_key_secret", "secret_key", "api_secret"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("contract contains forbidden credential field %q", forbidden)
		}
	}
}

func rewrapAssertAdminSessionOnly(t *testing.T, name string, operation map[string]any) {
	t.Helper()
	security := rewrapSlice(t, operation, "security")
	if len(security) != 1 {
		t.Fatalf("%s security entries = %d, want 1", name, len(security))
	}
	requirement, ok := security[0].(map[string]any)
	if !ok || len(requirement) != 1 {
		t.Fatalf("%s security = %#v", name, security)
	}
	if scopes, ok := requirement["bearerSession"].([]any); !ok || len(scopes) != 0 {
		t.Fatalf("%s must require bearerSession without alternate auth", name)
	}
	if got := rewrapSortedStrings(t, operation, "x-required-permissions"); !reflect.DeepEqual(got, []string{"platform.admin"}) {
		t.Fatalf("%s permissions = %v, want live platform.admin", name, got)
	}
	for _, key := range []string{"x-session-only", "x-live-permission-check", "x-platform-scope-only"} {
		if value, ok := operation[key].(bool); !ok || !value {
			t.Fatalf("%s must set %s: true", name, key)
		}
	}
	for _, key := range []string{"x-api-key-allowed", "x-tenant-allowed", "x-workload-identity-allowed"} {
		if value, ok := operation[key].(bool); !ok || value {
			t.Fatalf("%s must set %s: false", name, key)
		}
	}
}

func rewrapAssertResponseSet(t *testing.T, name string, operation map[string]any, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := rewrapSortedKeys(rewrapMap(t, operation, "responses")); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s responses = %v, want %v", name, got, want)
	}
}

func rewrapAssertParameterRefs(t *testing.T, operation map[string]any, want ...string) {
	t.Helper()
	raw := rewrapSlice(t, operation, "parameters")
	got := make([]string, len(raw))
	for index, value := range raw {
		parameter, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("parameter %d = %#v", index, value)
		}
		got[index] = rewrapString(t, parameter, "$ref")
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parameter refs = %v, want %v", got, want)
	}
}

func rewrapAssertHeaderParameter(t *testing.T, parameter map[string]any, name string) {
	t.Helper()
	if rewrapString(t, parameter, "name") != name || rewrapString(t, parameter, "in") != "header" {
		t.Fatalf("header parameter = %#v, want %s", parameter, name)
	}
	if required, ok := parameter["required"].(bool); !ok || !required {
		t.Fatalf("%s must be required", name)
	}
	schema := rewrapMap(t, parameter, "schema")
	if rewrapInt(t, schema, "minLength") != 1 || rewrapInt(t, schema, "maxLength") != 128 {
		t.Fatalf("%s length bounds = %#v", name, schema)
	}
}

func rewrapAssertNoStore(t *testing.T, name string, response map[string]any) {
	t.Helper()
	headers := rewrapMap(t, response, "headers")
	for header, ref := range map[string]string{
		"Cache-Control":          "#/components/headers/NoStore",
		"X-Content-Type-Options": "#/components/headers/NoSniff",
	} {
		if got := rewrapString(t, rewrapMap(t, headers, header), "$ref"); got != ref {
			t.Fatalf("%s %s = %q, want %q", name, header, got, ref)
		}
	}
}

func rewrapAssertClosedObject(t *testing.T, name string, schema map[string]any, required []string) {
	t.Helper()
	if got := rewrapString(t, schema, "type"); got != "object" {
		t.Fatalf("%s type = %q", name, got)
	}
	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("%s must set additionalProperties: false", name)
	}
	sort.Strings(required)
	if got := rewrapSortedStrings(t, schema, "required"); !reflect.DeepEqual(got, required) {
		t.Fatalf("%s required = %v, want %v", name, got, required)
	}
}

func rewrapContainsKey(value any, forbidden string) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == forbidden || rewrapContainsKey(child, forbidden) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if rewrapContainsKey(child, forbidden) {
				return true
			}
		}
	}
	return false
}

func rewrapMap(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%q = %#v, want object", key, object[key])
	}
	return value
}

func rewrapSlice(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	value, ok := object[key].([]any)
	if !ok {
		t.Fatalf("%q = %#v, want array", key, object[key])
	}
	return value
}

func rewrapString(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("%q = %#v, want string", key, object[key])
	}
	return value
}

func rewrapInt(t *testing.T, object map[string]any, key string) int {
	t.Helper()
	value, ok := object[key].(int)
	if !ok {
		t.Fatalf("%q = %#v, want integer", key, object[key])
	}
	return value
}

func rewrapSortedKeys[T any](object map[string]T) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func rewrapSortedStrings(t *testing.T, object map[string]any, key string) []string {
	t.Helper()
	values := rewrapSlice(t, object, key)
	result := make([]string, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s[%d] = %#v, want string", key, index, value)
		}
		result[index] = text
	}
	sort.Strings(result)
	return result
}
