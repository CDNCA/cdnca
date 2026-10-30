package v1

import (
	"os"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestObservabilityLogOpenAPIContract(t *testing.T) {
	source, err := os.ReadFile("observability-log.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("parse observability-log.yaml: %v", err)
	}
	if got := stringValue(t, document, "openapi"); got != "3.1.0" {
		t.Fatalf("openapi = %q, want 3.1.0", got)
	}

	paths := mapValue(t, document, "paths")
	wantMethods := map[string]string{
		"/v1/observability/logs":            "get",
		"/v1/observability/logs/export":     "get",
		"/v1/observability/frontend-events": "post",
	}
	if len(paths) != len(wantMethods) {
		t.Fatalf("paths = %d, want exactly %d", len(paths), len(wantMethods))
	}
	for path, method := range wantMethods {
		pathItem := mapValue(t, paths, path)
		if len(pathItem) != 1 {
			t.Fatalf("%s methods = %v, want only %s", path, sortedKeys(pathItem), method)
		}
		operation := mapValue(t, pathItem, method)
		assertSessionOnly(t, path+" "+method, operation)
	}

	list := mapValue(t, mapValue(t, paths, "/v1/observability/logs"), "get")
	assertStatusSet(t, "list", list, "200", "400", "401", "403", "503")
	assertScopeContract(t, list)
	assertParameterSet(t, "list", list, "action", "action_verb", "actor_user_id", "after_audit_boundary", "audit_boundary", "change", "cursor", "from", "kind", "limit", "resource_id", "resource_type", "result", "source_ip", "target_scope_id", "to")
	listPage := mapValue(t, mapValue(t, mapValue(t, mapValue(t, list, "responses"), "200"), "content"), "application/json")
	if got := stringValue(t, mapValue(t, listPage, "schema"), "$ref"); got != "#/components/schemas/LogPage" {
		t.Fatalf("list response schema = %q", got)
	}
	pageSchema := mapValue(t, mapValue(t, componentsValue(t, document), "schemas"), "LogPage")
	if got := sortedStrings(t, pageSchema, "required"); !reflect.DeepEqual(got, []string{"items", "snapshot_at", "total_count"}) {
		t.Fatalf("log page required fields = %v", got)
	}
	items := mapValue(t, mapValue(t, pageSchema, "properties"), "items")
	if got := intValue(t, items, "maxItems"); got != 300 {
		t.Fatalf("log page maxItems=%d, want 300", got)
	}
	boundaryProperty := mapValue(t, mapValue(t, pageSchema, "properties"), "audit_boundary")
	if got := intValue(t, boundaryProperty, "maxLength"); got != 4096 {
		t.Fatalf("audit boundary maxLength=%d", got)
	}

	export := mapValue(t, mapValue(t, paths, "/v1/observability/logs/export"), "get")
	assertStatusSet(t, "export", export, "200", "400", "401", "403", "503")
	assertScopeContract(t, export)
	assertParameterSet(t, "export", export, "action", "action_verb", "change", "from", "kind", "resource_id", "resource_type", "result", "source_ip", "target_scope_id", "to")
	exportResponse := mapValue(t, mapValue(t, export, "responses"), "200")
	headers := mapValue(t, exportResponse, "headers")
	assertHeaderConst(t, headers, "Content-Disposition", `attachment; filename="observability-logs.csv"`)
	assertHeaderConst(t, headers, "Cache-Control", "no-store")
	assertHeaderConst(t, headers, "X-Content-Type-Options", "nosniff")
	digest := mapValue(t, mapValue(t, headers, "X-Content-SHA256"), "schema")
	if got := stringValue(t, digest, "pattern"); got != "^[0-9a-f]{64}$" {
		t.Fatalf("X-Content-SHA256 pattern = %q", got)
	}
	csv := mapValue(t, mapValue(t, mapValue(t, exportResponse, "content"), "text/csv"), "schema")
	if got := intValue(t, csv, "maxLength"); got != 8*1024*1024 {
		t.Fatalf("CSV maxLength = %d, want 8 MiB", got)
	}

	frontend := mapValue(t, mapValue(t, paths, "/v1/observability/frontend-events"), "post")
	assertStatusSet(t, "frontend", frontend, "202", "400", "401", "403", "503")
	assertScopeContract(t, frontend)
	assertParameterSet(t, "frontend", frontend, "target_scope_id")
	if _, ok := mapValue(t, frontend, "responses")["202"].(map[string]any)["content"]; ok {
		t.Fatal("frontend 202 must not declare a response body")
	}
	requestSchema := mapValue(t,
		mapValue(t,
			mapValue(t,
				mapValue(t, frontend, "requestBody"), "content"), "application/json"), "schema")
	if additional, ok := requestSchema["additionalProperties"].(bool); !ok || additional {
		t.Fatal("frontend request must set additionalProperties: false")
	}
	properties := mapValue(t, requestSchema, "properties")
	wantFields := []string{"event_code", "reason_code", "release", "result_code", "route"}
	if got := sortedKeys(properties); !reflect.DeepEqual(got, wantFields) {
		t.Fatalf("frontend fields = %v, want %v", got, wantFields)
	}
	if got := sortedStrings(t, requestSchema, "required"); !reflect.DeepEqual(got, wantFields) {
		t.Fatalf("frontend required = %v, want %v", got, wantFields)
	}
	for _, forbidden := range []string{"source_ip", "actor", "actor_user_id", "request_id"} {
		if _, ok := properties[forbidden]; ok {
			t.Fatalf("frontend request exposes trusted field %q", forbidden)
		}
	}

	components := mapValue(t, document, "components")
	schemes := mapValue(t, components, "securitySchemes")
	if len(schemes) != 1 {
		t.Fatalf("security schemes = %v, want only bearerSession", sortedKeys(schemes))
	}
	bearer := mapValue(t, schemes, "bearerSession")
	if stringValue(t, bearer, "type") != "http" || stringValue(t, bearer, "scheme") != "bearer" {
		t.Fatalf("bearerSession = %#v", bearer)
	}

	errorSchema := mapValue(t, mapValue(t, components, "schemas"), "Error")
	if additional, ok := errorSchema["additionalProperties"].(bool); !ok || additional {
		t.Fatal("error schema must reject dependency detail fields")
	}
	errorObject := mapValue(t, mapValue(t, errorSchema, "properties"), "error")
	if additional, ok := errorObject["additionalProperties"].(bool); !ok || additional {
		t.Fatal("error object must reject dependency detail fields")
	}
	code := mapValue(t, mapValue(t, errorObject, "properties"), "code")
	wantCodes := []string{
		"authentication_required",
		"observability_logs_cursor_expired",
		"observability_logs_invalid_request",
		"observability_logs_unavailable",
		"permission_denied",
	}
	if got := sortedStrings(t, code, "enum"); !reflect.DeepEqual(got, wantCodes) {
		t.Fatalf("stable error codes = %v, want %v", got, wantCodes)
	}
}

func componentsValue(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	return mapValue(t, document, "components")
}

func assertParameterSet(t *testing.T, name string, operation map[string]any, want ...string) {
	t.Helper()
	parameters := sliceValue(t, operation, "parameters")
	got := make([]string, 0, len(parameters))
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s parameter = %#v", name, raw)
		}
		if ref, ok := parameter["$ref"].(string); ok {
			const prefix = "#/components/parameters/"
			if len(ref) <= len(prefix) || ref[:len(prefix)] != prefix {
				t.Fatalf("%s parameter ref = %q", name, ref)
			}
			got = append(got, componentParameterName(t, ref[len(prefix):]))
			continue
		}
		got = append(got, stringValue(t, parameter, "name"))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s parameters = %v, want %v", name, got, want)
	}
}

func componentParameterName(t *testing.T, component string) string {
	t.Helper()
	names := map[string]string{
		"Action": "action", "ActionVerb": "action_verb", "Change": "change", "Cursor": "cursor", "From": "from", "Kind": "kind", "Limit": "limit",
		"ResourceID": "resource_id", "ResourceType": "resource_type",
		"Result": "result", "SourceIP": "source_ip", "To": "to", "ActorUserID": "actor_user_id",
		"AfterAuditBoundary": "after_audit_boundary", "AuditBoundaryMode": "audit_boundary",
	}
	name, ok := names[component]
	if !ok {
		t.Fatalf("unknown parameter component %q", component)
	}
	return name
}

func assertSessionOnly(t *testing.T, name string, operation map[string]any) {
	t.Helper()
	security := sliceValue(t, operation, "security")
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
}

func assertScopeContract(t *testing.T, operation map[string]any) {
	t.Helper()
	parameters := sliceValue(t, operation, "parameters")
	var target map[string]any
	for _, raw := range parameters {
		parameter, ok := raw.(map[string]any)
		if ok && parameter["name"] == "target_scope_id" {
			target = parameter
			break
		}
	}
	if target == nil {
		t.Fatal("operation omits target_scope_id")
	}
	if required, ok := target["required"].(bool); !ok || required {
		t.Fatal("target_scope_id must be optional for tenant sessions")
	}
	if stringValue(t, target, "x-platform-permission") != "platform.admin" {
		t.Fatal("target_scope_id must require platform.admin")
	}
	if allowed, ok := target["x-tenant-allowed"].(bool); !ok || allowed {
		t.Fatal("tenant sessions must omit target_scope_id")
	}
	if isolated, ok := target["x-tenant-actor-subject-isolation"].(bool); !ok || !isolated {
		t.Fatal("tenant operation must enforce actor/subject isolation")
	}
}

func assertStatusSet(t *testing.T, name string, operation map[string]any, want ...string) {
	t.Helper()
	got := sortedKeys(mapValue(t, operation, "responses"))
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s statuses = %v, want %v", name, got, want)
	}
}

func assertHeaderConst(t *testing.T, headers map[string]any, name, want string) {
	t.Helper()
	schema := mapValue(t, mapValue(t, headers, name), "schema")
	if got := stringValue(t, schema, "const"); got != want {
		t.Fatalf("%s const = %q, want %q", name, got, want)
	}
}

func mapValue(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%q = %#v, want object", key, object[key])
	}
	return value
}

func sliceValue(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	value, ok := object[key].([]any)
	if !ok {
		t.Fatalf("%q = %#v, want array", key, object[key])
	}
	return value
}

func stringValue(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("%q = %#v, want string", key, object[key])
	}
	return value
}

func intValue(t *testing.T, object map[string]any, key string) int {
	t.Helper()
	value, ok := object[key].(int)
	if !ok {
		t.Fatalf("%q = %#v, want integer", key, object[key])
	}
	return value
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStrings(t *testing.T, object map[string]any, key string) []string {
	t.Helper()
	values := sliceValue(t, object, key)
	result := make([]string, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%q[%d] = %#v, want string", key, index, value)
		}
		result[index] = text
	}
	sort.Strings(result)
	return result
}
