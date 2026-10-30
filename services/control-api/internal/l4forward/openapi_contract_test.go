package l4forward

import (
	"os"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPackageNameIsReadOnlyStreamMetadata(t *testing.T) {
	for _, path := range []string{"../../../../api/control-l4-forward.openapi.yaml", "../../../../api/openapi/v1/control.yaml"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		schemas := l4OpenAPIMap(t, l4OpenAPIMap(t, document, "components"), "schemas")
		stream := l4OpenAPIMap(t, schemas, "Stream")
		fields := stream["allOf"].([]any)[1].(map[string]any)
		for _, key := range []string{"package_name", "package_expires_at"} {
			metadata := l4OpenAPIMap(t, l4OpenAPIMap(t, fields, "properties"), key)
			if metadata["readOnly"] != true || !reflect.DeepEqual(metadata["type"], []any{"string", "null"}) {
				t.Fatalf("%s %s metadata = %#v", path, key, metadata)
			}
			if key == "package_expires_at" && metadata["format"] != "date-time" {
				t.Fatalf("%s package expiry format = %#v", path, metadata["format"])
			}
			for _, schema := range []string{"StreamAttributes", "StreamFields", "StreamRuntimeSpec", "StreamRuntimeSpecV2"} {
				if fields, ok := schemas[schema].(map[string]any); ok {
					if properties, ok := fields["properties"].(map[string]any); ok && properties[key] != nil {
						t.Fatalf("%s exposes %s in %s", path, key, schema)
					}
				}
			}
		}
	}
}

func TestStreamListFilterOpenAPIContract(t *testing.T) {
	readDocument := func(path string) map[string]any {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		return document
	}
	root := readDocument("../../../../api/openapi/v1/control.yaml")
	if got := l4OpenAPIMap(t, l4OpenAPIMap(t, root, "paths"), "/v1/streams")["$ref"]; got != "../../control-l4-forward.openapi.yaml#/paths/~1v1~1streams" {
		t.Fatalf("canonical stream path reference = %v", got)
	}
	fragment := readDocument("../../../../api/control-l4-forward.openapi.yaml")
	operation := l4OpenAPIMap(t, l4OpenAPIMap(t, l4OpenAPIMap(t, fragment, "paths"), "/v1/streams"), "get")
	parameters := make(map[string]map[string]any)
	for _, entry := range operation["parameters"].([]any) {
		parameter := entry.(map[string]any)
		if name, ok := parameter["name"].(string); ok {
			if parameter["in"] != "query" {
				t.Fatalf("%s is not a query parameter", name)
			}
			parameters[name] = l4OpenAPIMap(t, parameter, "schema")
		}
	}
	for name, want := range map[string]map[string]any{
		"listen_port":        {"type": "integer", "minimum": 1, "maximum": 65535},
		"upstream":           {"type": "string", "minLength": 1, "maxLength": 253},
		"display_id":         {"type": "string", "pattern": "^[1-9][0-9]{0,18}$"},
		"owner_display_id":   {"type": "string", "pattern": "^[1-9][0-9]{0,18}$"},
		"publication_state":  {"type": "string", "enum": []any{"unknown", "pending", "leased", "retrying", "reconciling", "succeeded", "failed", "superseded"}},
		"group_id":           {"type": "string", "format": "uuid"},
		"package_product_id": {"type": "string", "format": "uuid"},
		"cname_domain":       {"type": "string", "minLength": 1, "maxLength": 253},
		"cname_hostname":     {"type": "string", "minLength": 1, "maxLength": 253},
		"region_id":          {"type": "string", "format": "uuid"},
		"node_group_id":      {"type": "string", "format": "uuid"},
		"sync_state":         {"type": "string", "enum": []any{"done", "pending", "failed"}},
	} {
		if !reflect.DeepEqual(parameters[name], want) {
			t.Errorf("%s schema = %#v, want %#v", name, parameters[name], want)
		}
	}
	for _, name := range []string{"page", "limit", "search", "protocol", "enabled"} {
		if parameters[name] == nil {
			t.Errorf("existing filter %s is missing", name)
		}
	}
}

func TestL4ForwardOpenAPIFragmentContract(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-l4-forward.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}

	paths := l4OpenAPIMap(t, document, "paths")
	if got := l4OpenAPIKeys(paths); !reflect.DeepEqual(got, []string{
		"/v1/l4-live-connections", "/v1/stream-groups", "/v1/stream-groups/{id}", "/v1/streams", "/v1/streams/batch",
		"/v1/streams/batch-action", "/v1/streams/{id}",
		"/v1/streams/{id}/live-connections", "/v1/streams/{id}/live-connections/close",
		"/v1/user-configs", "/v1/user-configs/effective", "/v1/user-configs/{id}",
	}) {
		t.Fatalf("paths = %v", got)
	}
	operations := map[string]struct {
		method      string
		operationID string
		permission  string
	}{
		"list":               {"get", "listStreams", "streams.read"},
		"create":             {"post", "createStream", "streams.manage"},
		"get":                {"get", "getStream", "streams.read"},
		"update":             {"patch", "updateStream", "streams.manage"},
		"delete":             {"delete", "deleteStream", "streams.manage"},
		"groups/list":        {"get", "listStreamGroups", "streams.read"},
		"groups/create":      {"post", "createStreamGroup", "streams.manage"},
		"groups/update":      {"patch", "updateStreamGroup", "streams.manage"},
		"groups/delete":      {"delete", "deleteStreamGroup", "streams.manage"},
		"defaults/list":      {"get", "listUserConfigs", "streams.read"},
		"defaults/effective": {"get", "getEffectiveUserConfigs", "streams.read"},
		"defaults/create":    {"post", "createUserConfig", "streams.manage"},
		"defaults/delete":    {"delete", "deleteUserConfig", "streams.manage"},
		"live/list":          {"get", "listStreamLiveConnections", "streams.read"},
		"live/close":         {"post", "closeStreamLiveConnections", "streams.manage"},
		"batch":              {"post", "batchCreateStreams", "streams.manage"},
		"batch-action":       {"post", "batchStreamAction", "streams.manage"},
	}
	for name, expected := range operations {
		path := "/v1/streams/{id}"
		switch name {
		case "list", "create":
			path = "/v1/streams"
		case "groups/list", "groups/create":
			path = "/v1/stream-groups"
		case "groups/update", "groups/delete":
			path = "/v1/stream-groups/{id}"
		case "defaults/list", "defaults/create":
			path = "/v1/user-configs"
		case "defaults/effective":
			path = "/v1/user-configs/effective"
		case "defaults/delete":
			path = "/v1/user-configs/{id}"
		case "live/list":
			path = "/v1/streams/{id}/live-connections"
		case "live/close":
			path = "/v1/streams/{id}/live-connections/close"
		case "batch":
			path = "/v1/streams/batch"
		case "batch-action":
			path = "/v1/streams/batch-action"
		}
		operation := l4OpenAPIMap(t, l4OpenAPIMap(t, paths, path), expected.method)
		if operation["operationId"] != expected.operationID {
			t.Fatalf("%s operationId = %#v", name, operation["operationId"])
		}
		if got := l4OpenAPIStrings(t, operation, "x-required-permissions"); !reflect.DeepEqual(got, []string{expected.permission}) {
			t.Fatalf("%s permissions = %v", name, got)
		}
	}

	components := l4OpenAPIMap(t, document, "components")
	schemas := l4OpenAPIMap(t, components, "schemas")
	streamFields := l4OpenAPIMap(t, schemas, "StreamAttributes")
	properties := l4OpenAPIMap(t, streamFields, "properties")
	for _, field := range []string{
		"package_subscription_id", "remark", "upstream_host", "dns_policy",
		"geo_policy", "proxy_protocol_inbound", "max_connections_per_client",
	} {
		if properties[field] == nil {
			t.Errorf("StreamAttributes missing %s", field)
		}
	}

	update := l4OpenAPIMap(t, schemas, "UpdateStreamRequest")
	if !l4OpenAPIContainsRequired(update, "expected_revision") {
		t.Error("UpdateStreamRequest does not require expected_revision")
	}
	patch := l4OpenAPIMap(t, l4OpenAPIMap(t, paths, "/v1/streams/{id}"), "patch")
	if !l4OpenAPIContainsParameterRef(t, patch, "#/components/parameters/IfMatch") {
		t.Error("updateStream does not require If-Match")
	}

	runtimeV2 := l4OpenAPIMap(t, schemas, "StreamRuntimeSpecV2")
	for _, identity := range []string{"tenant_id", "stream_id", "revision"} {
		if !l4OpenAPIContainsRequired(runtimeV2, identity) {
			t.Errorf("StreamRuntimeSpecV2 does not require %s", identity)
		}
	}
	intent := l4OpenAPIMap(t, schemas, "StreamPublishIntent")
	for _, identity := range []string{
		"id", "version", "resource_revision", "configuration_source_revision", "runtime_spec",
		"state", "automatic_request_id", "publication_id", "rollout_id",
	} {
		if !l4OpenAPIContainsRequired(intent, identity) {
			t.Errorf("StreamPublishIntent does not require %s", identity)
		}
	}
	stream := l4OpenAPIMap(t, schemas, "Stream")
	if !l4OpenAPIContainsRequired(stream, "display_id") {
		t.Error("Stream does not require display_id")
	}
	streamParts, ok := stream["allOf"].([]any)
	if !ok || len(streamParts) != 2 {
		t.Fatalf("Stream allOf = %#v", stream["allOf"])
	}
	streamObject, ok := streamParts[1].(map[string]any)
	if !ok {
		t.Fatalf("Stream object = %#v", streamParts[1])
	}
	displayID := l4OpenAPIMap(t, l4OpenAPIMap(t, streamObject, "properties"), "display_id")
	if got := displayID["pattern"]; got != "^[1-9][0-9]{0,18}$" {
		t.Fatalf("Stream display_id pattern = %#v", got)
	}

	runtime := l4OpenAPIMap(t, schemas, "StreamRuntimeSpec")
	if got := l4OpenAPIRefs(t, runtime, "oneOf"); !reflect.DeepEqual(got, []string{
		"#/components/schemas/StreamRuntimeSpecV2",
	}) {
		t.Fatalf("StreamRuntimeSpec variants = %v", got)
	}
	// Migration 506: a stream belongs to no website.
	if properties["site_id"] != nil || l4OpenAPIContainsRequired(runtimeV2, "site_id") {
		t.Fatal("stream contract still names a website (site_id)")
	}
}

func l4OpenAPIMap(t *testing.T, source map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := source[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v", key, source[key])
	}
	return value
}

func l4OpenAPIKeys(source map[string]any) []string {
	result := make([]string, 0, len(source))
	for key := range source {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func l4OpenAPIStrings(t *testing.T, source map[string]any, key string) []string {
	t.Helper()
	values, ok := source[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v", key, source[key])
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s entry = %#v", key, value)
		}
		result = append(result, text)
	}
	return result
}

func l4OpenAPIContainsRequired(source map[string]any, field string) bool {
	if required, ok := source["required"].([]any); ok {
		for _, value := range required {
			if value == field {
				return true
			}
		}
	}
	for _, key := range []string{"allOf", "oneOf"} {
		items, _ := source[key].([]any)
		for _, item := range items {
			mapping, ok := item.(map[string]any)
			if ok && l4OpenAPIContainsRequired(mapping, field) {
				return true
			}
		}
	}
	return false
}

func l4OpenAPIContainsParameterRef(t *testing.T, operation map[string]any, expected string) bool {
	t.Helper()
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatalf("parameters = %#v", operation["parameters"])
	}
	for _, parameter := range parameters {
		mapping, ok := parameter.(map[string]any)
		if ok && mapping["$ref"] == expected {
			return true
		}
	}
	return false
}

func l4OpenAPIRefs(t *testing.T, source map[string]any, key string) []string {
	t.Helper()
	items, ok := source[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v", key, source[key])
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		mapping, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("%s entry = %#v", key, item)
		}
		ref, ok := mapping["$ref"].(string)
		if !ok {
			t.Fatalf("%s ref = %#v", key, mapping["$ref"])
		}
		result = append(result, ref)
	}
	return result
}

func l4OpenAPITypes(t *testing.T, source map[string]any, key string) []string {
	t.Helper()
	items, ok := source[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v", key, source[key])
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		mapping, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("%s entry = %#v", key, item)
		}
		value, ok := mapping["type"].(string)
		if !ok {
			t.Fatalf("%s type = %#v", key, mapping["type"])
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
