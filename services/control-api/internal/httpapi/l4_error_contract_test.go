package httpapi

import (
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestL4ErrorAndIdempotencyOpenAPIContracts(t *testing.T) {
	readDocument := func(name string) map[string]any {
		t.Helper()
		content, err := os.ReadFile("../../../../api/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := yaml.Unmarshal(content, &document); err != nil {
			t.Fatal(err)
		}
		return document
	}
	realtime := readDocument("control-l4-realtime.openapi.yaml")
	if realtime["openapi"] != "3.1.0" {
		t.Fatalf("OpenAPI version = %v", realtime["openapi"])
	}
	for _, path := range []string{"/v1/analytics/l4-realtime", "/v1/admin/analytics/l4-realtime"} {
		responses := l4ContractObject(t, realtime, "paths", path, "get", "responses")
		for status, name := range map[string]string{
			"400": "BadRequest", "401": "Unauthenticated", "403": "Forbidden", "500": "InternalError", "503": "ServiceUnavailable",
		} {
			if ref := l4ContractObject(t, responses, status)["$ref"]; ref != "#/components/responses/"+name {
				t.Errorf("%s %s response reference = %v", path, status, ref)
			}
			response := l4ContractObject(t, realtime, "components", "responses", name)
			if ref := l4ContractObject(t, response, "content", "application/json", "schema")["$ref"]; ref != "#/components/schemas/ErrorResponse" {
				t.Errorf("%s JSON error reference = %v", name, ref)
			}
			if ref := l4ContractObject(t, response, "headers", "X-Request-ID")["$ref"]; ref != "#/components/headers/RequestID" {
				t.Errorf("%s request ID header reference = %v", name, ref)
			}
		}
		if ref := l4ContractObject(t, responses, "200", "headers", "X-Request-ID")["$ref"]; ref != "#/components/headers/RequestID" {
			t.Errorf("%s success request ID header reference = %v", path, ref)
		}
	}
	envelope := l4ContractObject(t, realtime, "components", "schemas", "ErrorResponse")
	if !reflect.DeepEqual(envelope["required"], []any{"error"}) || l4ContractObject(t, envelope, "properties", "error")["$ref"] != "#/components/schemas/Error" {
		t.Fatalf("error envelope = %#v", envelope)
	}
	errorSchema := l4ContractObject(t, realtime, "components", "schemas", "Error")
	if !reflect.DeepEqual(errorSchema["required"], []any{"code", "message", "request_id"}) {
		t.Fatalf("error required properties = %#v", errorSchema["required"])
	}
	if ref := l4ContractObject(t, errorSchema, "properties", "request_id")["$ref"]; ref != "#/components/schemas/RequestID" {
		t.Fatalf("error request ID reference = %v", ref)
	}
	requestID := l4ContractObject(t, realtime, "components", "schemas", "RequestID")
	if !reflect.DeepEqual(requestID, map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9._-]{1,128}$"}) {
		t.Fatalf("request ID schema = %#v", requestID)
	}
	forward := readDocument("control-l4-forward.openapi.yaml")
	if ref := l4ContractObject(t, forward, "paths", "/v1/user-configs/{id}", "delete", "responses", "409")["$ref"]; ref != "#/components/responses/Conflict" {
		t.Fatalf("delete user config conflict reference = %v", ref)
	}
	lineSwitch := readDocument("control-l4-line-switch.openapi.yaml")
	key := l4ContractObject(t, lineSwitch, "components", "parameters", "IdempotencyKey", "schema")
	if !reflect.DeepEqual(key, map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"}) {
		t.Fatalf("line switch idempotency key schema = %#v", key)
	}
}

func l4ContractObject(t *testing.T, object map[string]any, path ...string) map[string]any {
	t.Helper()
	for _, key := range path {
		value, ok := object[key].(map[string]any)
		if !ok {
			t.Fatalf("%s is not an object: %#v", key, object[key])
		}
		object = value
	}
	return object
}
