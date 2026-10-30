package httpapi

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenRestySecurityCanonicalOpenAPIAggregation(t *testing.T) {
	wantRefs := map[string]string{
		"/v1/openresty-security/configs/global":            "../../control-openresty-security.openapi.yaml#/paths/~1v1~1openresty-security~1configs~1global",
		"/v1/openresty-security/overrides":                 "../../control-openresty-security.openapi.yaml#/paths/~1v1~1openresty-security~1overrides",
		"/v1/openresty-security/overrides/{id}":            "../../control-openresty-security.openapi.yaml#/paths/~1v1~1openresty-security~1overrides~1{id}",
		"/v1/openresty-security/targets":                   "../../control-openresty-security.openapi.yaml#/paths/~1v1~1openresty-security~1targets",
		"/v1/openresty-security/effective":                 "../../control-openresty-security.openapi.yaml#/paths/~1v1~1openresty-security~1effective",
		"/v1/cc-rule-groups":                               "../../control-openresty-security.openapi.yaml#/paths/~1v1~1cc-rule-groups",
		"/v1/openresty-security/actions/download-cc-image": "../../control-openresty-security.openapi.yaml#/paths/~1v1~1openresty-security~1actions~1download-cc-image",
	}

	source, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("parse canonical control OpenAPI: %v", err)
	}
	for path, wantRef := range wantRefs {
		pathItem, ok := document.Paths[path]
		if !ok {
			t.Errorf("canonical control OpenAPI is missing %s", path)
			continue
		}
		gotRef, ok := pathItem["$ref"].(string)
		if !ok || gotRef != wantRef {
			t.Errorf("canonical %s ref = %#v, want %q", path, pathItem["$ref"], wantRef)
		}
		if len(pathItem) != 1 {
			t.Errorf("canonical %s must contain only its fragment ref: %#v", path, pathItem)
		}
	}
}
