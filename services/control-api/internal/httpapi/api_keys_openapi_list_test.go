package httpapi

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"gopkg.in/yaml.v3"
)

// tp-b7b / fz-x9 #48: control.yaml APIKeyList documents what apiKeyListResponse
// writes (items, next_cursor, has_more, optional total), and both list
// operations take the offset parameter the handler accepts.
func TestControlOpenAPIAPIKeyListMatchesResponse(t *testing.T) {
	source, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type operation struct {
		Parameters []struct {
			Ref string `yaml:"$ref"`
		} `yaml:"parameters"`
	}
	var document struct {
		Paths map[string]struct {
			Get operation `yaml:"get"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string                  `yaml:"required"`
				Properties map[string]map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
			Parameters map[string]struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	schema := document.Components.Schemas["APIKeyList"]
	required := append([]string(nil), schema.Required...)
	sort.Strings(required)
	if !reflect.DeepEqual(required, []string{"has_more", "items", "next_cursor"}) {
		t.Fatalf("APIKeyList required = %v", schema.Required)
	}
	total := 7
	encoded, err := json.Marshal(newAPIKeyListResponse(apikey.APIKeyListPage{Items: []apikey.Key{}, NextCursor: "c", Total: &total}))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	for field := range body {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("response field %q is not in control.yaml APIKeyList", field)
		}
	}
	for field := range schema.Properties {
		if _, ok := body[field]; !ok {
			t.Errorf("control.yaml APIKeyList field %q is not written by apiKeyListResponse", field)
		}
	}
	if body["total"] != float64(7) {
		t.Fatalf("total = %v", body["total"])
	}
	if offset := document.Components.Parameters["APIKeyListOffset"]; offset.Name != "offset" || offset.In != "query" {
		t.Fatalf("APIKeyListOffset = %+v", offset)
	}
	for _, path := range []string{"/v1/account/api-keys", "/v1/admin/users/{user_id}/api-keys"} {
		refs := map[string]bool{}
		for _, parameter := range document.Paths[path].Get.Parameters {
			refs[parameter.Ref] = true
		}
		for _, name := range []string{"APIKeyListLimit", "APIKeyListCursor", "APIKeyListOffset"} {
			if !refs["#/components/parameters/"+name] {
				t.Errorf("GET %s does not take %s", path, name)
			}
		}
	}
}
