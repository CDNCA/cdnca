package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNodeDisplayIDJSONAndOpenAPIContract(t *testing.T) {
	field, found := reflect.TypeOf(Node{}).FieldByName("DisplayID")
	if !found || field.Type.Kind() != reflect.String || field.Tag.Get("json") != "display_id" {
		t.Fatalf("Node.DisplayID contract = found:%v type:%v tag:%q", found, field.Type, field.Tag.Get("json"))
	}
	encoded, err := json.Marshal(Node{DisplayID: "9007199254740993"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"display_id":"9007199254740993"`) {
		t.Fatalf("node display ID is not a required JSON string: %s", encoded)
	}

	openAPIPath := filepath.Join("..", "..", "..", "..", "api", "openapi", "v1", "control.yaml")
	openAPIBytes, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	openAPI := string(openAPIBytes)
	start := strings.Index(openAPI, "\n    Node:\n")
	end := strings.Index(openAPI[start+1:], "\n    NodeGatewayEndpoint:\n")
	if start < 0 || end < 0 {
		t.Fatal("Node OpenAPI schema not found")
	}
	nodeSchema := openAPI[start : start+1+end]
	for _, required := range []string{
		"required: [id, display_id, name, description, region, admin_state, management_settings, revision, created_at, updated_at]",
		"display_id:\n          type: string",
		"pattern: '^[1-9][0-9]*$'",
	} {
		if !strings.Contains(nodeSchema, required) {
			t.Errorf("Node OpenAPI schema missing %q", required)
		}
	}
}

func TestNodeCreateDisplayIDGateOrderingContract(t *testing.T) {
	sourceBytes, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	start := strings.Index(source, "func (s *Store) Create(")
	end := strings.Index(source[start+1:], "func (s *Store) IssueToken(")
	if start < 0 || end < 0 {
		t.Fatal("Store.Create source not found")
	}
	create := source[start : start+1+end]
	ordered := []string{
		"replayOrClaimWrite",
		"if stored.Found",
		"CheckNodeCreate",
		"DELETE FROM node_write_requests",
		"allocateNodeDisplayID",
		"INSERT INTO nodes",
		"completeWrite",
	}
	previous := -1
	for _, marker := range ordered {
		position := strings.Index(create, marker)
		if position < 0 || position <= previous {
			t.Fatalf("Store.Create marker %q position=%d after=%d", marker, position, previous)
		}
		previous = position
	}
	if strings.Count(create, "allocateNodeDisplayID") != 1 {
		t.Fatalf("Store.Create allocation count = %d, want 1", strings.Count(create, "allocateNodeDisplayID"))
	}
	if count := strings.Count(source, "display_id::text"); count != 5 {
		t.Fatalf("node display ID projection count = %d, want 5", count)
	}
}
