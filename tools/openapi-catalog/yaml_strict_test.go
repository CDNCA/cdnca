package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every OpenAPI document under api/ must parse with gopkg.in/yaml.v3, not only
// with the repo's pinned JavaScript yaml (fix-r1b, FINAL-1026 ❌7: an unquoted
// flow-mapping description in license.yaml was accepted by yaml@2.8.1 but
// rejected by yaml.v3 and Ruby Psych, so external OpenAPI tools could fail).
func TestRepositoryOpenAPIDocumentsParseWithYAMLv3(t *testing.T) {
	repo := filepath.Join("..", "..")
	var files []string
	for _, pattern := range []string{"api/*.yaml", "api/openapi/v1/*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(repo, pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) < 10 {
		t.Fatalf("found only %d OpenAPI documents under api/", len(files))
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var document yaml.Node
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Errorf("%s: %v", file, err)
		}
	}
}
