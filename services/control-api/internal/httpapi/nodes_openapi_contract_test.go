package httpapi

import (
	"os"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"gopkg.in/yaml.v3"
)

func TestNodeListOpenAPIDeclaresBoundedSearch(t *testing.T) {
	source, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string `yaml:"name"`
					In     string `yaml:"in"`
					Schema struct {
						Type      string `yaml:"type"`
						MaxLength int    `yaml:"maxLength"`
					} `yaml:"schema"`
				} `yaml:"parameters"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	for _, parameter := range document.Paths["/v1/nodes"].Get.Parameters {
		if parameter.Name == "search" {
			if parameter.In != "query" || parameter.Schema.Type != "string" ||
				parameter.Schema.MaxLength != nodepresence.MaxInventorySearchRunes {
				t.Fatalf("search parameter = %#v", parameter)
			}
			return
		}
	}
	t.Fatal("GET /v1/nodes is missing the search query parameter")
}
