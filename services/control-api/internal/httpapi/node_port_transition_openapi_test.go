package httpapi

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNodePortTransitionOpenAPIRuntimeAndReplayContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type operation struct {
		Responses map[string]struct {
			Ref string `yaml:"$ref"`
		} `yaml:"responses"`
		Parameters []struct {
			Ref string `yaml:"$ref"`
		} `yaml:"parameters"`
	}
	var document struct {
		Paths map[string]struct {
			Post operation `yaml:"post"`
			Get  operation `yaml:"get"`
		} `yaml:"paths"`
		Components struct {
			Parameters map[string]struct {
				Name     string `yaml:"name"`
				In       string `yaml:"in"`
				Required bool   `yaml:"required"`
				Schema   struct {
					Format  string `yaml:"format"`
					Pattern string `yaml:"pattern"`
				} `yaml:"schema"`
			} `yaml:"parameters"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	base := "/v1/nodes/{id}/gateway-port-transitions"
	for _, suffix := range []string{"", "/{transition_id}/finalize", "/{transition_id}/rollback"} {
		t.Run("write"+suffix, func(t *testing.T) {
			operation := document.Paths[base+suffix].Post
			if operation.Responses["503"].Ref != "#/components/responses/ServiceUnavailable" {
				t.Error("write route must declare unavailable runtime response")
			}
			if suffix == "" {
				return
			}
			for _, parameter := range operation.Parameters {
				if parameter.Ref == "#/components/parameters/NodeGatewayPortTransitionRequestID" {
					return
				}
			}
			t.Error("action route must declare caller-stable request identity")
		})
	}
	if _, exists := document.Paths[base+"/{transition_id}"].Get.Responses["503"]; exists {
		t.Error("reading a persisted transition must not require the write runtime")
	}
	parameter := document.Components.Parameters["NodeGatewayPortTransitionRequestID"]
	if parameter.Name != "X-Request-ID" || parameter.In != "header" || parameter.Required ||
		parameter.Schema.Format != "uuid" || parameter.Schema.Pattern != "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" {
		t.Errorf("request identity contract = %#v", parameter)
	}
}
