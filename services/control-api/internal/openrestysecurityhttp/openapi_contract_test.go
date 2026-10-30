package openrestysecurityhttp

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIDerivesScopeFromAuthenticationAndExposesNoTargetScopeQuery(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-openresty-security.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(source)
	if strings.Contains(contract, "#/components/parameters/TargetScopeID") ||
		strings.Contains(contract, "TargetScopeID: {name: target_scope_id") ||
		strings.Contains(contract, "target_scope_id:") {
		t.Fatal("OpenResty security OpenAPI still exposes target_scope_id instead of deriving the scope from authentication")
	}
}

type openRestySecurityOpenAPISchema struct {
	Type                 string                                    `yaml:"type"`
	Ref                  string                                    `yaml:"$ref"`
	AdditionalProperties *bool                                     `yaml:"additionalProperties"`
	Required             []string                                  `yaml:"required"`
	Properties           map[string]openRestySecurityOpenAPISchema `yaml:"properties"`
	Items                *openRestySecurityOpenAPISchema           `yaml:"items"`
	Enum                 []string                                  `yaml:"enum"`
	MinItems             int                                       `yaml:"minItems"`
	MaxItems             int                                       `yaml:"maxItems"`
	UniqueItems          bool                                      `yaml:"uniqueItems"`
	MinLength            int                                       `yaml:"minLength"`
	MaxLength            int                                       `yaml:"maxLength"`
}

func TestOpenAPIErrorEnvelopeMatchesHandler(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-openresty-security.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]openRestySecurityOpenAPISchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	envelope, ok := document.Components.Schemas["Error"]
	if !ok {
		t.Fatal("OpenAPI Error schema is missing")
	}
	if envelope.Type != "object" || envelope.AdditionalProperties == nil || *envelope.AdditionalProperties ||
		!reflect.DeepEqual(envelope.Required, []string{"error"}) {
		t.Fatalf("Error schema=%+v", envelope)
	}
	detail, ok := envelope.Properties["error"]
	if !ok || detail.Type != "object" || detail.AdditionalProperties == nil || *detail.AdditionalProperties ||
		!reflect.DeepEqual(detail.Required, []string{"code", "request_id"}) {
		t.Fatalf("Error.error schema=%+v present=%v", detail, ok)
	}
	if detail.Properties["code"].Type != "string" {
		t.Fatalf("Error.error.code schema=%+v", detail.Properties["code"])
	}
	requestID := detail.Properties["request_id"]
	if requestID.Type != "string" || requestID.MinLength != 1 || requestID.MaxLength != 128 {
		t.Fatalf("Error.error.request_id schema=%+v", requestID)
	}
	scopeLabel := document.Components.Schemas["Document"].Properties["scope_label"]
	if scopeLabel.Type != "string" || scopeLabel.MinLength != 1 || scopeLabel.MaxLength != 128 {
		t.Fatalf("Document.scope_label schema=%+v", scopeLabel)
	}
}

func TestOpenAPIRuleGroupsExposeStableSystemIdentity(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-openresty-security.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]openRestySecurityOpenAPISchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	ruleGroup := document.Components.Schemas["RuleGroup"]
	for _, property := range []string{"system_rule_id", "system_rule_key"} {
		field := ruleGroup.Properties[property]
		if field.Type != "string" || field.MaxLength == 0 {
			t.Fatalf("RuleGroup.%s schema=%+v", property, field)
		}
	}
}

func TestOpenAPIPatchOverrideDeclaresExplicitRemovedFields(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-openresty-security.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Patch struct {
				RequestBody struct {
					Content map[string]struct {
						Schema openRestySecurityOpenAPISchema `yaml:"schema"`
					} `yaml:"content"`
				} `yaml:"requestBody"`
			} `yaml:"patch"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]openRestySecurityOpenAPISchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	requestSchema := document.Paths["/v1/openresty-security/overrides/{id}"].Patch.RequestBody.
		Content["application/json"].Schema
	if !reflect.DeepEqual(requestSchema.Required, []string{"patch"}) {
		t.Fatalf("PATCH required=%v", requestSchema.Required)
	}
	removed, ok := requestSchema.Properties["removed_fields"]
	if !ok || removed.Type != "array" || removed.Items == nil ||
		removed.Items.Ref != "#/components/schemas/OverrideFieldName" || removed.MinItems != 1 ||
		removed.MaxItems != 24 || !removed.UniqueItems {
		t.Fatalf("removed_fields=%+v present=%v", removed, ok)
	}
	wantFields := []string{"waf_enable", "waf_resource_limits", "cc_enable", "block_time", "white_time",
		"tmp_white_total_limit", "tmp_white_per_limit", "custom_white", "custom_black", "ssl_handshake_limit",
		"default_page_refuse", "default_page_rule", "icmp_drop", "key", "auto_delete_access_log", "auto_switch",
		"slider_html", "captcha_html", "click_html", "delay_jump_html", "rotate_html", "easy_click_html",
		"easy_slider_html", "log"}
	if got := document.Components.Schemas["OverrideFieldName"].Enum; !reflect.DeepEqual(got, wantFields) {
		t.Fatalf("OverrideFieldName enum=%v", got)
	}
}
