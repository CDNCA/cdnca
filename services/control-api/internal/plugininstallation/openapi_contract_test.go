package plugininstallation

import (
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPluginInstallationOpenAPIExactRoutesHeadersErrorsAndPendingIdentity(t *testing.T) {
	encoded, err := os.ReadFile("../../../../api/control-plugin-installations.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document pluginInstallationOpenAPI
	if err := yaml.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	expectedRoutes := map[string]string{
		"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations":                              "get",
		"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}":           "get",
		"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}/confirm":   "post",
		"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}/upgrade":   "post",
		"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}/disable":   "post",
		"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}/resume":    "post",
		"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}/uninstall": "post",
		// 报告 A：平台资源（主题、规则数据包）由主控平台管理员确认；作用域取自会话。
		"/v1/platform/plugin-installations":                              "get",
		"/v1/platform/plugin-installations/{authorization_id}":           "get",
		"/v1/platform/plugin-installations/{authorization_id}/confirm":   "post",
		"/v1/platform/plugin-installations/{authorization_id}/upgrade":   "post",
		"/v1/platform/plugin-installations/{authorization_id}/disable":   "post",
		"/v1/platform/plugin-installations/{authorization_id}/uninstall": "post",
	}
	if len(document.Paths) != len(expectedRoutes) {
		t.Fatalf("paths=%v", document.Paths)
	}
	for route, method := range expectedRoutes {
		operations, found := document.Paths[route]
		operation, methodFound := operations[method]
		if !found || !methodFound || len(operations) != 1 {
			t.Fatalf("route %s methods=%v", route, operations)
		}
		if !hasPluginInstallationParameter(operation.Parameters, "#/components/parameters/RequestID") {
			t.Errorf("%s %s does not require X-Request-ID", method, route)
		}
		if method == "post" && (route[len(route)-7:] == "confirm" || route[len(route)-7:] == "upgrade") {
			if _, found := operation.Responses["422"]; !found {
				t.Errorf("%s %s does not declare 422", method, route)
			}
		}
	}
	requestID, found := document.Components.Parameters["RequestID"]
	if !found || requestID.Name != "X-Request-ID" || requestID.In != "header" || !requestID.Required {
		t.Fatalf("RequestID parameter=%+v found=%v", requestID, found)
	}
	resourceScope := document.Components.Schemas["PluginInstallation"].Properties["resource_scope"]
	if !reflect.DeepEqual(resourceScope.Enum, []string{"platform", "tenant"}) {
		t.Fatalf("resource_scope enum=%v", resourceScope.Enum)
	}
	entrypointType := document.Components.Schemas["PluginInstallation"].Properties["entrypoint_type"]
	if !reflect.DeepEqual(entrypointType.Enum, []string{"theme", "rule_pack", "external_https", "ui_page"}) {
		t.Fatalf("entrypoint_type enum=%v", entrypointType.Enum)
	}
	identityGeneration := document.Components.Schemas["PluginInstallation"].Properties["identity_generation"]
	if identityGeneration.Minimum == nil || *identityGeneration.Minimum != 0 {
		t.Fatalf("identity_generation minimum=%v, pending candidates must allow zero", identityGeneration.Minimum)
	}
	wantErrors := []string{
		"authentication_required", "permission_denied", "invalid_request", "plugin_installation_not_found",
		"plugin_installation_revision_conflict", "plugin_installation_idempotency_conflict",
		"plugin_installation_scope_approval_required", "plugin_installation_platform_paused",
		"plugin_installation_license_unavailable",
		"plugin_installation_state_conflict", "plugin_installation_result_unknown", "internal_error",
	}
	gotErrors := document.Components.Schemas["Error"].Properties["error"].Properties["code"].Enum
	if !reflect.DeepEqual(gotErrors, wantErrors) {
		t.Fatalf("error enum=%v", gotErrors)
	}
}

func hasPluginInstallationParameter(parameters []pluginInstallationOpenAPIParameterRef, reference string) bool {
	for _, parameter := range parameters {
		if parameter.Ref == reference {
			return true
		}
	}
	return false
}

type pluginInstallationOpenAPI struct {
	Paths      map[string]map[string]pluginInstallationOpenAPIOperation `yaml:"paths"`
	Components struct {
		Parameters map[string]pluginInstallationOpenAPIParameter `yaml:"parameters"`
		Schemas    map[string]pluginInstallationOpenAPISchema    `yaml:"schemas"`
	} `yaml:"components"`
}

type pluginInstallationOpenAPIOperation struct {
	Parameters []pluginInstallationOpenAPIParameterRef `yaml:"parameters"`
	Responses  map[string]any                          `yaml:"responses"`
}

type pluginInstallationOpenAPIParameterRef struct {
	Ref string `yaml:"$ref"`
}

type pluginInstallationOpenAPIParameter struct {
	Name     string `yaml:"name"`
	In       string `yaml:"in"`
	Required bool   `yaml:"required"`
}

type pluginInstallationOpenAPISchema struct {
	Minimum    *int64                                     `yaml:"minimum"`
	Enum       []string                                   `yaml:"enum"`
	Properties map[string]pluginInstallationOpenAPISchema `yaml:"properties"`
}
