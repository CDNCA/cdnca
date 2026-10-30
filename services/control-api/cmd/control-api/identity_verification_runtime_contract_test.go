package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIdentityVerificationCanonicalOpenAPIDelegatesExactlyThirteenRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	expected := identityVerificationContractPaths()
	found := 0
	for path, pathItem := range document.Paths {
		if !strings.HasPrefix(path, "/v1/identity-verification/") {
			continue
		}
		found++
		escaped := strings.NewReplacer("~", "~0", "/", "~1").Replace(path)
		want := "../../control-identity-verification.openapi.yaml#/paths/" + escaped
		if _, exists := expected[path]; !exists {
			t.Errorf("canonical OpenAPI contains unexpected identity verification path %s", path)
		} else if fmt.Sprint(pathItem["$ref"]) != want {
			t.Errorf("canonical OpenAPI path %s ref=%q, want %q", path, pathItem["$ref"], want)
		}
	}
	if found != len(expected) {
		t.Fatalf("canonical OpenAPI identity verification paths=%d, want %d", found, len(expected))
	}
}

func TestIdentityVerificationHelmValuesSchemaTemplateAndValidation(t *testing.T) {
	defaultValues := readIdentityVerificationHelmValues(t, "../../../../infra/helm/cdnca/values.yaml")
	if defaultValues == nil || defaultValues.Enabled || defaultValues.Settlement.WorkerEnabled ||
		defaultValues.ResolverName != "" || defaultValues.CursorKeySecret.ExistingSecret != "" {
		t.Fatalf("default identity verification values=%#v", defaultValues)
	}
	productionValues := readIdentityVerificationHelmValues(t,
		"../../../../infra/helm/cdnca/values-production.yaml")
	if productionValues == nil || !productionValues.Enabled || !productionValues.Settlement.WorkerEnabled ||
		productionValues.ResolverName == "" || productionValues.CursorKeySecret.ExistingSecret == "" ||
		productionValues.CursorKeySecret.Key == "" || !productionValues.Provider.Enabled ||
		!productionValues.Issuer.Enabled || productionValues.Provider.APIKeySecret.ExistingSecret == "" ||
		productionValues.Provider.CallbackHMACSecret.ExistingSecret == "" ||
		productionValues.Provider.ObjectStore.CredentialsSecret.ExistingSecret == "" ||
		productionValues.Issuer.MTLSSecret.ExistingSecret == "" {
		t.Fatalf("production identity verification values=%#v", productionValues)
	}

	schemaRaw, err := os.ReadFile("../../../../infra/helm/cdnca/values.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		t.Fatal(err)
	}
	definitions := jsonObject(t, schema["definitions"], "definitions")
	controlAPI := jsonObject(t, definitions["controlApi"], "definitions.controlApi")
	required := jsonArray(t, controlAPI["required"], "definitions.controlApi.required")
	if !jsonStringArrayContains(required, "identityVerification") {
		t.Fatal("controlApi schema does not require identityVerification")
	}
	properties := jsonObject(t, controlAPI["properties"], "definitions.controlApi.properties")
	identityReference := jsonObject(t, properties["identityVerification"], "controlApi.identityVerification")
	if identityReference["$ref"] != "#/definitions/identityVerification" {
		t.Fatalf("identityVerification schema reference=%v", identityReference["$ref"])
	}
	identitySchema := jsonObject(t, definitions["identityVerification"], "definitions.identityVerification")
	encodedIdentitySchema, err := json.Marshal(identitySchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, requiredContract := range []string{
		`"workerEnabled"`, `"const":true`, `"existingSecret"`, `"minLength":1`,
		`"resolverName"`, `"cursorKeySecret"`, `"settlement"`, `"provider"`, `"issuer"`,
		`"workloadIdentities"`, `"callbackHMACSecret"`, `"credentialsSecret"`, `"mtlsSecret"`,
	} {
		if !strings.Contains(string(encodedIdentitySchema), requiredContract) {
			t.Errorf("identity verification schema missing %s", requiredContract)
		}
	}

	template := readIdentityVerificationContractFile(t,
		"../../../../infra/helm/cdnca/templates/control-api.yaml")
	for _, requiredContract := range []string{
		"IDENTITY_VERIFICATION_RUNTIME_ENABLED",
		"IDENTITY_VERIFICATION_CURSOR_KEY_BASE64",
		"IDENTITY_VERIFICATION_RESOLVER_NAME",
		"IDENTITY_VERIFICATION_SETTLEMENT_WORKER_ENABLED",
		"IDENTITY_VERIFICATION_KYC_PROVIDER_NAME",
		"IDENTITY_VERIFICATION_KYC_CALLBACK_HMAC_BASE64",
		"IDENTITY_VERIFICATION_OBJECT_SECRET_ACCESS_KEY",
		"IDENTITY_VERIFICATION_ISSUER_MTLS_LISTEN_ADDR",
		"IDENTITY_VERIFICATION_ISSUER_WORKLOAD_IDENTITIES",
		"identity-verification-issuer",
		".Values.controlApi.identityVerification.cursorKeySecret.existingSecret",
		".Values.controlApi.identityVerification.cursorKeySecret.key",
	} {
		if !strings.Contains(template, requiredContract) {
			t.Errorf("control-api template missing %s", requiredContract)
		}
	}
	validation := readIdentityVerificationContractFile(t,
		"../../../../infra/helm/cdnca/templates/validation.yaml")
	for _, requiredContract := range []string{
		"controlApi.identityVerification requires controlApi",
		"controlApi.identityVerification.settlement.workerEnabled must be true",
		"controlApi.identityVerification.cursorKeySecret.existingSecret",
		"controlApi.identityVerification.cursorKeySecret.key",
		"controlApi.identityVerification.provider requires issuer",
		"controlApi.identityVerification.issuer.mtlsSecret.existingSecret",
	} {
		if !strings.Contains(validation, requiredContract) {
			t.Errorf("Helm validation missing %s", requiredContract)
		}
	}
}

type identityVerificationHelmValues struct {
	Enabled         bool   `yaml:"enabled"`
	ResolverName    string `yaml:"resolverName"`
	ReviewTTL       string `yaml:"reviewTTL"`
	RetentionPeriod string `yaml:"retentionPeriod"`
	CursorKeySecret struct {
		ExistingSecret string `yaml:"existingSecret"`
		Key            string `yaml:"key"`
	} `yaml:"cursorKeySecret"`
	Settlement struct {
		WorkerEnabled bool `yaml:"workerEnabled"`
	} `yaml:"settlement"`
	Provider struct {
		Enabled      bool `yaml:"enabled"`
		APIKeySecret struct {
			ExistingSecret string `yaml:"existingSecret"`
		} `yaml:"apiKeySecret"`
		CallbackHMACSecret struct {
			ExistingSecret string `yaml:"existingSecret"`
		} `yaml:"callbackHMACSecret"`
		ObjectStore struct {
			CredentialsSecret struct {
				ExistingSecret string `yaml:"existingSecret"`
			} `yaml:"credentialsSecret"`
		} `yaml:"objectStore"`
	} `yaml:"provider"`
	Issuer struct {
		Enabled    bool `yaml:"enabled"`
		MTLSSecret struct {
			ExistingSecret string `yaml:"existingSecret"`
		} `yaml:"mtlsSecret"`
	} `yaml:"issuer"`
}

func readIdentityVerificationHelmValues(t *testing.T, path string) *identityVerificationHelmValues {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		ControlAPI struct {
			IdentityVerification *identityVerificationHelmValues `yaml:"identityVerification"`
		} `yaml:"controlApi"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	return values.ControlAPI.IdentityVerification
}

func readIdentityVerificationContractFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func jsonObject(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s has type %T, want object", path, value)
	}
	return result
}

func jsonArray(t *testing.T, value any, path string) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("%s has type %T, want array", path, value)
	}
	return result
}

func jsonStringArrayContains(values []any, want string) bool {
	for _, value := range values {
		if fmt.Sprint(value) == want {
			return true
		}
	}
	return false
}

func identityVerificationContractPaths() map[string]struct{} {
	return map[string]struct{}{
		"/v1/identity-verification/status":                                                      {},
		"/v1/identity-verification/cases":                                                       {},
		"/v1/identity-verification/cases/{case_id}":                                             {},
		"/v1/identity-verification/cases/{case_id}/submit":                                      {},
		"/v1/identity-verification/cases/{case_id}/withdraw":                                    {},
		"/v1/identity-verification/cases/{case_id}/expire":                                      {},
		"/v1/identity-verification/reviewer/cases":                                              {},
		"/v1/identity-verification/reviewer/cases/{case_id}":                                    {},
		"/v1/identity-verification/reviewer/cases/{case_id}/claim":                              {},
		"/v1/identity-verification/reviewer/cases/{case_id}/decision":                           {},
		"/v1/identity-verification/provider-sessions":                                           {},
		"/v1/identity-verification/provider-sessions/{session_id}/uploads":                      {},
		"/v1/identity-verification/provider-sessions/{session_id}/uploads/{upload_id}/finalize": {},
		"/v1/identity-verification/provider-callbacks/{provider}":                               {},
		// 平台管理员跨租户实名申请列表（管理端实名审核入口）。
		"/v1/identity-verification/admin/cases": {},
	}
}
