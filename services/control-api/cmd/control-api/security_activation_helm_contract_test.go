package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestSecurityActivationHelmDefaultsDisabledAndWiresTruthfulReadiness(t *testing.T) {
	values, err := os.ReadFile("../../../../infra/helm/cdnca/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile("../../../../infra/helm/cdnca/templates/control-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../../../../infra/helm/cdnca/values.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(schema, &document); err != nil {
		t.Fatalf("values schema is invalid JSON: %v", err)
	}
	valuesText, templateText, schemaText := string(values), string(template), string(schema)
	for _, required := range []string{
		"securityActivation:", "enabled: false", "reconcileInterval:", "candidateTTL:",
		"requiredWAFAPIVersion:", "requiredCCAPIVersion:",
	} {
		if !strings.Contains(valuesText, required) {
			t.Errorf("values.yaml missing %q", required)
		}
	}
	for _, required := range []string{
		"CDNCA_SECURITY_ACTIVATION_ENABLED", "CDNCA_SECURITY_ACTIVATION_RECONCILE_INTERVAL",
		"CDNCA_SECURITY_ACTIVATION_CANDIDATE_TTL", "CDNCA_SECURITY_ACTIVATION_REQUIRED_WAF_API_VERSION",
		"CDNCA_SECURITY_ACTIVATION_REQUIRED_CC_API_VERSION",
	} {
		if !strings.Contains(templateText, required) {
			t.Errorf("control-api template missing %q", required)
		}
	}
	for _, required := range []string{"securityActivation", "requiredWAFAPIVersion", "requiredCCAPIVersion"} {
		if !strings.Contains(schemaText, required) {
			t.Errorf("values schema missing %q", required)
		}
	}
	definitions := document["definitions"].(map[string]any)
	securityActivation := definitions["securityActivation"].(map[string]any)
	properties := securityActivation["properties"].(map[string]any)
	assertDurationPattern := func(name string, valid, invalid []string) {
		t.Helper()
		property := properties[name].(map[string]any)
		pattern := regexp.MustCompile(property["pattern"].(string))
		for _, value := range valid {
			if !pattern.MatchString(value) {
				t.Errorf("%s rejected valid duration %q", name, value)
			}
		}
		for _, value := range invalid {
			if pattern.MatchString(value) {
				t.Errorf("%s accepted invalid duration %q", name, value)
			}
		}
	}
	assertDurationPattern("reconcileInterval",
		[]string{"100ms", "999ms", "1000ms", "59999ms", "60000ms", "1s", "60s", "1m"},
		[]string{"99ms", "60001ms", "0s", "61s", "2m"})
	assertDurationPattern("candidateTTL",
		[]string{"1m", "60m", "100m", "1440m", "1h", "24h"},
		[]string{"0m", "1441m", "0h", "25h"})
}
