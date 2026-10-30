package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const systemConfigurationHelmEnv = "SYSTEM_CONFIGURATION_RUNTIME_ENABLED"

type systemConfigurationHelmValues struct {
	ControlAPI struct {
		SystemConfiguration struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"systemConfiguration"`
	} `yaml:"controlApi"`
}

func TestSystemConfigurationHelmComposition(t *testing.T) {
	chart := filepath.Join("..", "..", "..", "..", "infra", "helm", "cdnca")
	readValues := func(name string) systemConfigurationHelmValues {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(chart, name))
		if err != nil {
			t.Fatal(err)
		}
		var values systemConfigurationHelmValues
		if err := yaml.Unmarshal(raw, &values); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return values
	}
	if readValues("values.yaml").ControlAPI.SystemConfiguration.Enabled {
		t.Fatal("default system configuration runtime must be disabled")
	}
	if !readValues("values-production.yaml").ControlAPI.SystemConfiguration.Enabled {
		t.Fatal("production system configuration runtime must be enabled")
	}

	rawSchema, err := os.ReadFile(filepath.Join(chart, "values.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Definitions map[string]json.RawMessage `json:"definitions"`
	}
	if err := json.Unmarshal(rawSchema, &schema); err != nil {
		t.Fatalf("parse values schema: %v", err)
	}
	var controlAPI struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema.Definitions["controlApi"], &controlAPI); err != nil {
		t.Fatalf("parse controlApi schema: %v", err)
	}
	if !slices.Contains(controlAPI.Required, "systemConfiguration") {
		t.Fatal("controlApi schema does not require systemConfiguration")
	}
	var systemConfiguration struct {
		Type                 string                     `json:"type"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(controlAPI.Properties["systemConfiguration"], &systemConfiguration); err != nil {
		t.Fatalf("parse systemConfiguration schema: %v", err)
	}
	var enabled struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(systemConfiguration.Properties["enabled"], &enabled); err != nil {
		t.Fatalf("parse systemConfiguration.enabled schema: %v", err)
	}
	if systemConfiguration.Type != "object" || systemConfiguration.AdditionalProperties == nil ||
		*systemConfiguration.AdditionalProperties || !slices.Contains(systemConfiguration.Required, "enabled") ||
		enabled.Type != "boolean" {
		t.Fatalf("systemConfiguration schema is not strict: %#v enabled=%#v", systemConfiguration, enabled)
	}

	rawTemplate, err := os.ReadFile(filepath.Join(chart, "templates", "control-api.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	template := string(rawTemplate)
	if strings.Count(template, "- name: "+systemConfigurationHelmEnv) != 1 {
		t.Fatalf("%s must be injected exactly once", systemConfigurationHelmEnv)
	}
	want := "- name: " + systemConfigurationHelmEnv + "\n              value: {{ .Values.controlApi.systemConfiguration.enabled | quote }}"
	if !strings.Contains(template, want) {
		t.Fatal("system configuration runtime env does not use the strict Helm boolean value")
	}
}
