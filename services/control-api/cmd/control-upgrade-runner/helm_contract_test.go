package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlUpgradeRunnerHelmContractIsLeastPrivilegeAndDurable(t *testing.T) {
	chart := filepath.Join("..", "..", "..", "..", "infra", "helm", "cdnca")
	files := map[string][]string{
		filepath.Join(chart, "templates", "control-upgrade-runner.yaml"): {
			"kind: Deployment", "replicas: 1", "strategy:", "type: Recreate", "automountServiceAccountToken: false",
			"expectedReplicas must equal controlApi.replicaCount", "quorum must be a strict majority",
			"CONTROL_UPGRADE_INSTALLATION_ID_FILE", "CONTROL_UPGRADE_TRUST_FILE", "CONTROL_UPGRADE_PLAN_SOURCE_URL",
			"CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE", "CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE",
			"CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE", "CONTROL_UPGRADE_PLAN_LKG_FILE",
			"CONTROL_UPGRADE_INTERNAL_TOKEN_FILE", "CONTROL_UPGRADE_INTERNAL_URL", "CONTROL_UPGRADE_STATE_DIR",
			"cdnca.containerSecurityContext", "persistentVolumeClaim:", "serviceAccountToken:", "expirationSeconds: 3600",
			"-migration",
		},
		filepath.Join(chart, "templates", "control-api.yaml"): {
			"CONTROL_VERSION", "CONTROL_ARTIFACT_SHA256", "CONTROL_UPGRADE_EXPECTED_REPLICAS", "CONTROL_UPGRADE_QUORUM",
			"CONTROL_UPGRADE_INTERNAL_TOKEN_FILE", "serviceAccountToken:", "expirationSeconds: 3600",
		},
		filepath.Join(chart, "templates", "serviceaccounts.yaml"): {
			"resources: [\"secrets\"]", "resourceNames:", "verbs: [\"get\", \"update\", \"patch\"]",
			"kind: RoleBinding", "-upgrade-plan-writer",
		},
		filepath.Join(chart, "templates", "control-upgrade-runner-rbac.yaml"): {
			"kind: Role", "apiGroups: [\"apps\"]", "resources: [\"deployments\"]", "verbs: [\"get\", \"patch\"]",
			"apiGroups: [\"batch\"]", "resources: [\"jobs\"]", "verbs: [\"create\", \"get\"]",
			"resourceNames:", "kind: RoleBinding",
		},
	}
	runnerRBAC, err := os.ReadFile(filepath.Join(chart, "templates", "control-upgrade-runner-rbac.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runnerRBAC), "\"delete\"") {
		t.Error("control upgrade runner includes unused Job delete permission")
	}
	serviceAccounts, err := os.ReadFile(filepath.Join(chart, "templates", "serviceaccounts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"list\"", "\"watch\"", "\"create\"", "\"delete\""} {
		if strings.Contains(string(serviceAccounts), forbidden) {
			t.Errorf("control-api Secret writer includes forbidden verb %s", forbidden)
		}
	}
	for path, required := range files {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range required {
			if !strings.Contains(string(encoded), fragment) {
				t.Errorf("%s missing %q", path, fragment)
			}
		}
	}
	rawSchema, err := os.ReadFile(filepath.Join(chart, "values.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if json.Unmarshal(rawSchema, &schema) != nil {
		t.Fatal("values schema is invalid JSON")
	}
	for _, path := range []string{filepath.Join(chart, "values.yaml"), filepath.Join(chart, "values-production.yaml")} {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range []string{"controlUpgradeRunner:", "enabled:", "state:", "planSecret:", "planSource:", "trustSecret:"} {
			if !strings.Contains(string(encoded), fragment) {
				t.Errorf("%s missing %q", path, fragment)
			}
		}
	}
	rootOpenAPI := filepath.Join("..", "..", "..", "..", "api", "openapi", "v1", "control.yaml")
	fragmentOpenAPI := filepath.Join("..", "..", "..", "..", "api", "control-upgrade-plan.openapi.yaml")
	for path, required := range map[string][]string{
		rootOpenAPI:     {"control-upgrade-plan.openapi.yaml", "/v1/internal/control-upgrade/health:", "/v1/internal/control-upgrade/version:"},
		fragmentOpenAPI: {"control.upgrades.manage", "internalBearer", "Idempotency-Key", "If-Match", "ControlSnapshot", "QuorumUnavailable"},
	} {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range required {
			if !strings.Contains(string(encoded), fragment) {
				t.Errorf("%s missing %q", path, fragment)
			}
		}
	}
}
