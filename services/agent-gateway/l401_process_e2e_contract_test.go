package gateway

import (
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestL401ProcessE2EInputContract(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	if _, enabled, err := loadL401ProcessE2EConfig(lookup); err != nil || enabled {
		t.Fatalf("disabled input = enabled:%t err:%v", enabled, err)
	}

	values := map[string]string{"L401_PROCESS_E2E": "1"}
	lookup = func(name string) (string, bool) { value, ok := values[name]; return value, ok }
	if _, enabled, err := loadL401ProcessE2EConfig(lookup); err == nil || !enabled {
		t.Fatalf("incomplete enabled input = enabled:%t err:%v", enabled, err)
	}
}

func TestL401ProcessE2EInputLoadsExactProductionIdentities(t *testing.T) {
	token := privateL401TestFile(t, "token", "opaque-token\n", 0o600)
	agentBinary := privateL401TestFile(t, "edge-agent", "binary", 0o700)
	agentConfig := privateL401TestFile(t, "agent.json", "{}\n", 0o600)
	values := map[string]string{
		"L401_PROCESS_E2E":               "1",
		"L401_NATS_URL":                  "nats://127.0.0.1:4222",
		"L401_CONTROL_BASE_URL":          "http://127.0.0.1:8080",
		"L401_CONTROL_BEARER_TOKEN_FILE": token,
		"L401_CONTROL_SCOPE_ID":          "018f47a2-5b9c-7d31-8a60-104c9c0b7101",
		"L401_NODE_ID":                   "018f47a2-5b9c-7d31-8a60-104c9c0b7102",
		"L401_OLD_ROLLOUT_ID":            "018f47a2-5b9c-7d31-8a60-104c9c0b7103",
		"L401_NEW_ROLLOUT_ID":            "018f47a2-5b9c-7d31-8a60-104c9c0b7104",
		"L401_OLD_DEPLOYMENT_ID":         "018f47a2-5b9c-7d31-8a60-104c9c0b7105",
		"L401_NEW_DEPLOYMENT_ID":         "018f47a2-5b9c-7d31-8a60-104c9c0b7106",
		"L401_AGENT_BINARY":              agentBinary,
		"L401_AGENT_CONFIG_FILE":         agentConfig,
	}
	lookup := func(name string) (string, bool) { value, ok := values[name]; return value, ok }

	config, enabled, err := loadL401ProcessE2EConfig(lookup)
	if err != nil || !enabled {
		t.Fatalf("load exact input = enabled:%t err:%v", enabled, err)
	}
	if config.nodeID != values["L401_NODE_ID"] || config.oldRolloutID != values["L401_OLD_ROLLOUT_ID"] ||
		config.newRolloutID != values["L401_NEW_ROLLOUT_ID"] || config.agentBinary != agentBinary ||
		config.agentConfigFile != agentConfig {
		t.Fatalf("loaded input drifted: %+v", config)
	}
}

func TestL401StatusEvidenceRequiresExactCommandIdentity(t *testing.T) {
	command := &agentv1.DeploymentCommand{DeploymentId: "deployment", Attempt: 2, ConfigVersionId: "config"}
	evidence := &l401CommandEvidence{command: command}
	status := &agentv1.DeploymentStatus{DeploymentId: "deployment", Attempt: 2, ConfigVersionId: "config"}
	if !l401StatusMatchesCommand(status, evidence) {
		t.Fatal("exact status identity was rejected")
	}
	for _, mutate := range []func(*agentv1.DeploymentStatus){
		func(value *agentv1.DeploymentStatus) { value.DeploymentId = "other" },
		func(value *agentv1.DeploymentStatus) { value.Attempt++ },
		func(value *agentv1.DeploymentStatus) { value.ConfigVersionId = "other" },
	} {
		candidate := proto.Clone(status).(*agentv1.DeploymentStatus)
		mutate(candidate)
		if l401StatusMatchesCommand(candidate, evidence) {
			t.Fatalf("mismatched status identity was accepted: %+v", candidate)
		}
	}
}

func privateL401TestFile(t *testing.T, name, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
