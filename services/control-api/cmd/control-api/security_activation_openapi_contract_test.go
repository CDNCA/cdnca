package main

import (
	"os"
	"strings"
	"testing"
)

func TestSecurityActivationOpenAPISourceAndBundleStaySynchronized(t *testing.T) {
	fragment, err := os.ReadFile("../../../../api/control-site-publications.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragmentText, rootText := string(fragment), string(root)
	paths := []string{
		"/v1/site-publications/security-activations:",
		"/v1/site-publications/security-activations/{candidate_id}:",
		"/v1/site-publications/security-activations/{candidate_id}/reconcile:",
		"/v1/site-publications/security-activations/{candidate_id}/rollback:",
	}
	for _, path := range paths {
		if !strings.Contains(fragmentText, path) {
			t.Errorf("OpenAPI source fragment is missing %s", path)
		}
		escaped := strings.NewReplacer("/", "~1", "{", "{", "}", "}").Replace(path[:len(path)-1])
		if !strings.Contains(rootText, "#/paths/"+escaped) {
			t.Errorf("root OpenAPI does not delegate %s to the source fragment", path)
		}
	}
	for _, schema := range []string{
		"SecurityActivationCreateRequest:", "SecurityActivationCandidate:",
		"SecurityActivationPromotionCAS:", "SecurityActivationRollbackRequest:",
		"SecurityActivationBinding:", "SecurityActivationStatusResult:",
	} {
		if !strings.Contains(fragmentText, schema) {
			t.Errorf("OpenAPI source fragment is missing %s", schema)
		}
	}
	for _, requirement := range []string{
		"candidate_source_revision", "candidate_config_version_id", "candidate_artifact_sha256",
		"target_snapshot_sha256", "expected_active_policy_version", "security_policies.manage",
		"security_policies.read", "getSecurityPolicyActivationStatus", "policy_kind",
	} {
		if !strings.Contains(fragmentText, requirement) {
			t.Errorf("OpenAPI source fragment is missing %s", requirement)
		}
	}
	for _, operationID := range []string{
		"createSecurityPolicyActivation", "reconcileSecurityPolicyActivation", "rollbackSecurityPolicyActivation",
	} {
		start := strings.Index(fragmentText, "operationId: "+operationID)
		if start < 0 {
			t.Fatalf("OpenAPI source fragment is missing operation %s", operationID)
		}
		section := fragmentText[start:]
		if next := strings.Index(section[1:], "\n  /v1/"); next >= 0 {
			section = section[:next+1]
		}
		for _, header := range []string{"Traceparent", "CorrelationID", "TaskID"} {
			if !strings.Contains(section, "#/components/parameters/"+header) {
				t.Errorf("OpenAPI operation %s is missing %s", operationID, header)
			}
		}
	}
}
