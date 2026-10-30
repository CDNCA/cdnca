package dnsreconcilehttp

import (
	"os"
	"strings"
	"testing"
)

func TestCanonicalOpenAPIReferencesOnlyFiveTenantDNSReconcilePaths(t *testing.T) {
	encoded, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	document := string(encoded)
	for _, path := range []string{
		"/v1/sites/{site_id}/dns-reconcile/dry-run:",
		"/v1/sites/{site_id}/dns-reconcile/apply:",
		"/v1/sites/{site_id}/dns-reconcile/tasks/{task_id}:",
		"/v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/commit:",
		"/v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/cancel:",
	} {
		if !strings.Contains(document, path) {
			t.Errorf("canonical OpenAPI is missing %s", path)
		}
	}
	if strings.Contains(document, "/internal/v1/dns/reconcile") || strings.Contains(document, "workloadAuth") {
		t.Fatal("canonical public OpenAPI exposed DNS workload report surface")
	}
}
