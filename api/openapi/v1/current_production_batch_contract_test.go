package v1

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type currentProductionBatchDocument struct {
	Paths map[string]struct {
		Ref string `yaml:"$ref"`
	} `yaml:"paths"`
}

func TestCurrentProductionBatchCanonicalPathRefs(t *testing.T) {
	expected := map[string]string{
		"/v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications":                  "control-origin-auth-publications.openapi.yaml",
		"/v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications/{publication_id}": "control-origin-auth-publications.openapi.yaml",
		"/v1/tenant-scopes/{tenant_scope_id}/error-page-publications":                        "control-error-page-publications.openapi.yaml",
		"/v1/tenant-scopes/{tenant_scope_id}/error-page-publications/{publication_id}":       "control-error-page-publications.openapi.yaml",
		"/v1/recharge-payments/checkouts":                                                    "control-recharge-payments.openapi.yaml",
		"/v1/admin/recharge-payments/orders/{order_id}/refunds":                              "control-recharge-payments.openapi.yaml",
		"/v1/admin/recharge-payments/orders/{order_id}/voids":                                "control-recharge-payments.openapi.yaml",
		"/v1/admin/recharge-payments/orders/{order_id}/reconciliation":                       "control-recharge-payments.openapi.yaml",
		"/v1/recharges/orders":                                    "control-recharges.openapi.yaml",
		"/v1/admin/recharges/orders":                              "control-recharges.openapi.yaml",
		"/v1/admin/recharges/orders/{order_id}/reconciliation":    "control-recharges.openapi.yaml",
		"/v1/admin/recharges/statistics":                          "control-recharges.openapi.yaml",
		"/v1/admin/recharges/statistics.csv":                      "control-recharges.openapi.yaml",
		"/v1/admin/analytics/logs/{kind}/geo-evidence/{event_id}": "control-analytics-geo.openapi.yaml",
		"/v1/analytics/logs/{kind}/geo-evidence/{event_id}":       "control-analytics-geo.openapi.yaml",
		"/v1/admin/control-upgrade-plan":                          "control-upgrade-plan.openapi.yaml",
		"/v1/admin/control-upgrade-plan/run-log":                  "control-upgrade-plan.openapi.yaml",
		"/v1/admin/control-upgrade-plan/options":                  "control-upgrade-plan.openapi.yaml",
		"/v1/admin/control-upgrade-plan/issue":                    "control-upgrade-plan.openapi.yaml",
		"/v1/internal/control-upgrade/plan":                       "control-upgrade-plan.openapi.yaml",
		"/v1/internal/control-upgrade/drain":                      "control-upgrade-plan.openapi.yaml",
		"/v1/internal/control-upgrade/resume":                     "control-upgrade-plan.openapi.yaml",
		"/v1/internal/control-upgrade/health":                     "control-upgrade-plan.openapi.yaml",
		"/v1/internal/control-upgrade/version":                    "control-upgrade-plan.openapi.yaml",
		"/v1/admin/security/coordination/metrics":                 "control-security-coordination-metrics.openapi.yaml",
	}

	root := currentProductionBatchReadDocument(t, "control.yaml")
	for path, fragment := range expected {
		fragmentDocument := currentProductionBatchReadDocument(t, filepath.Join("..", "..", fragment))
		if _, ok := fragmentDocument.Paths[path]; !ok {
			t.Errorf("fragment %s omits %s", fragment, path)
		}
		want := "../../" + fragment + "#/paths/" + currentProductionBatchPointer(path)
		if item, ok := root.Paths[path]; !ok || item.Ref != want {
			t.Errorf("canonical path %s ref = %q, want %q", path, item.Ref, want)
		}
	}
}

func currentProductionBatchReadDocument(t *testing.T, path string) currentProductionBatchDocument {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test path")
	}
	path = filepath.Join(filepath.Dir(filename), path)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document currentProductionBatchDocument
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return document
}

func currentProductionBatchPointer(path string) string {
	return strings.ReplaceAll(strings.ReplaceAll(path, "~", "~0"), "/", "~1")
}
