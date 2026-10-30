package errorpagecontrol

import (
	"os"
	"strings"
	"testing"
)

func TestSITE13ProductionBundleOpenAPIContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-pages.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	for _, required := range []string{
		"    ErrorPageProductionBundleBinding:",
		"required: [tenant_id, site_id, category, revision, asset_sha256]",
		"    ErrorPageProductionBundleDescriptor:",
		"const: application/vnd.cdnca.edge-error-page-bundle+json;version=1",
		"    ErrorPageActivationReceipt:",
		"required: [schema, state, binding, bundle_sha256, running_config_unchanged]",
		"state: { const: activated }",
		"required: [active_digest]",
		"state: { const: failed }",
		"required: [reason_code]",
		"    ErrorPageActivationFailureCode:",
		"bundle_integrity_failed",
		"binding_mismatch",
		"precheck_failed",
		"activation_failed",
		"health_failed",
		"rollback_failed",
	} {
		if !strings.Contains(fragment, required) {
			t.Fatalf("production bundle OpenAPI contract is missing %q", required)
		}
	}
}
