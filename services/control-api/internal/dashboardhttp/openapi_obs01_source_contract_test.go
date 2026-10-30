package dashboardhttp

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOBS01OpenAPIRetainsSourceAndDegradedContracts(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-dashboard.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Get struct {
				RequiredPermissions []string `yaml:"x-required-permissions"`
				OptionalPermissions []string `yaml:"x-optional-permissions"`
			} `yaml:"get"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string `yaml:"required"`
				Properties map[string]struct {
					Enum    []string `yaml:"enum"`
					Pattern string   `yaml:"pattern"`
				} `yaml:"properties"`
				OneOf []struct {
					Ref string `yaml:"$ref"`
				} `yaml:"oneOf"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}

	dashboard := document.Paths["/v1/dashboard"].Get
	if slices.Contains(dashboard.RequiredPermissions, "nodes.read") {
		t.Fatalf("tenant dashboard required permissions = %v, do not want nodes.read", dashboard.RequiredPermissions)
	}
	if !slices.Contains(dashboard.OptionalPermissions, "nodes.read") {
		t.Fatalf("tenant dashboard optional permissions = %v, want nodes.read", dashboard.OptionalPermissions)
	}

	progress := document.Components.Schemas["SubscriptionTrafficProgress"]
	for _, field := range []string{"finalized_through", "source_watermark", "source_evidence_sha256"} {
		if !slices.Contains(progress.Required, field) {
			t.Errorf("SubscriptionTrafficProgress.required = %v, want %s", progress.Required, field)
		}
	}
	if got := progress.Properties["source_evidence_sha256"].Pattern; got != "^[0-9a-f]{64}$" {
		t.Errorf("source_evidence_sha256 pattern = %q", got)
	}
	meta := document.Components.Schemas["DashboardMeta"]
	if !slices.Contains(meta.Required, "snapshot_at") {
		t.Errorf("DashboardMeta.required = %v, want snapshot_at", meta.Required)
	}
	if _, ok := meta.Properties["snapshot_at"]; !ok {
		t.Errorf("DashboardMeta.properties is missing snapshot_at")
	}
	tenant := document.Components.Schemas["TenantDashboard"]
	if !slices.Contains(tenant.Required, "identity_verification") {
		t.Errorf("TenantDashboard.required = %v, want identity_verification", tenant.Required)
	}
	if _, ok := tenant.Properties["identity_verification"]; !ok {
		t.Errorf("TenantDashboard.properties is missing identity_verification")
	}
	if !slices.Contains(tenant.Required, "profile") {
		t.Errorf("TenantDashboard.required = %v, want profile", tenant.Required)
	}
	if _, ok := tenant.Properties["profile"]; !ok {
		t.Errorf("TenantDashboard.properties is missing profile")
	}
	identityVerification := document.Components.Schemas["IdentityVerificationStats"]
	if !slices.Contains(identityVerification.Required, "verified") {
		t.Errorf("IdentityVerificationStats.required = %v, want verified", identityVerification.Required)
	}
	if _, ok := identityVerification.Properties["verified"]; !ok {
		t.Errorf("IdentityVerificationStats.properties is missing verified")
	}

	unavailable := document.Components.Schemas["UnavailableSection"]
	for _, field := range []string{"available", "reason"} {
		if !slices.Contains(unavailable.Required, field) {
			t.Errorf("UnavailableSection.required = %v, want %s", unavailable.Required, field)
		}
	}
	for _, reason := range []string{"dependency_unavailable", "dependency_timeout", "authoritative_fact_missing"} {
		if !slices.Contains(unavailable.Properties["reason"].Enum, reason) {
			t.Errorf("UnavailableSection.reason enum = %v, want %s", unavailable.Properties["reason"].Enum, reason)
		}
	}
	for _, name := range []string{
		"IdentityVerificationSection", "ProfileSection", "AccountSecuritySection", "NetworkSection",
		"AnalyticsSection", "TenantSubscriptionSection",
	} {
		schema := document.Components.Schemas[name]
		found := false
		for _, branch := range schema.OneOf {
			found = found || branch.Ref == "#/components/schemas/UnavailableSection"
		}
		if !found {
			t.Errorf("%s does not retain the explicit unavailable branch", name)
		}
	}
}
