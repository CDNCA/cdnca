package entitlementguard

import (
	"os"
	"strings"
	"testing"
)

func TestSITE02DomainQuotaCountsActiveDomainsInstallationWideAndExpansion(t *testing.T) {
	source, err := os.ReadFile("guard.go")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(source)
	for _, required := range []string{
		"func activeDomainCount",
		"site_domain_facts",
		"ExpansionDelta",
		"Count:        activeDomainCount",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("SITE-02 domain quota implementation missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"Count:        activeSiteCount",
		"SELECT count(*) FROM sites WHERE deleted_at IS NULL AND enabled = true",
		// The lease quota is installation-wide; a per-tenant count lets every
		// tenant consume the full licensed domains.count on its own.
		"activeDomainCount(check.AuditScopeID)",
		"WHERE fact.scope_id=$1",
	} {
		if strings.Contains(contract, forbidden) {
			t.Errorf("SITE-02 domain quota retained global site-count authority %q", forbidden)
		}
	}
}
