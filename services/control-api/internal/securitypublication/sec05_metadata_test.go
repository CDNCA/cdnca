package securitypublication

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

func TestSEC05PublicationCarriesCommentAndExpiryToEdgeConfig(t *testing.T) {
	const expiry = "2030-01-02T03:04:05Z"
	policy := policyForTest(securitypolicy.KindACL)
	policy.Rules[0].Comment = "temporary office deny"
	policy.Rules[0].ExpiresAt = expiry
	policy.Rules[0].Conditions = []securitypolicy.Condition{{
		Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.9/24"},
	}}
	binding := activeBinding(t, policy)
	compiled, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	rule := compiled.Site.SecurityPolicies[0].Rules[0]
	if rule.Comment != policy.Rules[0].Comment || rule.ExpiresAt != expiry {
		t.Fatalf("compiled metadata=%#v", rule)
	}
	expiresAt, _ := time.Parse("2006-01-02T15:04:05Z", expiry)
	want := "ngx.time() < " + strconv.FormatInt(expiresAt.Unix(), 10)
	nginx := renderSiteSecurityForTest(t, testTenantScopeID.String(), compiled.Site)
	if !strings.Contains(nginx, want) {
		t.Fatalf("edge config missing %q", want)
	}
}
