package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// A v2 site's CC host condition may name any of its domains (server_name):
// an alias, a wildcard alias or a host under it compiles to that match.host;
// a host the site does not serve is refused. The legacy compile (no
// domains) keeps accepting the primary only.
func TestSiteRuntimeV2CCHostConditionCoversEveryDomain(t *testing.T) {
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteRuntimeSecurityTestFact(siteID)
	fact.domains = []string{fact.domain, "www.example.test", "*.alias.example.test"}
	compile := func(host string) (string, error) {
		cc := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow, []securitypolicy.Rule{{
			ID: uuid.MustParse("33333333-3333-4333-8333-333333333334"), Name: "rule", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "host", Operator: "equals", Values: []string{host}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{
				Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 5, ResponseAction: "reject_429"}},
		}})
		security, err := siteRuntimeV2ListenerSecurity(uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), uuid.New(), fact, 8443,
			[]securityBindingFact{securityBindingForEdgeTest(t, cc, siteID, 3)})
		if err != nil {
			return "", err
		}
		if security == nil || security.CC == nil || len(security.CC.Policy.Rules) != 1 {
			t.Fatalf("listener security = %+v", security)
		}
		return security.CC.Policy.Rules[0].Match.Host, nil
	}
	for _, host := range []string{fact.domain, "www.example.test", "*.alias.example.test", "a.alias.example.test"} {
		if got, err := compile(host); err != nil || got != host {
			t.Errorf("host %q: match.host = %q, %v", host, got, err)
		}
	}
	for _, host := range []string{"other.example.test", "alias.example.test"} {
		if _, err := compile(host); err == nil {
			t.Errorf("host %q the site does not serve was accepted", host)
		}
	}
}
