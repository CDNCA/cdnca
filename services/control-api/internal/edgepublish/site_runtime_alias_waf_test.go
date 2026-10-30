package edgepublish

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// aliasWAFSecurity compiles one WAF rule with conditions for a v2 site with
// domains (primary first) on port 8443.
func aliasWAFSecurity(t *testing.T, domains []string, conditions []securitypolicy.Condition) (*edgeconfig.ListenerSecurity, error) {
	t.Helper()
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteRuntimeSecurityTestFact(siteID)
	fact.domain, fact.domains = domains[0], domains
	waf := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Name: "rule", Priority: 1, Enabled: true,
		Conditions: conditions, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
	return siteRuntimeV2ListenerSecurity(uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), uuid.New(), fact, 8443,
		[]securityBindingFact{securityBindingForEdgeTest(t, waf, siteID, 3)})
}

func aliasWAFHosts(t *testing.T, security *edgeconfig.ListenerSecurity) []string {
	t.Helper()
	if security == nil || len(security.Policies) != 1 {
		t.Fatalf("listener security = %+v", security)
	}
	hosts := []string{}
	for _, rule := range security.Policies[0].Rules {
		if rule.Match.Port != 8443 {
			t.Fatalf("rule lost its port: %+v", rule)
		}
		hosts = append(hosts, rule.Match.Host)
	}
	return hosts
}

// A v2 site serves every domain in server_name; its WAF rules hold on each,
// so a rule is not pinned to the primary domain (ngx.var.host == primary
// would never hold on an alias).
func TestSiteRuntimeV2WAFRuleHoldsOnEveryAliasDomain(t *testing.T) {
	header := []securitypolicy.Condition{{Field: "header", Key: "x-bad", Operator: "equals", Values: []string{"1"}}}
	for name, domains := range map[string][]string{
		"exact alias":                {"cdn.example.test", "www.example.test"},
		"wildcard alias":             {"cdn.example.test", "*.alias.example.test"},
		"wildcard primary and alias": {"*.x.example", "x.example"},
	} {
		t.Run(name, func(t *testing.T) {
			security, err := aliasWAFSecurity(t, domains, header)
			if err != nil {
				t.Fatal(err)
			}
			if hosts := aliasWAFHosts(t, security); len(hosts) != 1 || hosts[0] != "" {
				t.Fatalf("rule hosts = %q, want one rule scoped by server_name only", hosts)
			}
		})
	}
	// One exact domain keeps its implicit host scope (legacy-identical).
	security, err := aliasWAFSecurity(t, []string{"cdn.example.test"}, header)
	if err != nil {
		t.Fatal(err)
	}
	if hosts := aliasWAFHosts(t, security); len(hosts) != 1 || hosts[0] != "cdn.example.test" {
		t.Fatalf("single domain rule hosts = %q", hosts)
	}
}

// A host condition is decided at compile time against the one domain a
// single-domain site serves; a multi-domain site serves several hosts, so it
// is refused like on a wildcard primary (securitypublication edgeWAFMatch
// refuses WAF host conditions before this compiler runs; this is the
// compiler's own guard). A single exact domain keeps deciding it.
func TestSiteRuntimeV2WAFHostConditionOnSeveralDomainsIsRefused(t *testing.T) {
	host := []securitypolicy.Condition{{Field: "host", Operator: "equals", Values: []string{"www.example.test"}}}
	for name, domains := range map[string][]string{
		"exact alias":    {"cdn.example.test", "www.example.test"},
		"wildcard alias": {"cdn.example.test", "*.example.test"},
	} {
		if _, err := compileSecurityRuleMatchesFor(domains, 8443, host, nil); !errors.Is(err, ErrUnsupportedSecurityPolicy) {
			t.Fatalf("%s: host condition error = %v", name, err)
		}
	}
	if matches, err := compileSecurityRuleMatchesFor([]string{"www.example.test"}, 8443, host, nil); err != nil ||
		len(matches) != 1 || matches[0].Host != "www.example.test" {
		t.Fatalf("single domain host condition = %+v, %v", matches, err)
	}
	if matches, err := compileSecurityRuleMatchesFor([]string{"cdn.example.test"}, 8443, host, nil); err != nil || len(matches) != 0 {
		t.Fatalf("single domain unmatched host condition = %+v, %v", matches, err)
	}
	// Through the whole v2 listener compile the rule is refused too.
	if _, err := aliasWAFSecurity(t, []string{"cdn.example.test", "www.example.test"}, host); err == nil {
		t.Fatal("a host condition on a multi-domain site was accepted")
	}
}

// The legacy (v1) renderer serves the primary domain only: its rules keep the
// primary's implicit host scope whatever aliases the site has.
func TestLegacyWAFRuleKeepsPrimaryHostScope(t *testing.T) {
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteRuntimeSecurityTestFact(siteID)
	fact.domains = []string{fact.domain, "www.example.test"}
	waf := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Name: "rule", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "header", Key: "x-bad", Operator: "equals", Values: []string{"1"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
	_, site, err := compileSiteFact(uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), fact, 8080, nil,
		[]securityBindingFact{securityBindingForEdgeTest(t, waf, siteID, 3)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(site.SecurityPolicies) != 1 || len(site.SecurityPolicies[0].Rules) != 1 ||
		site.SecurityPolicies[0].Rules[0].Match.Host != fact.domain {
		t.Fatalf("legacy WAF = %+v", site.SecurityPolicies)
	}
}
