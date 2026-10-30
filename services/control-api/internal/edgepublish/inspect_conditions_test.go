package edgepublish

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// Content conditions (contains / regex / detect on args, query, body, URI,
// header, cookie, UA, referer) become inspect clauses on the edge match,
// exactly as securitypublication.edgeWAFInspect and the node precheck
// (securityRuntimeInspect) derive them. Before G3-d the publish compiler
// refused them, so no WAF policy with such a rule could be released.
func TestCompileSecurityRuleMatchesCarriesInspectConditions(t *testing.T) {
	matches, err := compileSecurityRuleMatches("cdn.example.test", 80, []securitypolicy.Condition{
		{Field: "user_agent", Operator: "regex", Values: []string{"^Googlebot"}},
		{Field: "args", Operator: "detect", Values: []string{"sqli"}},
		{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"66.249.64.0/19"}},
	})
	if err != nil {
		t.Fatalf("compileSecurityRuleMatches() error = %v", err)
	}
	want := []edgeconfig.WAFMatch{{Host: "cdn.example.test", Port: 80, SourceCIDR: "66.249.64.0/19", Inspect: []edgeconfig.WAFInspect{
		// Snapshot condition order (field, operator, key, values).
		{Target: "args", Operator: "detect", Values: []string{"sqli"}},
		{Target: "user_agent", Operator: "regex", Values: []string{"^Googlebot"}},
	}}}
	if !reflect.DeepEqual(matches, want) {
		t.Fatalf("matches = %#v, want %#v", matches, want)
	}
	if _, err := compileSecurityRuleMatches("cdn.example.test", 80, []securitypolicy.Condition{
		{Field: "args", Operator: "detect", Values: []string{"rce"}},
	}); !errors.Is(err, ErrUnsupportedSecurityPolicy) {
		t.Fatalf("unknown detector: err = %v, want ErrUnsupportedSecurityPolicy", err)
	}
}

func TestCompileSiteFactPublishesCatalogStyleInspectRule(t *testing.T) {
	siteID := uuid.MustParse("31111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 3, domain: "inspect.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("32222222-2222-4222-8222-222222222222"), Name: "sqli", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "args", Operator: "detect", Values: []string{"sqli"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
	binding := securityBindingForEdgeTest(t, policy, siteID, 1)
	_, site, err := compileSiteFact(binding.policy.ScopeID, fact, 80, nil, []securityBindingFact{binding}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(inspect) = %v", err)
	}
	rules := site.SecurityPolicies[0].Rules
	if len(rules) != 1 || len(rules[0].Match.Inspect) != 1 || rules[0].Match.Inspect[0].Target != "args" {
		t.Fatalf("compiled rules = %#v", rules)
	}
}
