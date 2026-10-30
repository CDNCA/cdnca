package edgepublish

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// G3-d #13: a WAF policy's quick block rules (system-managed, ahead of the
// user's rules) publish through both compilers: the legacy site (v1) and the
// site runtime v2 listener security fragments. They need IP_INTEL v2.
func TestQuickBlockRulesPublishOnBothRuntimes(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("41111111-1111-4111-8111-111111111111")
	fact := siteRuntimeSecurityTestFact(siteID)
	block := securitypolicy.QuickBlock{BlockIDCCN: true, BlockIDCGlobal: true, Carriers: []string{"carrier:cn-mobile"},
		AllowedCrawlers: []securitypolicy.TrustedCrawler{{Networks: []string{"66.249.64.0/19"},
			UserAgentPrefixes: []string{"Mozilla/5.0 (compatible; Googlebot/2.1"}}}}
	if err := securitypolicy.NormalizeQuickBlock(&block); err != nil {
		t.Fatal(err)
	}
	user := securitypolicy.Rule{ID: uuid.MustParse("018f7a5e-0000-7000-8000-00000000b001"), Name: "admin", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, nil)
	policy.Rules = securitypolicy.MergeQuickBlockRules(policy.ID, []securitypolicy.Rule{user}, &block)
	policy.QuickBlock = &block
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		t.Fatalf("quick block policy rejected: %v", err)
	}
	binding := securityBindingForEdgeTest(t, policy, siteID, 1)

	_, site, err := compileSiteFact(scopeID, fact, 80, nil, []securityBindingFact{binding}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(quick block) = %v", err)
	}
	rules := site.SecurityPolicies[0].Rules
	if len(rules) != 4 || rules[3].RuleID != user.ID.String() {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].Action != edgeconfig.WAFBlock || rules[0].Control != edgeconfig.WAFContinue ||
		len(rules[0].Match.IPIntel) != 1 || rules[0].Match.IPIntel[0].Field != edgeconfig.WAFIPIntelTag ||
		rules[1].Match.IPIntel[0].Values[0] != "carrier:cn-mobile" ||
		rules[2].Action != edgeconfig.WAFAllow || rules[2].Control != edgeconfig.WAFContinue ||
		rules[2].Match.SourceCIDR != "66.249.64.0/19" || len(rules[2].Match.Inspect) != 1 ||
		rules[2].Match.Inspect[0].Target != "user_agent" {
		t.Fatalf("quick block rules = %+v", rules[:3])
	}
	found := false
	for _, capability := range siteRuntimeV2SecurityRequired(site) {
		found = found || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL && capability.ApiVersion == 2
	}
	if !found {
		t.Fatal("quick block release does not require IP_INTEL v2")
	}

	security, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.New(), fact, 80, []securityBindingFact{binding})
	if err != nil || security == nil || len(security.Policies) != 1 || len(security.Policies[0].Rules) != 4 {
		t.Fatalf("listener security = %+v, %v", security, err)
	}
	fragments, err := edgeconfig.RenderSecurityFragments(scopeID.String(), "cfg-quick-block",
		[]edgeconfig.SecurityListener{{SiteID: siteID.String(), Domain: fact.domain, Port: 80, Protocol: edgeconfig.ProtocolHTTP, Security: *security}})
	if err != nil {
		t.Fatalf("RenderSecurityFragments = %v", err)
	}
	location := strings.Join(fragments.Location, "\n")
	for _, want := range []string{`match("tag=0000000000030000")`, `match("tag=0000000000000004")`,
		`"target":"user_agent"`, `\\(compatible; Googlebot/2\\.1`} {
		if !strings.Contains(location, want) {
			t.Fatalf("v2 location fragment lacks %s:\n%s", want, location)
		}
	}
	if !fragments.NeedsCC {
		t.Fatal("quick block release does not load the security Lua directory")
	}
}
