package edgepublish

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// Two sites bound to one WAF library with a quick
// block; one site overrides it. The v2 listener security of the overriding
// site runs its effective quick block (same reserved rule IDs, ahead of the
// user rules); the other site runs the library's.
func TestSiteRuntimeV2QuickBlockSiteOverride(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteA := uuid.MustParse("41111111-1111-4111-8111-11111111111a")
	siteB := uuid.MustParse("41111111-1111-4111-8111-11111111111b")
	block := securitypolicy.QuickBlock{BlockIDCCN: true, Carriers: []string{"carrier:cn-mobile"},
		AllowedCrawlers: []securitypolicy.TrustedCrawler{{Networks: []string{"66.249.64.0/19"}, UserAgentPrefixes: []string{"Googlebot"}}}}
	if err := securitypolicy.NormalizeQuickBlock(&block); err != nil {
		t.Fatal(err)
	}
	user := securitypolicy.Rule{ID: uuid.MustParse("018f7a5e-0000-7000-8000-00000000b001"), Name: "admin", Priority: 2, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop}
	policy := securityPolicyForEdgeTest(siteA, securitypolicy.KindWAF, securitypolicy.ActionAllow, nil)
	policy.Rules = securitypolicy.MergeQuickBlockRules(policy.ID, []securitypolicy.Rule{user}, &block)
	policy.QuickBlock = &block

	carriers := []string{"carrier:cn-unicom"}
	override := securitypolicy.QuickBlockOverride{BlockIDCCN: boolPointer(false), BlockIDCGlobal: boolPointer(true),
		Carriers: &carriers, AllowedCrawlers: &[]securitypolicy.TrustedCrawler{}}
	bindings := map[uuid.UUID][]securityBindingFact{
		siteA: {securityBindingForEdgeTest(t, policy, siteA, 1)},
		siteB: {securityBindingForEdgeTest(t, policy, siteB, 1)},
	}
	applySiteQuickBlockOverrides(bindings, map[uuid.UUID]securitypolicy.QuickBlockOverride{siteA: override})

	listener := func(siteID uuid.UUID) []edgeconfig.WAFRule {
		t.Helper()
		security, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.New(), siteRuntimeSecurityTestFact(siteID), 80, bindings[siteID])
		if err != nil || security == nil || len(security.Policies) != 1 {
			t.Fatalf("listener security(%s) = %+v, %v", siteID, security, err)
		}
		// The binding identity stays the published library version.
		if security.Policies[0].PolicyID != policy.ID.String() || security.Policies[0].PolicyVersion != policy.Revision {
			t.Fatalf("policy identity = %+v", security.Policies[0])
		}
		return security.Policies[0].Rules
	}
	a, b := listener(siteA), listener(siteB)
	// Site A: idc:global (slot 1), cn-unicom (slot 2), no crawler, then the user rule.
	if len(a) != 3 || a[0].RuleID != securitypolicy.QuickBlockRuleID(policy.ID, 1).String() ||
		a[0].Match.IPIntel[0].Values[0] != "idc:global" || len(a[0].Match.IPIntel[0].Values) != 1 ||
		a[1].RuleID != securitypolicy.QuickBlockRuleID(policy.ID, 2).String() || a[1].Match.IPIntel[0].Values[0] != "carrier:cn-unicom" ||
		a[2].RuleID != user.ID.String() {
		t.Fatalf("site A rules = %+v", a)
	}
	// Site B: the library's idc:cn, cn-mobile, crawler allow, user rule.
	if len(b) != 4 || b[0].Match.IPIntel[0].Values[0] != "idc:cn" || b[1].Match.IPIntel[0].Values[0] != "carrier:cn-mobile" ||
		b[2].Action != edgeconfig.WAFAllow || b[2].Match.SourceCIDR != "66.249.64.0/19" || b[3].RuleID != user.ID.String() {
		t.Fatalf("site B rules = %+v", b)
	}

	// An override that turns everything off leaves the user rule only.
	off := securitypolicy.QuickBlockOverride{BlockIDCCN: boolPointer(false), Carriers: &[]string{}}
	bindings[siteA] = []securityBindingFact{securityBindingForEdgeTest(t, policy, siteA, 1)}
	applySiteQuickBlockOverrides(bindings, map[uuid.UUID]securitypolicy.QuickBlockOverride{siteA: off})
	if rules := listener(siteA); len(rules) != 1 || rules[0].RuleID != user.ID.String() {
		t.Fatalf("site A off = %+v", rules)
	}

	// An override the site's policy cannot carry is refused for that site.
	blocking := securityPolicyForEdgeTest(siteA, securitypolicy.KindWAF, securitypolicy.ActionBlock, []securitypolicy.Rule{user})
	bindings[siteA] = []securityBindingFact{securityBindingForEdgeTest(t, blocking, siteA, 1)}
	applySiteQuickBlockOverrides(bindings, map[uuid.UUID]securitypolicy.QuickBlockOverride{siteA: {BlockIDCCN: boolPointer(true)}})
	if _, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.New(), siteRuntimeSecurityTestFact(siteA), 80, bindings[siteA]); !errors.Is(err, securitypolicy.ErrQuickBlockUnsupported) {
		t.Fatalf("unsupported override: %v", err)
	}
}
