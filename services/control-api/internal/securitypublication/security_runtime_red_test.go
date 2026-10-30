package securitypublication

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

func TestCompileSiteSecurityBindingsSupportsWAFActionFlowMatrix(t *testing.T) {
	for _, action := range []string{
		securitypolicy.ActionAllow,
		securitypolicy.ActionBlock,
		securitypolicy.ActionLog,
	} {
		for _, flow := range []string{securitypolicy.FlowContinue, securitypolicy.FlowStop} {
			t.Run(action+"/"+flow, func(t *testing.T) {
				policy := policyForTest(securitypolicy.KindWAF)
				policy.Rules[0].Action = action
				policy.Rules[0].Flow = flow
				compiled, err := CompileSiteSecurityBindings(
					baseSite(), testTenantScopeID, testSiteID,
					[]ActiveBinding{activeBinding(t, policy)},
				)
				if err != nil {
					t.Fatalf("CompileSiteSecurityBindings: %v", err)
				}
				if len(compiled.Site.SecurityPolicies) != 1 || len(compiled.Site.SecurityPolicies[0].Rules) != 1 {
					t.Fatalf("compiled WAF rules = %#v", compiled.Site.SecurityPolicies)
				}
				wantAction := map[string]edgeconfig.WAFAction{
					securitypolicy.ActionAllow: edgeconfig.WAFAllow,
					securitypolicy.ActionBlock: edgeconfig.WAFBlock,
					securitypolicy.ActionLog:   edgeconfig.WAFLog,
				}[action]
				wantFlow := map[string]edgeconfig.WAFControl{
					securitypolicy.FlowContinue: edgeconfig.WAFContinue,
					securitypolicy.FlowStop:     edgeconfig.WAFStop,
				}[flow]
				if rule := compiled.Site.SecurityPolicies[0].Rules[0]; rule.Action != wantAction || rule.Control != wantFlow {
					t.Fatalf("compiled WAF action/flow = %q/%q, want %q/%q",
						rule.Action, rule.Control, wantAction, wantFlow)
				}
			})
		}
	}
}

func TestCompileSiteSecurityBindingsAcceptsWAFACLAndCCTogether(t *testing.T) {
	acl := policyForTest(securitypolicy.KindACL)
	acl.Rules[0].Conditions = []securitypolicy.Condition{{
		Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"},
	}}
	cc := policyForTest(securitypolicy.KindCC)
	cc.Rules[0].Action = securitypolicy.ActionRateLimit
	cc.Rules[0].Conditions = []securitypolicy.Condition{{
		Field: "path", Operator: "prefix", Values: []string{"/api"},
	}}
	cc.Rules[0].ActionConfig.RateLimit = &securitypolicy.RateLimitConfig{WindowSeconds: 60, MaxRequests: 100}
	bindings := []ActiveBinding{
		activeBinding(t, policyForTest(securitypolicy.KindWAF)),
		activeBinding(t, acl),
		activeBinding(t, cc),
	}
	compiled, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, bindings)
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings: %v", err)
	}
	if len(compiled.Bindings) != 3 ||
		compiled.Bindings[0].Kind != securitypolicy.KindACL ||
		compiled.Bindings[1].Kind != securitypolicy.KindCC ||
		compiled.Bindings[2].Kind != securitypolicy.KindWAF {
		t.Fatalf("compiled security binding identities = %#v", compiled.Bindings)
	}
}
