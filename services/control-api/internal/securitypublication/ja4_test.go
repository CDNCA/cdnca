package securitypublication

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const (
	testJA4Chrome = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	testJA4Curl   = "t13d3112h2_e8f1e7e78f70_6bebaf5329ac"
)

// ja4block (ja4block/service.go policyFields) publishes exactly this shape:
// a WAF block rule with one ja4 equals condition. It must reach the node as
// a $cdnca_ja4 condition, not ErrUnsupportedRuntime (FX14 / NF02).
func TestCompileSiteSecurityBindingsCompilesJA4BlockRule(t *testing.T) {
	policy := policyForTest(securitypolicy.KindWAF)
	policy.Rules[0].Conditions = []securitypolicy.Condition{{Field: "ja4", Operator: "equals", Values: []string{testJA4Chrome}}}
	policy.Rules[0].Action, policy.Rules[0].Flow = securitypolicy.ActionBlock, securitypolicy.FlowStop
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		t.Fatalf("ValidatePublishablePolicy(ja4 equals) = %v", err)
	}
	compiled, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{activeBinding(t, policy)})
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings(ja4) = %v", err)
	}
	if got := compiled.Site.SecurityPolicies[0].Rules[0].Match.JA4; !slices.Equal(got, []string{testJA4Chrome}) {
		t.Fatalf("compiled JA4 = %v", got)
	}
	nginx := renderSiteSecurityForTest(t, testTenantScopeID.String(), compiled.Site)
	if !strings.Contains(nginx, `ngx.var.cdnca_ja4 == "`+testJA4Chrome+`"`) {
		t.Fatal("nginx.conf lacks the JA4 condition")
	}
}

func TestEdgeWAFMatchJA4SetAndShadowing(t *testing.T) {
	match, err := edgeWAFMatch([]securitypolicy.Condition{
		{Field: "ja4", Operator: "in", Values: []string{testJA4Curl, testJA4Chrome}},
		{Field: "path", Operator: "prefix", Values: []string{"/login"}},
	})
	if err != nil || !slices.Equal(match.JA4, []string{testJA4Chrome, testJA4Curl}) || match.Path == nil {
		t.Fatalf("edgeWAFMatch(ja4 in) = %#v, %v", match, err)
	}
	// fix-ja4rule ②: not_in compiles to NotJA4.
	negated, err := edgeWAFMatch([]securitypolicy.Condition{{Field: "ja4", Operator: "not_in", Values: []string{testJA4Curl, testJA4Chrome}}})
	if err != nil || !slices.Equal(negated.NotJA4, []string{testJA4Chrome, testJA4Curl}) || negated.JA4 != nil {
		t.Fatalf("edgeWAFMatch(ja4 not_in) = %#v, %v", negated, err)
	}
	// A negated rule is never a cover (and is never covered by a set rule).
	if securityMatchCovers(negated, edgeconfig.WAFMatch{NotJA4: negated.NotJA4}) || securityMatchCovers(edgeconfig.WAFMatch{JA4: []string{testJA4Chrome}}, negated) {
		t.Fatal("securityMatchCovers must not treat not_ja4 as coverage")
	}
	for name, condition := range map[string]securitypolicy.Condition{
		"not_equals": {Field: "ja4", Operator: "not_equals", Values: []string{testJA4Chrome}},
		"prefix":     {Field: "ja4", Operator: "prefix", Values: []string{"t13d"}},
		"malformed":  {Field: "ja4", Operator: "equals", Values: []string{"forged-ja4"}},
		"keyed":      {Field: "ja4", Operator: "equals", Key: "x", Values: []string{testJA4Chrome}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := edgeWAFMatch([]securitypolicy.Condition{condition}); !errors.Is(err, ErrUnsupportedRuntime) {
				t.Fatalf("edgeWAFMatch(%s) error = %v, want ErrUnsupportedRuntime", name, err)
			}
		})
	}
	set := edgeconfig.WAFMatch{JA4: []string{testJA4Chrome, testJA4Curl}}
	if !securityMatchCovers(set, edgeconfig.WAFMatch{JA4: []string{testJA4Curl}}) ||
		securityMatchCovers(set, edgeconfig.WAFMatch{Method: "GET"}) ||
		securityMatchCovers(edgeconfig.WAFMatch{JA4: []string{testJA4Chrome}}, set) {
		t.Fatal("securityMatchCovers ignores the JA4 set")
	}
	// A terminal JA4 rule does not shadow a later rule for other clients.
	policy := policyForTest(securitypolicy.KindWAF)
	policy.Rules = []securitypolicy.Rule{
		{ID: uuid.New(), Name: "ja4", Priority: 1, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "ja4", Operator: "equals", Values: []string{testJA4Chrome}}}},
		{ID: uuid.New(), Name: "admin", Priority: 2, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}},
	}
	if _, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{activeBinding(t, policy)}); err != nil {
		t.Fatalf("JA4 rule wrongly shadowed a path rule: %v", err)
	}
}
