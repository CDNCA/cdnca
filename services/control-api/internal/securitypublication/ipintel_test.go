package securitypublication

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// G3-c: WAF rules on the client address' carrier / IDC tag, ASN, country,
// province and city compile to cdnca_iplib conditions (one per field,
// AND-ed) instead of ErrUnsupportedRuntime.
func TestCompileSiteSecurityBindingsCompilesIPIntelRule(t *testing.T) {
	policy := policyForTest(securitypolicy.KindWAF)
	policy.Rules[0].Conditions = []securitypolicy.Condition{
		{Field: "carrier", Operator: "in", Values: []string{"carrier:cn-telecom", "carrier:cn-mobile"}},
		{Field: "country", Operator: "equals", Values: []string{"CN"}},
		{Field: "province", Operator: "not_in", Values: []string{"440000"}},
	}
	policy.Rules[0].Action, policy.Rules[0].Flow = securitypolicy.ActionBlock, securitypolicy.FlowStop
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		t.Fatalf("ValidatePublishablePolicy(ip intel) = %v", err)
	}
	compiled, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{activeBinding(t, policy)})
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings(ip intel) = %v", err)
	}
	want := []edgeconfig.WAFIPIntel{
		{Field: edgeconfig.WAFIPIntelCountry, Values: []string{"CN"}},
		{Field: edgeconfig.WAFIPIntelProvince, Negate: true, Values: []string{"440000"}},
		{Field: edgeconfig.WAFIPIntelTag, Values: []string{"carrier:cn-telecom", "carrier:cn-mobile"}},
	}
	if got := compiled.Site.SecurityPolicies[0].Rules[0].Match.IPIntel; !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled ip intel = %#v", got)
	}
	nginx := renderSiteSecurityForTest(t, testTenantScopeID.String(), compiled.Site)
	if !strings.Contains(nginx, `require("cdnca_iplib").match("tag=0000000000000005")`) {
		t.Fatal("nginx.conf lacks the carrier condition")
	}
}

func TestEdgeWAFMatchIPIntelRejectsAndShadows(t *testing.T) {
	for name, condition := range map[string]securitypolicy.Condition{
		"carrier wrong prefix": {Field: "carrier", Operator: "equals", Values: []string{"idc:cn"}},
		"asn range":            {Field: "asn", Operator: "number_gte", Values: []string{"100"}},
		"asn zero":             {Field: "asn", Operator: "equals", Values: []string{"0"}},
		"equals two":           {Field: "country", Operator: "equals", Values: []string{"CN", "US"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := edgeWAFMatch([]securitypolicy.Condition{condition}); !errors.Is(err, ErrUnsupportedRuntime) {
				t.Fatalf("edgeWAFMatch(%s) error = %v, want ErrUnsupportedRuntime", name, err)
			}
		})
	}
	idc := edgeconfig.WAFMatch{IPIntel: []edgeconfig.WAFIPIntel{{Field: edgeconfig.WAFIPIntelTag, Values: []string{"idc:cn", "idc:global"}}}}
	if !securityMatchCovers(idc, edgeconfig.WAFMatch{IPIntel: []edgeconfig.WAFIPIntel{{Field: edgeconfig.WAFIPIntelTag, Values: []string{"idc:cn"}}}}) ||
		securityMatchCovers(idc, edgeconfig.WAFMatch{Method: "GET"}) {
		t.Fatal("securityMatchCovers ignores the IP intelligence condition")
	}
	// A terminal "block all IDC" rule does not shadow a later rule for other clients.
	policy := policyForTest(securitypolicy.KindWAF)
	policy.Rules = []securitypolicy.Rule{
		{ID: uuid.New(), Name: "idc", Priority: 1, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "ip_tag", Operator: "in", Values: []string{"idc:cn", "idc:global"}}}},
		{ID: uuid.New(), Name: "admin", Priority: 2, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}},
	}
	if _, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{activeBinding(t, policy)}); err != nil {
		t.Fatalf("IDC rule wrongly shadowed a path rule: %v", err)
	}
	// ... but it does shadow a later, narrower IDC rule (never reached).
	policy.Rules[1].Conditions = []securitypolicy.Condition{{Field: "ip_tag", Operator: "equals", Values: []string{"idc:cn"}}}
	if _, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{activeBinding(t, policy)}); err == nil {
		t.Fatal("a rule shadowed by an earlier terminal IDC rule compiled")
	}
}
