package securitypublication

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// SF-E01 (Codex security-flow audit 10-27): an ACL allow with expires_at was
// projected into the managed WAF's timeless allow_cidrs, so CRS stayed off
// for the client after the rule expired. Only permanent allows may be there;
// a temporary allow stays in the rule plan with its expiry, from which the
// node derives the time-limited CRS exemption (cdnca_managed_waf.lua).
func TestSFE01TemporaryACLAllowIsNotTimelessCRSBypass(t *testing.T) {
	for _, tc := range []struct {
		name, expiry string
		enabled      bool
		wantTimeless bool
		wantPlanRule bool
	}{
		{name: "permanent", enabled: true, wantTimeless: true, wantPlanRule: true},
		{name: "disabled", expiry: "2030-01-02T03:04:05Z", enabled: false},
		{name: "future", expiry: "2030-01-02T03:04:05Z", enabled: true, wantPlanRule: true},
		{name: "expired", expiry: "2020-01-02T03:04:05Z", enabled: true, wantPlanRule: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cidr := range []string{"192.0.2.9/32", "2001:db8::/64"} {
				acl := securitypolicy.Policy{ID: uuid.New(), ScopeID: testTenantScopeID, Kind: securitypolicy.KindACL,
					Name: "temporary allow", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1,
					Rules: []securitypolicy.Rule{{ID: uuid.New(), Name: "office exception", Priority: 1, Enabled: tc.enabled,
						ExpiresAt: tc.expiry, Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop,
						Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{cidr}}}}}}
				waf, err := (catalogAuditBuilder{}).wafPolicy(auditCatalog(), []string{"waf_set:crs_sqli"}, "")
				if err != nil {
					t.Fatal(err)
				}
				compiled, err := auditCompile(baseSite(), testSiteID, acl, waf)
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
				managed, err := edgeconfig.CanonicalListenerManagedWAF(*compiled.Site.ManagedWAF)
				if err != nil {
					t.Fatal(err)
				}
				if got := slices.Contains(managed.AllowCIDRs, cidr); got != tc.wantTimeless {
					t.Fatalf("%s expires_at=%q in timeless allow_cidrs=%t want %t (%v)", cidr, tc.expiry, got, tc.wantTimeless, managed.AllowCIDRs)
				}
				found := false
				for _, policy := range compiled.Site.SecurityPolicies {
					for _, rule := range policy.Rules {
						if policy.Kind == edgeconfig.SecurityACL && rule.Match.SourceCIDR == cidr && rule.Action == edgeconfig.WAFAllow {
							found = rule.ExpiresAt == tc.expiry
						}
					}
				}
				if found != tc.wantPlanRule {
					t.Fatalf("%s rule plan carries the allow with its expiry=%t want %t", cidr, found, tc.wantPlanRule)
				}
			}
		})
	}
}
