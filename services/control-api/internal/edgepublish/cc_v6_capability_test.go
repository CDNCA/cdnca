package edgepublish

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// TestCCV6FeaturesRequireCCV6AndNameV5Nodes: trusted crawlers, the pass
// cookie domain, IP lists and header matches need CC v6; a CC v5 node is
// refused by name and a CC v6 node accepted.
func TestCCV6FeaturesRequireCCV6AndNameV5Nodes(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "cc.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	rule := func(conditions ...securitypolicy.Condition) securitypolicy.Rule {
		return securitypolicy.Rule{ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "rate", Priority: 1,
			Enabled: true, Conditions: conditions, Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
				WindowSeconds: 10, MaxRequests: 30, ResponseAction: "reject_429"}}}
	}
	path := securitypolicy.Condition{Field: "path", Operator: "prefix", Values: []string{"/"}}
	cases := map[string]func(*securitypolicy.Policy){
		"trusted crawlers": func(policy *securitypolicy.Policy) {
			policy.CCSettings = &securitypolicy.CCSettings{TrustedCrawlers: []securitypolicy.CCTrustedCrawler{{Name: "google",
				UserAgentTokens: []string{"Googlebot"}, RDNSSuffixes: []string{"googlebot.com"}}}}
		},
		"cookie domain": func(policy *securitypolicy.Policy) {
			policy.CCSettings = &securitypolicy.CCSettings{ChallengeCookieDomain: "example.test"}
		},
		"ip exclusion": func(policy *securitypolicy.Policy) {
			policy.Rules = []securitypolicy.Rule{rule(path,
				securitypolicy.Condition{Field: "client_ip", Operator: "ip_not_in_cidr", Values: []string{"10.0.0.0/8"}})}
		},
		"user agent": func(policy *securitypolicy.Policy) {
			policy.Rules = []securitypolicy.Rule{rule(path,
				securitypolicy.Condition{Field: "user_agent", Operator: "contains", Values: []string{"python"}})}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow,
				[]securitypolicy.Rule{rule(path)})
			mutate(&policy)
			_, site, err := compileSiteFact(scopeID, fact, 8080, nil, []securityBindingFact{securityBindingForEdgeTest(t, policy, siteID, 2)}, nil)
			if err != nil {
				t.Fatalf("compileSiteFact: %v", err)
			}
			required := siteRuntimeV2SecurityRequired(site)
			if got := ccRequirement(required); got != ccV6APIVersion {
				t.Fatalf("policy requires CC v%d, want v%d", got, ccV6APIVersion)
			}
			if listenerCCAPIVersion(&edgeconfig.ListenerSecurity{CC: site.CCV2}) != ccV6APIVersion {
				t.Fatal("site runtime v2 listener does not require CC v6")
			}
			features := func(version uint32) []*agentv1.Capability {
				result := edge135Features()
				for _, feature := range result {
					if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_CC {
						feature.ApiVersion = version
					}
				}
				return result
			}
			nodeID := uuid.New()
			err = targetCapabilityError(nodeID, "1.0.35", required, features(5))
			var refusal *TargetCapabilityError
			if !errors.As(err, &refusal) || refusal.Required != 6 || refusal.Advertised != 5 ||
				!strings.Contains(err.Error(), "trusted crawlers") || !strings.Contains(err.Error(), nodeID.String()) {
				t.Fatalf("CC v6 policy on a CC v5 node: %v", err)
			}
			if err := targetCapabilityError(nodeID, "1.0.35", required, features(6)); err != nil {
				t.Fatalf("CC v6 node refused: %v", err)
			}
		})
	}
}
