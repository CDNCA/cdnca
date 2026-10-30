package edgepublish

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestCompileSiteFactCarriesCCV2WithoutLegacyProjection(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "cc.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "limit", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/api"}}},
		Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 10, ResponseAction: "reject_429"}},
	}})
	binding := securityBindingForEdgeTest(t, policy, siteID, 2)
	binding.bindingID = uuid.MustParse("33333333-3333-4333-8333-333333333333")
	snapshot, site, err := compileSiteFact(scopeID, fact, 8080, nil, []securityBindingFact{binding}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact: %v", err)
	}
	if site.CCV2 == nil || len(site.SecurityPolicies) != 0 || len(snapshot.SecurityPolicies) != 0 ||
		len(snapshot.SecurityBindings) != 1 || snapshot.SecurityBindings[0].Kind != securitypolicy.KindCC {
		t.Fatalf("site=%#v snapshot=%#v", site, snapshot)
	}
	if site.CCV2.Policy.SchemaVersion != edgeconfig.CCV2SchemaVersion || site.CCV2.Policy.BindingID != binding.bindingID.String() ||
		!strings.HasPrefix(site.CCV2.Policy.Rules[0].Match.Path.Value, "/api") {
		t.Fatalf("CC v2 site binding = %#v", site.CCV2)
	}
	capabilities := siteRuntimeV2SecurityRequired(site)
	ccFound := false
	for _, capability := range capabilities {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			ccFound = capability.GetApiVersion() == 2
		}
	}
	if !ccFound {
		t.Fatalf("required capabilities = %#v, want CC v2", capabilities)
	}
	nginx := renderSiteSecurityForTest(t, scopeID.String(), site)
	if !strings.Contains(nginx, "cdnca-cc-v2-registry-begin") || strings.Contains(nginx, "cdnca-security kind=cc") {
		t.Fatalf("CC v2 nginx contract missing or mixed with legacy runtime:\n%s", nginx)
	}
}
