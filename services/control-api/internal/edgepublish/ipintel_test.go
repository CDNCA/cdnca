package edgepublish

import (
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func ipIntelSite() edgeconfig.Site {
	return edgeconfig.Site{SecurityPolicies: []edgeconfig.SecurityPolicy{{Kind: edgeconfig.SecurityWAF,
		Rules: []edgeconfig.WAFRule{{Match: edgeconfig.WAFMatch{IPIntel: []edgeconfig.WAFIPIntel{
			{Field: edgeconfig.WAFIPIntelTag, Values: []string{"idc:cn"}}}}}}}}}
}

// G3-c: a WAF rule on carrier / IDC / ASN / region needs the node's IP
// intelligence library (CAPABILITY_NAME_IP_INTEL v2). Without it the rule
// could never match, so nodes lacking it are refused by name; a release
// without such rules does not require it.
func TestIPIntelRuleRequiresIPIntelV2AndNamesNodesWithout(t *testing.T) {
	required := siteRuntimeV2SecurityRequired(ipIntelSite())
	var capability *agentv1.Capability
	for _, item := range required {
		if item.Name == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
			capability = item
		}
	}
	if capability == nil || capability.ApiVersion != 2 {
		t.Fatalf("required capabilities %v lack IP_INTEL v2", required)
	}
	for _, item := range siteRuntimeV2SecurityRequired(edgeconfig.Site{}) {
		if item.Name == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
			t.Fatal("a release without IP intelligence rules requires IP_INTEL")
		}
	}
	nodeID := uuid.New()
	err := targetCapabilityError(nodeID, "1.0.35", required, edge134Features())
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || !strings.Contains(err.Error(), "IP_INTEL") ||
		!strings.Contains(err.Error(), nodeID.String()) {
		t.Fatalf("IP intelligence rule on a node without IP_INTEL: %v", err)
	}
	v1 := append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 1})
	if err := targetCapabilityError(nodeID, "1.0.35", required, v1); !errors.As(err, &refusal) || refusal.Required != 2 {
		t.Fatalf("IP_INTEL v1 node: %v", err)
	}
	v2 := append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 2})
	if err := targetCapabilityError(nodeID, "1.0.35", required, v2); err != nil {
		t.Fatalf("IP intelligence rule on an IP_INTEL v2 node: %v", err)
	}
	if name, ok := siteruntimecap.Name("ip_intel"); !ok || name != agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
		t.Fatalf("site runtime v2 capability ip_intel = %v,%v", name, ok)
	}
}

func TestCompileSiteFactCompilesIPIntelWAFRule(t *testing.T) {
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "ip.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "block IDC outside CN", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{
			{Field: "ip_tag", Operator: "in", Values: []string{"idc:cn", "idc:global"}},
			{Field: "country", Operator: "not_equals", Values: []string{"CN"}},
			{Field: "method", Operator: "equals", Values: []string{"GET"}},
		},
		Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
	binding := securityBindingForEdgeTest(t, policy, siteID, 1)
	_, site, err := compileSiteFact(binding.policy.ScopeID, fact, 80, nil, []securityBindingFact{binding}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(ip intel, nil) = %v", err)
	}
	want := []edgeconfig.WAFIPIntel{
		{Field: edgeconfig.WAFIPIntelCountry, Negate: true, Values: []string{"CN"}},
		{Field: edgeconfig.WAFIPIntelTag, Values: []string{"idc:cn", "idc:global"}},
	}
	rules := site.SecurityPolicies[0].Rules
	if len(rules) != 1 || rules[0].Match.Method != "GET" || !reflect.DeepEqual(rules[0].Match.IPIntel, want) {
		t.Fatalf("compiled rules = %#v", rules)
	}
	// A set condition expanded into several matches keeps the IP
	// intelligence conditions on every one of them.
	matches, err := compileSecurityRuleMatches("ip.example.test", 80, []securitypolicy.Condition{
		{Field: "carrier", Operator: "equals", Values: []string{"carrier:cn-mobile"}},
		{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24", "198.51.100.0/24"}},
	})
	if err != nil || len(matches) != 2 {
		t.Fatalf("matches = %+v, %v", matches, err)
	}
	for _, match := range matches {
		if len(match.IPIntel) != 1 || match.IPIntel[0].Values[0] != "carrier:cn-mobile" {
			t.Fatalf("expanded match lost the carrier condition: %+v", match)
		}
	}
	for name, condition := range map[string]securitypolicy.Condition{
		"asn range": {Field: "asn", Operator: "number_gte", Values: []string{"100"}},
		"bad city":  {Field: "city", Operator: "equals", Values: []string{"440000"}},
	} {
		if _, err := compileSecurityRuleMatches("ip.example.test", 80, []securitypolicy.Condition{condition}); !errors.Is(err, ErrUnsupportedSecurityPolicy) {
			t.Errorf("%s: err = %v, want ErrUnsupportedSecurityPolicy", name, err)
		}
	}
}

// G3-c gate (节点库未就绪时拒绝发布运营商/IDC 规则并提示，库就绪后
// 自动发布): declaring IP_INTEL v2 is not enough; a node that has never
// applied a verified IP intelligence library (no healthy delivery of the
// ip-intel node manifest) is refused by name, after the nodes lacking the
// capability itself, and the refusal says the library has not loaded yet.
func TestIPIntelRuleRefusesNodesThatNeverLoadedALibrary(t *testing.T) {
	required := siteRuntimeV2SecurityRequired(ipIntelSite())
	v2 := &agentv1.AgentCapabilities{AgentVersion: "1.0.35",
		Features: append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 2})}
	loaded, waiting, unknown := uuid.New(), uuid.New(), uuid.New()
	nodes := []uuid.UUID{loaded, waiting, unknown}
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{loaded: v2, waiting: v2}
	ready := map[uuid.UUID]bool{loaded: true}

	err := ipIntelLibraryTargetsError(nodes, required, sessions, ready)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || refusal.NodeID != waiting ||
		!reflect.DeepEqual(refusal.OtherNodeIDs, []uuid.UUID{unknown}) || refusal.Required != 2 || refusal.Advertised != 2 ||
		refusal.AgentVersion != "1.0.35" || refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
		t.Fatalf("nodes without a loaded library: %#v (%v)", refusal, err)
	}
	if message := err.Error(); !strings.Contains(message, "has not loaded a verified IP intelligence library") ||
		strings.Contains(message, "upgrade the node agent") {
		t.Fatalf("refusal message %q does not say the library is not loaded", message)
	}
	refusal.AutoResume = true
	if message := refusal.Error(); !strings.Contains(message, "once the library reaches the nodes") {
		t.Fatalf("auto-resume message %q", message)
	}
	if err := ipIntelLibraryTargetsError([]uuid.UUID{loaded}, required, sessions, ready); err != nil {
		t.Fatalf("node with a loaded library: %v", err)
	}
	// A release without IP intelligence rules does not look at libraries.
	if err := ipIntelLibraryTargetsError(nodes, siteRuntimeV2SecurityRequired(edgeconfig.Site{}), sessions, nil); err != nil {
		t.Fatalf("release without IP intelligence rules: %v", err)
	}
	// The system republisher rebuilds the refusal from its parts; a node
	// that declares the capability is still reported as waiting for its library.
	rebuilt := refusedAllError([]systemRefusal{{NodeID: waiting, AgentVersion: "1.0.35", Feature: refusal.Feature,
		Capability: refusal.Capability.String(), Required: 2, Advertised: 2}})
	if !strings.Contains(rebuilt.Error(), "has not loaded a verified IP intelligence library") {
		t.Fatalf("rebuilt refusal %q", rebuilt.Error())
	}
}
