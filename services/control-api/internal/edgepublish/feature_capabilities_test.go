package edgepublish

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// edge133Features is what a 1.0.33 agent with a ready security runtime
// declares (agents/edge-agent/cmd/edge-agent/daemon.go agentCapabilities at
// 9150da49): tcp/udp v3, CC v2, and none of capabilities 30-33.
func edge133Features() []*agentv1.Capability {
	return []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 3},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 3},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV6, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 2},
	}
}

// edge134Features is the same node after upgrading to 1.0.34.
func edge134Features() []*agentv1.Capability {
	features := edge133Features()
	for _, feature := range features {
		switch feature.Name {
		case agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY:
			feature.ApiVersion = 4
		case agentv1.CapabilityName_CAPABILITY_NAME_CC:
			feature.ApiVersion = 3
		}
	}
	return append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1})
}

func ccChallengeSiteForEdgeTest(t *testing.T, challenge securitypolicy.ChallengeConfig) (snapshotSite, edgeconfig.Site) {
	t.Helper()
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "cc.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "challenge", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
		Action:     securitypolicy.ActionChallenge, Flow: securitypolicy.FlowStop,
		ActionConfig: securitypolicy.ActionConfig{Challenge: &challenge},
	}})
	snapshot, site, err := compileSiteFact(scopeID, fact, 8080, nil, []securityBindingFact{securityBindingForEdgeTest(t, policy, siteID, 2)}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact: %v", err)
	}
	return snapshot, site
}

func ccRequirement(capabilities []*agentv1.Capability) uint32 {
	for _, capability := range capabilities {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			return capability.GetApiVersion()
		}
	}
	return 0
}

// TestChallengeRequiresCCV3AndRefusesOlderNode: a challenge (always with
// proof of work from the 1.0.35 baseline) requires CC v3; a node declaring CC
// v2 is refused by name and feature, there is no weaker variant for it.
func TestChallengeRequiresCCV3AndRefusesOlderNode(t *testing.T) {
	pow := securitypolicy.ChallengeConfig{Type: "js", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 21600,
		BanSeconds: 360, PowBits: 16, ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}
	nodeID := uuid.MustParse("44444444-4444-4444-8444-444444444444")

	_, site := ccChallengeSiteForEdgeTest(t, pow)
	required := siteRuntimeV2SecurityRequired(site)
	if got := ccRequirement(required); got != ccProofOfWorkAPIVersion {
		t.Fatalf("challenge requires CC v%d, want v%d", got, ccProofOfWorkAPIVersion)
	}
	err := targetCapabilityError(nodeID, "1.0.33", required, edge133Features())
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) ||
		refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_CC || refusal.Required != 3 || refusal.Advertised != 2 ||
		!strings.Contains(err.Error(), nodeID.String()) || !strings.Contains(err.Error(), "1.0.33") ||
		!strings.Contains(err.Error(), "proof of work") {
		t.Fatalf("CC v2 node refusal = %v", err)
	}
	if err := targetCapabilityError(nodeID, "1.0.34", required, edge134Features()); err != nil {
		t.Fatalf("CC v3 node refused: %v", err)
	}
	if listenerCCAPIVersion(&edgeconfig.ListenerSecurity{CC: site.CCV2}) != ccProofOfWorkAPIVersion {
		t.Fatal("site runtime v2 listener with a challenge does not require CC v3")
	}
}

// TestCatalogCCRuleRefusesCCV2Node: a CC rule from the catalog always carries
// proof of work, so a release with it is refused for a CC v2 node.
func TestCatalogCCRuleRefusesCCV2Node(t *testing.T) {
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CurrentSeed() {
		items[item.SystemKey] = item
	}
	nodeID := uuid.New()
	rules, err := securitypolicy.ExpandCCRuleGroup(items, "cc_rule:10001")
	if err != nil || len(rules) != 1 || rules[0].ActionConfig.Challenge == nil {
		t.Fatalf("expand: %+v, %v", rules, err)
	}
	_, site := ccChallengeSiteForEdgeTest(t, *rules[0].ActionConfig.Challenge)
	required := siteRuntimeV2SecurityRequired(site)
	if ccRequirement(required) != ccProofOfWorkAPIVersion || targetCapabilityError(nodeID, "1.0.33", required, edge133Features()) == nil {
		t.Fatalf("catalog rule: CC v%d, CC v2 node not refused", ccRequirement(required))
	}
	if err := targetCapabilityError(nodeID, "1.0.34", required, edge134Features()); err != nil {
		t.Fatalf("CC v3 node refused: %v", err)
	}
}

// TestManagedWAFAndSharedL4RefuseOnly133Nodes: the other gated features name
// themselves; ungated requirements (CC v2, tcp v2) are left to the agent.
func TestManagedWAFAndSharedL4RefuseOnly133Nodes(t *testing.T) {
	nodeID := uuid.New()
	for _, test := range []struct {
		required *agentv1.Capability
		feature  string
	}{
		{&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1}, "OWASP CRS"},
		{&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 4}, "TLS passthrough"},
	} {
		required := []*agentv1.Capability{test.required}
		err := targetCapabilityError(nodeID, "1.0.33", required, edge133Features())
		if !errors.Is(err, ErrTargetIneligible) || !strings.Contains(err.Error(), test.feature) {
			t.Fatalf("%s on a 1.0.33 node: %v", test.required.Name, err)
		}
		if err := targetCapabilityError(nodeID, "1.0.34", required, edge134Features()); err != nil {
			t.Fatalf("%s on a 1.0.34 node: %v", test.required.Name, err)
		}
	}
	ungated := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 2},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 2}}
	if err := targetCapabilityError(nodeID, "0.9", ungated, nil); err != nil {
		t.Fatalf("ungated requirement refused: %v", err)
	}
}

// A drain limit other than the default rides on every v2 stream as
// drain_max_ms, which agents before tcp/udp v5 decode strictly and refuse: the
// release requires v5 and a 1.0.34 node gets a readable refusal. Unset, the
// stream keeps requiring what it did.
func TestL4DrainLimitRequiresTCPV5AndRefuses134Node(t *testing.T) {
	nodeID := uuid.New()
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 5}}
	err := targetCapabilityError(nodeID, "1.0.34", required, edge134Features())
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || refusal.Advertised != 4 ||
		!strings.Contains(err.Error(), "drain limit") || !strings.Contains(err.Error(), nodeID.String()) {
		t.Fatalf("drain limit on a 1.0.34 node: %v", err)
	}
	edge135 := edge134Features()
	for _, feature := range edge135 {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY {
			feature.ApiVersion = 5
		}
	}
	if err := targetCapabilityError(nodeID, "1.0.35", required, edge135); err != nil {
		t.Fatalf("drain limit on a v5 node: %v", err)
	}
}

// TestCountByRequiresCCV4AndRefusesEveryV3Node: a CC rule counting by
// network / host / URI / TLS fingerprint needs CC v4 (agents before it
// refuse the whole policy and the site answers 503). The release requires
// v4, every target node below it is named in one refusal, and a v4 node is
// accepted; without count_by the requirement stays where it was.
func TestCountByRequiresCCV4AndRefusesEveryV3Node(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "cc.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "cidr", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
		Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
			WindowSeconds: 10, MaxRequests: 30, ResponseAction: "reject_429"}},
		CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyClientCIDR, IPv4Prefix: 24, IPv6Prefix: 64}},
	}})
	_, site, err := compileSiteFact(scopeID, fact, 8080, nil, []securityBindingFact{securityBindingForEdgeTest(t, policy, siteID, 2)}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact: %v", err)
	}
	required := siteRuntimeV2SecurityRequired(site)
	if got := ccRequirement(required); got != ccCountByAPIVersion {
		t.Fatalf("count_by policy requires CC v%d, want v%d", got, ccCountByAPIVersion)
	}
	if listenerCCAPIVersion(&edgeconfig.ListenerSecurity{CC: site.CCV2}) != ccCountByAPIVersion {
		t.Fatal("site runtime v2 listener with count_by does not require CC v4")
	}
	first, second := uuid.MustParse("44444444-4444-4444-8444-444444444444"), uuid.MustParse("55555555-5555-4555-8555-555555555555")
	current := uuid.New()
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		first:   {AgentVersion: "1.0.34", Features: edge134Features()},
		current: {AgentVersion: "1.0.35", Features: edge135Features()},
		second:  {AgentVersion: "1.0.34", Features: edge134Features()},
	}
	refusal := capabilityTargetsError([]uuid.UUID{first, current, second}, required, sessions)
	var capability *TargetCapabilityError
	if !errors.As(refusal, &capability) || !errors.Is(refusal, ErrTargetIneligible) ||
		capability.Capability != agentv1.CapabilityName_CAPABILITY_NAME_CC || capability.Required != 4 || capability.Advertised != 3 ||
		capability.NodeID != first || len(capability.OtherNodeIDs) != 1 || capability.OtherNodeIDs[0] != second ||
		!strings.Contains(refusal.Error(), first.String()) || !strings.Contains(refusal.Error(), second.String()) ||
		strings.Contains(refusal.Error(), current.String()) || !strings.Contains(refusal.Error(), "counting by") {
		t.Fatalf("v3 nodes refusal = %v", refusal)
	}
	if err := targetCapabilityError(uuid.New(), "1.0.35", required, edge135Features()); err != nil {
		t.Fatalf("CC v4 node refused: %v", err)
	}
	// Proof of work alone still asks for v3 only.
	_, powSite := ccChallengeSiteForEdgeTest(t, securitypolicy.ChallengeConfig{Type: "js", FailureWindowSeconds: 60, MaxFailures: 5,
		PassSeconds: 21600, BanSeconds: 360, PowBits: 16, ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400})
	if listenerCCAPIVersion(&edgeconfig.ListenerSecurity{CC: powSite.CCV2}) != ccProofOfWorkAPIVersion {
		t.Fatal("proof-of-work policy no longer requires exactly CC v3")
	}
}

// edge135Features is a 1.0.35 node: CC v4 (counting keys).
func edge135Features() []*agentv1.Capability {
	features := edge134Features()
	for _, feature := range features {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			feature.ApiVersion = 4
		}
	}
	return features
}

// new_conn_rate (单 IP 新建连接速率) rides on the stream it limits, which agents
// before tcp/udp v6 decode strictly and refuse: the release requires v6 and
// every node without it is named in one readable refusal. Unset, the stream
// keeps requiring what it did.
func TestL4NewConnRateRequiresTCPV6AndNamesEveryOldNode(t *testing.T) {
	stream := edgeconfig.L4StreamRuntimeV2{Listener: edgeconfig.L4ListenerV2{Protocol: "udp", Address: "*", Port: 18443}}
	limit := 3_600_000
	stream.DrainMaxMS = &limit
	stream.NewConnRate = &edgeconfig.L4NewConnRateV2{RatePerSecond: 10}
	edge135 := edge134Features()
	for _, feature := range edge135 {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY {
			feature.ApiVersion = 6
		}
	}
	first, second, current := uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		uuid.MustParse("00000000-0000-4000-8000-000000000002"), uuid.MustParse("00000000-0000-4000-8000-000000000003")
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 6}}
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		first:   {AgentVersion: "1.0.34", Features: edge134Features()},
		second:  {AgentVersion: "1.0.34", Features: edge134Features()},
		current: {AgentVersion: "1.0.35", Features: edge135},
	}
	err := capabilityTargetsError([]uuid.UUID{current, second, first}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || refusal.NodeID != second || refusal.Advertised != 4 ||
		!strings.Contains(err.Error(), "new connection rate") || !strings.Contains(err.Error(), second.String()) ||
		!strings.Contains(err.Error(), first.String()) || strings.Contains(err.Error(), current.String()) ||
		len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != first {
		t.Fatalf("new connection rate on two 1.0.34 nodes: %v (%+v)", err, refusal)
	}
	if err := capabilityTargetsError([]uuid.UUID{current}, required, sessions); err != nil {
		t.Fatalf("new connection rate on a v6 node: %v", err)
	}
}

// A WAF rule on the TLS fingerprint needs a node that computes it (native
// runtime with ngx_http_cdnca_ja4_module, CAPABILITY_NAME_JA4 v1). Without
// it $cdnca_ja4 is empty and the rule would silently never match, so the
// release requires JA4 v1 and nodes lacking it are refused by name.
func TestJA4RuleRequiresJA4CapabilityAndRefusesNodeWithout(t *testing.T) {
	site := edgeconfig.Site{SecurityPolicies: []edgeconfig.SecurityPolicy{{Kind: edgeconfig.SecurityWAF,
		Rules: []edgeconfig.WAFRule{{Match: edgeconfig.WAFMatch{JA4: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}}}}}}}
	required := siteRuntimeV2SecurityRequired(site)
	var ja4 *agentv1.Capability
	for _, capability := range required {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_JA4 {
			ja4 = capability
		}
	}
	if ja4 == nil || ja4.ApiVersion != 1 {
		t.Fatalf("required capabilities %v lack JA4 v1", required)
	}
	plain := siteRuntimeV2SecurityRequired(edgeconfig.Site{})
	for _, capability := range plain {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_JA4 {
			t.Fatal("a release without JA4 rules requires JA4")
		}
	}
	nodeID := uuid.New()
	err := targetCapabilityError(nodeID, "1.0.34", required, edge134Features())
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || !strings.Contains(err.Error(), "JA4") ||
		!strings.Contains(err.Error(), nodeID.String()) {
		t.Fatalf("JA4 rule on a node without JA4: %v", err)
	}
	withJA4 := append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_JA4, ApiVersion: 1})
	if err := targetCapabilityError(nodeID, "1.0.35", required, withJA4); err != nil {
		t.Fatalf("JA4 rule on a JA4 node: %v", err)
	}
}

// fix-ja4rule ②: a WAF rule "JA4 not in list" needs WAF_JA4_NEGATION v1 as
// well as JA4; a JA4 node without it is refused as too old, by name.
func TestNotJA4RuleRequiresJA4NegationCapability(t *testing.T) {
	site := edgeconfig.Site{SecurityPolicies: []edgeconfig.SecurityPolicy{{Kind: edgeconfig.SecurityWAF,
		Rules: []edgeconfig.WAFRule{{Match: edgeconfig.WAFMatch{NotJA4: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}}}}}}}
	required := siteRuntimeV2SecurityRequired(site)
	versions := map[agentv1.CapabilityName]uint32{}
	for _, capability := range required {
		versions[capability.GetName()] = capability.GetApiVersion()
	}
	if versions[agentv1.CapabilityName_CAPABILITY_NAME_JA4] != 1 || versions[agentv1.CapabilityName_CAPABILITY_NAME_WAF_JA4_NEGATION] != 1 {
		t.Fatalf("required %v lacks JA4 v1 / WAF_JA4_NEGATION v1", required)
	}
	for _, capability := range siteRuntimeV2SecurityRequired(edgeconfig.Site{SecurityPolicies: []edgeconfig.SecurityPolicy{{Kind: edgeconfig.SecurityWAF,
		Rules: []edgeconfig.WAFRule{{Match: edgeconfig.WAFMatch{JA4: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}}}}}}}) {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF_JA4_NEGATION {
			t.Fatal("a JA4 in-list rule requires WAF_JA4_NEGATION")
		}
	}
	nodeID := uuid.New()
	withJA4 := append(edge135Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_JA4, ApiVersion: 1})
	err := targetCapabilityError(nodeID, "1.0.35", required, withJA4)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_WAF_JA4_NEGATION ||
		!strings.Contains(err.Error(), "节点版本过低") || !strings.Contains(err.Error(), nodeID.String()) {
		t.Fatalf("JA4 node without WAF_JA4_NEGATION = %v", err)
	}
	withNegation := append(withJA4, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_JA4_NEGATION, ApiVersion: 1})
	if err := targetCapabilityError(nodeID, "1.0.35", required, withNegation); err != nil {
		t.Fatalf("JA4 + WAF_JA4_NEGATION node refused: %v", err)
	}
}

// fix-ja4rule ③: a CC rule counting by User-Agent / header / cookie / query
// or matching on JA4 needs CC v7 and CC_MATCH_KEYS v1 (JA4 v1 too for the JA4
// match); a CC v6 node is refused as too old, by name.
func TestCCMatchKeysRequireCCV7AndCapability(t *testing.T) {
	policy := edgeconfig.CCV2Policy{Enabled: true, Rules: []edgeconfig.CCV2Rule{{
		CountBy: []edgeconfig.CCV2CountKey{{Key: edgeconfig.CCV2CountHeader, Name: "x-api-key"}},
		Match:   edgeconfig.CCV2Match{JA4: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}}}}}
	required := siteRuntimeV2SecurityRequired(edgeconfig.Site{CCV2: &edgeconfig.CCV2SiteBinding{Policy: policy}})
	versions := map[agentv1.CapabilityName]uint32{}
	for _, capability := range required {
		versions[capability.GetName()] = capability.GetApiVersion()
	}
	if ccRequirement(required) != 7 || versions[agentv1.CapabilityName_CAPABILITY_NAME_CC_MATCH_KEYS] != 1 ||
		versions[agentv1.CapabilityName_CAPABILITY_NAME_JA4] != 1 {
		t.Fatalf("required %v: want CC v7, CC_MATCH_KEYS v1, JA4 v1", required)
	}
	nodeID := uuid.New()
	v6 := append(edge135Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_JA4, ApiVersion: 1})
	err := targetCapabilityError(nodeID, "1.0.35", required, v6)
	if err == nil || !strings.Contains(err.Error(), "节点版本过低") || !strings.Contains(err.Error(), nodeID.String()) {
		t.Fatalf("CC v6 node = %v", err)
	}
	v7 := []*agentv1.Capability{}
	for _, capability := range v6 {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			capability = &agentv1.Capability{Name: capability.GetName(), ApiVersion: 7}
		}
		v7 = append(v7, capability)
	}
	v7 = append(v7, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC_MATCH_KEYS, ApiVersion: 1})
	if err := targetCapabilityError(nodeID, "1.0.35", required, v7); err != nil {
		t.Fatalf("CC v7 + CC_MATCH_KEYS node refused: %v", err)
	}
}

// TestCountByJA4RequiresJA4V1AndCCV4: counting by TLS fingerprint reads
// $cdnca_ja4, which only nodes declaring JA4 v1 compute; the release needs
// both CC v4 and JA4 v1, and a CC v4 node without the JA4 module is named.
func TestCountByJA4RequiresJA4V1AndCCV4(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "cc.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "ja4", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
		Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
			WindowSeconds: 60, MaxRequests: 100, ResponseAction: "temporary_ban", BanSeconds: 300}},
		CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyJA4}}, ActionTarget: securitypolicy.ActionTargetCountKey,
	}})
	_, site, err := compileSiteFact(scopeID, fact, 8080, nil, []securityBindingFact{securityBindingForEdgeTest(t, policy, siteID, 2)}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact: %v", err)
	}
	required := siteRuntimeV2SecurityRequired(site)
	ja4 := uint32(0)
	for _, capability := range required {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_JA4 {
			ja4 = capability.GetApiVersion()
		}
	}
	if ccRequirement(required) != ccCountByAPIVersion || ja4 != ja4APIVersion {
		t.Fatalf("ja4 count_by requires CC v%d, JA4 v%d", ccRequirement(required), ja4)
	}
	if !edgeconfig.ListenerSecurityUsesJA4(&edgeconfig.ListenerSecurity{CC: site.CCV2}) {
		t.Fatal("site runtime v2 listener counting by ja4 does not need JA4")
	}
	withoutModule := uuid.New()
	err = targetCapabilityError(withoutModule, "1.0.35", required, edge135Features())
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_JA4 ||
		!strings.Contains(err.Error(), withoutModule.String()) {
		t.Fatalf("CC v4 node without JA4 = %v", err)
	}
	withModule := append(edge135Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_JA4, ApiVersion: 1})
	if err := targetCapabilityError(uuid.New(), "1.0.35", required, withModule); err != nil {
		t.Fatalf("CC v4 + JA4 node refused: %v", err)
	}
}

// TestAutoSwitchRequiresCCV5AndNamesV4Nodes: a CC policy with an active auto
// switch (自动切换) needs CC v5; a v4 node (1.0.35 before G1-e) is refused by
// name and a v5 node accepted.
func TestAutoSwitchRequiresCCV5AndNamesV4Nodes(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteFact{id: siteID, revision: 7, domain: "cc.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
	rate := func(id string, requests int) securitypolicy.Rule {
		return securitypolicy.Rule{ID: uuid.MustParse(id), Name: "rate", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
				WindowSeconds: 10, MaxRequests: requests, ResponseAction: "reject_429"}}}
	}
	policy := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow,
		[]securitypolicy.Rule{rate("22222222-2222-4222-8222-222222222222", 300)})
	policy.CCSettings = &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom,
		QPSTotal: 100, RecoverSeconds: 300, RuleGroups: []string{},
		Rules: []securitypolicy.Rule{rate("33333333-3333-4333-8333-333333333333", 20)}}}
	_, site, err := compileSiteFact(scopeID, fact, 8080, nil, []securityBindingFact{securityBindingForEdgeTest(t, policy, siteID, 2)}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact: %v", err)
	}
	required := siteRuntimeV2SecurityRequired(site)
	if got := ccRequirement(required); got != ccAutoSwitchAPIVersion {
		t.Fatalf("auto switch policy requires CC v%d, want v%d", got, ccAutoSwitchAPIVersion)
	}
	if listenerCCAPIVersion(&edgeconfig.ListenerSecurity{CC: site.CCV2}) != ccAutoSwitchAPIVersion {
		t.Fatal("site runtime v2 listener with an auto switch does not require CC v5")
	}
	nodeID := uuid.New()
	err = targetCapabilityError(nodeID, "1.0.35", required, edge135Features())
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.Required != 5 || refusal.Advertised != 4 ||
		!strings.Contains(err.Error(), "auto switch") || !strings.Contains(err.Error(), nodeID.String()) {
		t.Fatalf("auto switch on a CC v4 node: %v", err)
	}
	v5 := edge135Features()
	for _, feature := range v5 {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			feature.ApiVersion = 5
		}
	}
	if err := targetCapabilityError(nodeID, "1.0.35", required, v5); err != nil {
		t.Fatalf("CC v5 node refused: %v", err)
	}
}

// session_log (会话日志) needs tcp/udp v7; a v6 node is named in the refusal.
func TestL4SessionLogRequiresTCPV7AndNamesEveryOldNode(t *testing.T) {
	features := func(version uint32) []*agentv1.Capability {
		result := edge134Features()
		for _, feature := range result {
			if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY {
				feature.ApiVersion = version
			}
		}
		return result
	}
	old, current := uuid.MustParse("00000000-0000-4000-8000-000000000001"), uuid.MustParse("00000000-0000-4000-8000-000000000002")
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 7}}
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		old: {AgentVersion: "1.0.35-g4a", Features: features(6)}, current: {AgentVersion: "1.0.35", Features: features(7)},
	}
	err := capabilityTargetsError([]uuid.UUID{current, old}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != old || refusal.Advertised != 6 || !strings.Contains(err.Error(), "session log") {
		t.Fatalf("session log on a v6 node: %v", err)
	}
	if err := capabilityTargetsError([]uuid.UUID{current}, required, sessions); err != nil {
		t.Fatalf("session log on a v7 node: %v", err)
	}
}

// A port range or follow-port origin (port_end / follow_port) needs tcp/udp
// v9; every v8 node is named in the refusal.
func TestL4PortRangeRequiresTCPV9AndNamesEveryOldNode(t *testing.T) {
	features := func(version uint32) []*agentv1.Capability {
		result := edge134Features()
		for _, feature := range result {
			if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY {
				feature.ApiVersion = version
			}
		}
		return result
	}
	first, second := uuid.MustParse("00000000-0000-4000-8000-000000000001"), uuid.MustParse("00000000-0000-4000-8000-000000000002")
	current := uuid.MustParse("00000000-0000-4000-8000-000000000003")
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 9}}
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		first: {AgentVersion: "1.0.35-g5", Features: features(8)}, second: {AgentVersion: "1.0.35-g4b", Features: features(7)},
		current: {AgentVersion: "1.0.35", Features: features(9)},
	}
	err := capabilityTargetsError([]uuid.UUID{current, first, second}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != first || refusal.Advertised != 8 || refusal.Required != 9 ||
		len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != second || !strings.Contains(err.Error(), "port range") {
		t.Fatalf("port range on v8/v7 nodes: %v %+v", err, refusal)
	}
	if err := capabilityTargetsError([]uuid.UUID{current}, required, sessions); err != nil {
		t.Fatalf("port range on a v9 node: %v", err)
	}
}

// Guard rules (guard_rules) need tcp/udp v10, above every other L4 feature;
// every v9 node is named; a geo condition also requires IP_INTEL v2 in the
// deployment (and so the library readiness gate).
func TestL4GuardRulesRequireTCPV10AndIPIntelForGeo(t *testing.T) {
	guarded := edgeconfig.L4StreamRuntimeV2{Listener: edgeconfig.L4ListenerV2{Protocol: "udp", Address: "*", Port: 20000, PortEnd: 20010},
		Endpoint: edgeconfig.L4EndpointV2{Address: "192.0.2.1", Port: 20000, FollowPort: true},
		GuardRules: []edgeconfig.L4GuardRuleV2{{ID: "66666666-6666-4666-8666-666666666661", Action: edgeconfig.L4GuardActionDrop,
			ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"192.0.2.0/24"}}}}}
	streams := []edgeconfig.L4StreamRuntimeV2{guarded}
	capabilities := map[agentv1.CapabilityName]uint32{}
	for _, capability := range siteRuntimeV2StreamsRequired(streams) {
		capabilities[capability.GetName()] = capability.GetApiVersion()
	}
	if capabilities[agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY] != 12 || capabilities[agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL] != 0 {
		t.Fatalf("client IP guard rule capabilities: %v", capabilities)
	}
	streams[0].GuardRules[0].Geo = []edgeconfig.WAFIPIntel{{Field: edgeconfig.WAFIPIntelTag, Values: []string{"idc:global"}}}
	capabilities = map[agentv1.CapabilityName]uint32{}
	for _, capability := range siteRuntimeV2StreamsRequired(streams) {
		capabilities[capability.GetName()] = capability.GetApiVersion()
	}
	if capabilities[agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL] != edgeconfig.IPIntelCapabilityVersion || !requiresIPIntel(siteRuntimeV2StreamsRequired(streams)) {
		t.Fatalf("geo guard rule capabilities: %v", capabilities)
	}

	features := func(version uint32) []*agentv1.Capability {
		result := edge134Features()
		for _, feature := range result {
			if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY {
				feature.ApiVersion = version
			}
		}
		return result
	}
	first, second := uuid.MustParse("00000000-0000-4000-8000-000000000001"), uuid.MustParse("00000000-0000-4000-8000-000000000002")
	current := uuid.MustParse("00000000-0000-4000-8000-000000000003")
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 10}}
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		first: {AgentVersion: "1.0.35-g4c", Features: features(9)}, second: {AgentVersion: "1.0.35-g4b", Features: features(7)},
		current: {AgentVersion: "1.0.35", Features: features(10)},
	}
	err := capabilityTargetsError([]uuid.UUID{current, first, second}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != first || refusal.Advertised != 9 || refusal.Required != 10 ||
		len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != second || !strings.Contains(err.Error(), "guard rules") {
		t.Fatalf("guard rules on v9/v7 nodes: %v %+v", err, refusal)
	}
	if err := capabilityTargetsError([]uuid.UUID{current}, required, sessions); err != nil {
		t.Fatalf("guard rules on a v10 node: %v", err)
	}
}

// A WAF policy with a managed WAF (OWASP CRS) rule publishes: the managed
// rule becomes the site's ManagedWAF, not a Lua rule (it was refused as
// "cannot be represented safely", so no managed WAF could be published).
func TestCompileSiteFactPublishesManagedWAFPolicy(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	snapshot, site, err := compileSiteFact(scopeID, siteRuntimeSecurityTestFact(siteID), 8080, nil,
		[]securityBindingFact{securityBindingForEdgeTest(t, managedWAFPolicyForEdgeTest(siteID), siteID, 2)}, nil)
	if err != nil {
		t.Fatalf("compileSiteFact: %v", err)
	}
	if site.ManagedWAF == nil || site.ManagedWAF.InspectionLimitAction != "block" || len(site.SecurityPolicies) != 1 ||
		len(site.SecurityPolicies[0].Rules) != 1 || len(snapshot.SecurityBindings) != 1 {
		t.Fatalf("site = %+v", site)
	}
}

// Every site runtime v2 document needs site_runtime v6, the 1.0.35 baseline,
// whatever the sites use: the refusal names the node version, not features
// (cache / JS challenge / managed WAF) the site may not use.
func TestSiteRuntimeBaselineRefusalNamesThe1035Node(t *testing.T) {
	nodeID := uuid.New()
	for name, advertised := range map[string][]*agentv1.Capability{
		"v5 node":         {{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 5}},
		"v2 node":         {{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 2}},
		"no site runtime": {{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}},
	} {
		refusal := targetCapabilityError(nodeID, "1.0.34", []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: siteRuntimeV6APIVersion},
		}, advertised)
		if refusal == nil {
			t.Fatalf("%s: not refused", name)
		}
		message := refusal.Error()
		for _, want := range []string{nodeID.String(), "1.0.34", "1.0.35", "节点版本低于 1.0.35"} {
			if !strings.Contains(message, want) {
				t.Errorf("%s: refusal lacks %q: %s", name, want, message)
			}
		}
		for _, misleading := range []string{"网站缓存", "JS 挑战", "托管 WAF", "site caching", "remove the feature"} {
			if strings.Contains(message, misleading) {
				t.Errorf("%s: refusal names %q, which the site may not use: %s", name, misleading, message)
			}
		}
	}
}

// Every site runtime v2 release is delivered as dynamic routing site objects
// (site runtime v9, ADR 0009 §8.3): a node declaring v8 is refused by name,
// with every other old node listed, and the message names dynamic routing.
func TestSiteObjectDeliveryRequiresSiteRuntimeV9AndNamesEveryOldNode(t *testing.T) {
	document := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 5},
	}
	required, err := dynamicRoutingDeliveryCapabilities(document)
	if err != nil || siteRuntimeCapability(required, agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME) != edgeconfig.DynamicRoutingSiteRuntimeVersion ||
		document[1].ApiVersion != 5 {
		t.Fatalf("delivery capabilities = %v (document %v): %v", required, document, err)
	}
	features := func(version uint32) []*agentv1.Capability {
		return append(edge134Features(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: version})
	}
	oldA, oldB, current := uuid.MustParse("00000000-0000-4000-8000-00000000000a"),
		uuid.MustParse("00000000-0000-4000-8000-00000000000b"), uuid.MustParse("00000000-0000-4000-8000-00000000000c")
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		oldA: {AgentVersion: "1.0.35-g8b", Features: features(8)}, oldB: {AgentVersion: "1.0.35-g8b", Features: features(6)},
		current: {AgentVersion: "1.0.35", Features: features(edgeconfig.DynamicRoutingSiteRuntimeVersion)},
	}
	err = capabilityTargetsError([]uuid.UUID{current, oldA, oldB}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != oldA || refusal.Advertised != 8 ||
		refusal.Required != edgeconfig.DynamicRoutingSiteRuntimeVersion || len(refusal.OtherNodeIDs) != 1 ||
		refusal.OtherNodeIDs[0] != oldB || !strings.Contains(err.Error(), "site runtime v9") {
		t.Fatalf("v9 delivery on v8/v6 nodes: %v", err)
	}
	if err := capabilityTargetsError([]uuid.UUID{current}, required, sessions); err != nil {
		t.Fatalf("v9 delivery on a v9 node: %v", err)
	}
	if _, err := dynamicRoutingDeliveryCapabilities([]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}); err == nil {
		t.Fatal("a document without site_runtime got delivery capabilities")
	}
}
