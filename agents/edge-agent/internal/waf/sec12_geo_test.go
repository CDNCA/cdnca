package waf

import (
	"net/netip"
	"testing"
)

func TestSEC12CountryMatchUsesSignedGeoRangesAndUnknownFailsSafe(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 12,
		Geo: []GeoRange{{CIDR: "198.51.100.0/24", Country: "CN"}, {CIDR: "2001:db8:1::/48", Country: "US"}},
		Rules: []Rule{
			{RuleID: "trusted", Priority: 1, Action: ActionAllow, Flow: FlowStop, Match: Match{SourceCIDR: "198.51.100.8/32"}},
			{RuleID: "block-cn", Priority: 2, Action: ActionBlock, Flow: FlowStop,
				Match: Match{Country: &CountryMatch{Operator: CountryIn, Values: []string{"CN"}}}},
		}})
	request := validRequestForTest()
	request.SourceAddr = netip.MustParseAddr("198.51.100.9")
	request.Header = map[string][]string{"x-forwarded-for": {"203.0.113.7"}}
	if decision := Evaluate(policy, request); decision.Action != ActionBlock || decision.RuleID != "block-cn" {
		t.Fatalf("country decision = %+v", decision)
	}
	request.SourceAddr = netip.MustParseAddr("198.51.100.8")
	if decision := Evaluate(policy, request); decision.Action != ActionAllow || decision.RuleID != "trusted" {
		t.Fatalf("trusted recovery decision = %+v", decision)
	}
	request.SourceAddr = netip.MustParseAddr("203.0.113.7")
	if decision := Evaluate(policy, request); decision.Action != ActionAllow || decision.RuleID != "" {
		t.Fatalf("unknown country must not match negated or positive region rule: %+v", decision)
	}
}

func TestSEC12RejectsAmbiguousOrUnboundGeoPolicy(t *testing.T) {
	base := Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{{RuleID: "country", Action: ActionBlock, Flow: FlowStop,
		Match: Match{Country: &CountryMatch{Operator: CountryNotIn, Values: []string{"CN"}}}}}}
	if _, _, err := CompileJSON(marshalPolicy(t, base)); err == nil {
		t.Fatal("country matcher without an authoritative geo table accepted")
	}
	base.Geo = []GeoRange{{CIDR: "198.51.100.0/24", Country: "CN"}, {CIDR: "198.51.100.128/25", Country: "US"}}
	if _, _, err := CompileJSON(marshalPolicy(t, base)); err == nil {
		t.Fatal("overlapping country ranges accepted")
	}
}
