package waf

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestSEC12V2SchemaNegotiationAndClientSourceValidation(t *testing.T) {
	v1 := Policy{SchemaVersion: SchemaVersionV1, PolicyVersion: 1, Rules: []Rule{}}
	if _, _, err := CompileJSON(marshalPolicy(t, v1)); err != nil {
		t.Fatalf("v1 compatibility: %v", err)
	}
	v2 := sec12V2Policy()
	if _, compiled, err := CompileJSON(marshalPolicy(t, v2)); err != nil {
		t.Fatalf("v2 compile: %v", err)
	} else if compiled.SchemaVersion != SchemaVersionV2 || compiled.ClientSource == nil || len(compiled.TrustedCrawlers) != 1 {
		t.Fatalf("compiled v2 = %#v", compiled)
	}
	v2.SchemaVersion = "cdnca.edge.waf/v3"
	if _, _, err := CompileJSON(marshalPolicy(t, v2)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown schema error = %v", err)
	}
	v2 = sec12V2Policy()
	v2.SchemaVersion = SchemaVersionV1
	if _, _, err := CompileJSON(marshalPolicy(t, v2)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("v1 accepted v2 fields: %v", err)
	}

	for name, mutate := range map[string]func(*Policy){
		"all-address proxy": func(policy *Policy) { policy.ClientSource.TrustedProxyCIDRs = []string{"0.0.0.0/0"} },
		"unmasked proxy":    func(policy *Policy) { policy.ClientSource.TrustedProxyCIDRs = []string{"203.0.113.7/24"} },
		"mapped proxy":      func(policy *Policy) { policy.ClientSource.TrustedProxyCIDRs = []string{"::ffff:203.0.113.7/128"} },
		"overlapping proxy": func(policy *Policy) {
			policy.ClientSource.TrustedProxyCIDRs = []string{"203.0.113.0/24", "203.0.113.0/25"}
		},
		"unsafe crawler":             func(policy *Policy) { policy.TrustedCrawlers[0].Networks = []string{"::/0"} },
		"missing crawler UA":         func(policy *Policy) { policy.TrustedCrawlers[0].UserAgentPrefixes = nil },
		"missing unknown geo action": func(policy *Policy) { policy.UnknownGeoAction = "" },
		"invalid unknown geo action": func(policy *Policy) { policy.UnknownGeoAction = "challenge" },
	} {
		t.Run(name, func(t *testing.T) {
			policy := sec12V2Policy()
			mutate(&policy)
			if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestSEC12V2TrustedProxyResolvesSourceWithoutBypass(t *testing.T) {
	policy := compileForTest(t, sec12V2Policy())
	request := sec12ProxyRequest("198.51.100.20", "OrdinaryBrowser/1", "/")
	decision := Evaluate(policy, request)
	if decision.Action != ActionBlock || decision.RuleID != "geo-cn" || decision.Reason != reasonBlock {
		t.Fatalf("proxy address bypassed resolved-client geo block: %#v", decision)
	}

	request.Header["x-forwarded-for"] = []string{"198.51.100.20, 203.0.113.9"}
	if decision := Evaluate(policy, request); decision.Action != ActionBlock || decision.RuleID != "geo-cn" {
		t.Fatalf("trusted multi-hop resolution = %#v", decision)
	}

	request.Header["x-forwarded-for"] = []string{"192.0.2.20"}
	if decision := Evaluate(policy, request); decision.Action != ActionAllow {
		t.Fatalf("non-blocked resolved country = %#v", decision)
	}
}

func TestSEC12V2RejectsSpoofedMalformedAndAmbiguousSourceChains(t *testing.T) {
	policy := compileForTest(t, sec12V2Policy())
	base := sec12ProxyRequest("198.51.100.20", "OrdinaryBrowser/1", "/")
	tests := map[string]func(*Request){
		"untrusted peer spoof":   func(request *Request) { request.SourceAddr = netip.MustParseAddr("192.0.2.10") },
		"multiple header fields": func(request *Request) { request.Header["x-forwarded-for"] = []string{"198.51.100.20", "192.0.2.20"} },
		"malformed address":      func(request *Request) { request.Header["x-forwarded-for"] = []string{"not-an-address"} },
		"ambiguous all proxies":  func(request *Request) { request.Header["x-forwarded-for"] = []string{"203.0.113.8, 203.0.113.9"} },
		"too many hops": func(request *Request) {
			request.Header["x-forwarded-for"] = []string{"198.51.100.20, 203.0.113.8, 203.0.113.9, 203.0.113.10"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := base
			request.Header = cloneRequestValues(base.Header)
			mutate(&request)
			decision := Evaluate(policy, request)
			if decision.Action != ActionBlock || decision.Reason != reasonClientSourceInvalid {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestSEC12V2CrawlerDualEvidenceSkipsOnlyGeoAndContinuesWAF(t *testing.T) {
	policy := compileForTest(t, sec12V2Policy())
	request := sec12ProxyRequest("198.51.100.20", "ExampleBot/2.1", "/")
	decision := Evaluate(policy, request)
	if decision.Action != ActionAllow || decision.Reason != reasonNoMatch || len(decision.Events) != 1 || decision.Events[0].Reason != reasonCrawlerGeoBypass {
		t.Fatalf("crawler geo-only bypass = %#v", decision)
	}

	request.Path = "/admin"
	decision = Evaluate(policy, request)
	if decision.Action != ActionBlock || decision.RuleID != "later-waf" || len(decision.Events) != 2 ||
		decision.Events[0].Reason != reasonCrawlerGeoBypass || decision.Events[1].Reason != reasonBlock {
		t.Fatalf("crawler skipped later WAF: %#v", decision)
	}

	request = sec12ProxyRequest("198.51.100.20", "ExampleBot-Evil/1", "/")
	if decision := Evaluate(policy, request); decision.Action != ActionBlock || decision.RuleID != "geo-cn" {
		t.Fatalf("UA without required prefix bypassed geo: %#v", decision)
	}
	request = sec12ProxyRequest("192.0.2.20", "ExampleBot/2.1", "/")
	if decision := Evaluate(policy, request); len(decision.Events) != 0 {
		t.Fatalf("UA without crawler CIDR produced bypass: %#v", decision)
	}
}

func TestSEC12V2UnknownGeoDefaultsSafe(t *testing.T) {
	policy := sec12V2Policy()
	policy.Rules[0].Match.Country.Operator = CountryNotIn
	compiled := compileForTest(t, policy)
	request := sec12ProxyRequest("203.0.114.20", "OrdinaryBrowser/1", "/")
	if decision := Evaluate(compiled, request); decision.Action != ActionAllow || decision.Reason != reasonUnknownGeoAllow ||
		len(decision.Events) != 1 || decision.Events[0].Reason != reasonUnknownGeoAllow {
		t.Fatalf("unknown geo was blocked: %#v", decision)
	}
	request.Path = "/admin"
	if decision := Evaluate(compiled, request); decision.Action != ActionBlock || decision.Reason != reasonBlock ||
		len(decision.Events) != 2 || decision.Events[0].Reason != reasonUnknownGeoAllow {
		t.Fatalf("unknown geo allow skipped later WAF: %#v", decision)
	}

	policy.UnknownGeoAction = GeoUnknownBlock
	compiled = compileForTest(t, policy)
	request.Path = "/"
	if decision := Evaluate(compiled, request); decision.Action != ActionBlock || decision.Reason != reasonUnknownGeoBlock ||
		len(decision.Events) != 1 || decision.Events[0].Reason != reasonUnknownGeoBlock {
		t.Fatalf("unknown geo block decision: %#v", decision)
	}
}

func TestSEC12V2BadCandidatePreservesPublisherCurrentAndLKG(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.PublishJSON(policyWithVersion(t, 1, "/v1"))
	if err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.ReadFile(first.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}
	validV2 := sec12V2Policy()
	validV2.PolicyVersion = 2
	second, err := publisher.PublishJSON(marshalPolicy(t, validV2))
	if err != nil {
		t.Fatalf("publish valid v2: %v", err)
	}
	currentV2, err := os.ReadFile(second.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}
	fallbackV1, err := os.ReadFile(filepath.Join(root, "fallback.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(currentBefore, currentV2) || !bytes.Equal(currentBefore, fallbackV1) {
		t.Fatal("v2 promotion did not preserve v1 as LKG")
	}
	bad := sec12V2Policy()
	bad.PolicyVersion = 3
	bad.UnknownGeoAction = "challenge"
	if _, err := publisher.PublishJSON(marshalPolicy(t, bad)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("bad v2 candidate error = %v", err)
	}
	currentAfter, _ := os.ReadFile(second.CurrentPath)
	fallbackAfter, _ := os.ReadFile(filepath.Join(root, "fallback.json"))
	if !bytes.Equal(currentV2, currentAfter) || !bytes.Equal(fallbackV1, fallbackAfter) {
		t.Fatal("bad v2 candidate changed active or LKG")
	}
	if _, err := os.Stat(filepath.Join(root, "versions", versionFilename(3))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bad v2 candidate created immutable version: %v", err)
	}
}

func TestSEC12V2OpenRestyStaticContract(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "lua", "cdnca_waf.lua"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`local SCHEMA_VERSION_V2 = "cdnca.edge.waf/v2"`),
		[]byte("local function resolve_client_source(policy, request)"),
		[]byte("local function trusted_crawler(policy, request)"),
		[]byte("unknown_geo_action"),
		[]byte(`"unknown_geo_allow"`),
		[]byte(`"unknown_geo_block"`),
		[]byte(`emit("crawler_geo_bypass"`),
		[]byte("rule.match.country and crawler"),
	} {
		if !bytes.Contains(source, required) {
			t.Errorf("Lua WAF is missing %q", required)
		}
	}
	if bytes.Contains(source, []byte("trusted_proxy_allow")) {
		t.Fatal("Lua WAF contains a trusted-proxy bypass")
	}
}

func sec12V2Policy() Policy {
	return Policy{
		SchemaVersion: SchemaVersionV2, PolicyVersion: 2,
		UnknownGeoAction: GeoUnknownAllow,
		ClientSource:     &ClientSourcePolicy{Header: "x-forwarded-for", MaxHops: 3, TrustedProxyCIDRs: []string{"203.0.113.0/24"}},
		TrustedCrawlers:  []TrustedCrawler{{Networks: []string{"198.51.100.0/24"}, UserAgentPrefixes: []string{"ExampleBot/"}}},
		Geo:              []GeoRange{{CIDR: "198.51.100.0/24", Country: "CN"}, {CIDR: "192.0.2.0/24", Country: "US"}},
		Rules: []Rule{
			{RuleID: "geo-cn", Priority: 1, Action: ActionBlock, Flow: FlowStop, Match: Match{Country: &CountryMatch{Operator: CountryIn, Values: []string{"CN"}}}},
			{RuleID: "later-waf", Priority: 2, Action: ActionBlock, Flow: FlowStop, Match: Match{Path: &PathMatch{Kind: PathExact, Value: "/admin"}}},
		},
	}
}

func sec12ProxyRequest(client, userAgent, path string) Request {
	return Request{
		Host: "example.test", Port: 443, Method: "GET", Path: path,
		Header:     map[string][]string{"x-forwarded-for": {client}, "user-agent": {userAgent}},
		SourceAddr: netip.MustParseAddr("203.0.113.10"),
	}
}

func cloneRequestValues(input map[string][]string) map[string][]string {
	result := make(map[string][]string, len(input))
	for key, values := range input {
		result[key] = append([]string(nil), values...)
	}
	return result
}
