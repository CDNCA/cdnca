package cc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCompileJSONCanonicalizesAndSortsPolicy(t *testing.T) {
	policy := validPolicy()
	policy.TrustedProxies = []string{"2001:db8:1::1/48", "10.20.30.40/8"}
	policy.Allowlist = []string{"2001:db8:2::9/64", "192.0.2.99/24"}
	policy.Rules = []Rule{
		validRule("z-rule", 20),
		validRule("b-rule", 10),
		validRule("a-rule", 10),
	}
	policy.Rules[0].Match.Host = "EDGE.EXAMPLE.TEST."
	raw := marshalPolicy(t, policy)

	first, compiled, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || first[len(first)-1] != '\n' {
		t.Fatal("compiler output is not stable canonical JSON")
	}
	if got := fmt.Sprint([]string{compiled.Rules[0].RuleID, compiled.Rules[1].RuleID, compiled.Rules[2].RuleID}); got != "[a-rule b-rule z-rule]" {
		t.Fatalf("rule order = %s", got)
	}
	if compiled.Rules[2].Match.Host != "edge.example.test" {
		t.Fatalf("normalized host = %q", compiled.Rules[2].Match.Host)
	}
	if got := compiled.TrustedProxies[0].prefix().String(); got != "10.0.0.0/8" {
		t.Fatalf("first trusted proxy = %q", got)
	}
	if got := compiled.Allowlist[1].prefix().String(); got != "2001:db8:2::/64" {
		t.Fatalf("IPv6 allowlist = %q", got)
	}
	if strings.Contains(string(first), "CgAAAA==") || !strings.Contains(string(first), `"network":[10,0,0,0]`) {
		t.Fatalf("CIDR network is not a numeric byte array: %s", first)
	}
}

func TestCompileJSONAcceptsAllAlgorithmsDimensionsAndActions(t *testing.T) {
	policy := validPolicy()
	policy.Rules = []Rule{
		validRule("fixed-client", 1),
		{
			RuleID: "leaky-path", Priority: 2, TenantID: "tenant-a", SiteID: "site-a",
			Match: Match{Path: &PathMatch{Kind: PathPrefix, Value: "/api/"}}, Dimension: DimensionPath,
			Limit: Limit{Algorithm: AlgorithmLeakyBucket, RatePerSecond: 10, Burst: 20}, Action: Action{Kind: ActionLog},
		},
		{
			RuleID: "fixed-site", Priority: 3, TenantID: "tenant-a", SiteID: "site-a",
			Match: Match{Method: "POST"}, Dimension: DimensionSite,
			Limit: Limit{Algorithm: AlgorithmFixedWindow, Requests: 100, WindowSeconds: 60}, Action: Action{Kind: ActionReject429},
		},
	}
	policy.Rules[0].Action = Action{Kind: ActionTemporaryBan, BanSeconds: 30}
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); err != nil {
		t.Fatal(err)
	}
}

func TestCompileJSONRejectsInvalidPolicies(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "schema", mutate: func(p *Policy) { p.SchemaVersion = "cdnca.edge.cc/v2" }},
		{name: "zero version", mutate: func(p *Policy) { p.PolicyVersion = 0 }},
		{name: "inexact JSON version", mutate: func(p *Policy) { p.PolicyVersion = MaxPolicyVersion + 1 }},
		{name: "duplicate rule ID", mutate: func(p *Policy) { p.Rules = append(p.Rules, p.Rules[0]) }},
		{name: "control character", mutate: func(p *Policy) { p.Rules[0].TenantID = "tenant\nother" }},
		{name: "long string", mutate: func(p *Policy) { p.Rules[0].SiteID = strings.Repeat("a", MaxIdentifierBytes+1) }},
		{name: "invalid host", mutate: func(p *Policy) { p.Rules[0].Match.Host = "bad:443" }},
		{name: "lowercase method", mutate: func(p *Policy) { p.Rules[0].Match.Method = "get" }},
		{name: "invalid path", mutate: func(p *Policy) { p.Rules[0].Match.Path.Value = "/a/../b" }},
		{name: "invalid proxy CIDR", mutate: func(p *Policy) { p.TrustedProxies = []string{"192.0.2.999/24"} }},
		{name: "mapped IPv6 CIDR", mutate: func(p *Policy) { p.Allowlist = []string{"::ffff:192.0.2.1/128"} }},
		{name: "duplicate canonical CIDR", mutate: func(p *Policy) { p.Allowlist = []string{"10.0.0.1/8", "10.1.2.3/8"} }},
		{name: "dimension", mutate: func(p *Policy) { p.Rules[0].Dimension = "header" }},
		{name: "fixed requests", mutate: func(p *Policy) { p.Rules[0].Limit.Requests = 0 }},
		{name: "fixed window", mutate: func(p *Policy) { p.Rules[0].Limit.WindowSeconds = MaxWindowSeconds + 1 }},
		{name: "mixed fixed fields", mutate: func(p *Policy) { p.Rules[0].Limit.RatePerSecond = 1 }},
		{name: "leaky rate", mutate: func(p *Policy) { p.Rules[0].Limit = Limit{Algorithm: AlgorithmLeakyBucket, Burst: 1} }},
		{name: "leaky burst", mutate: func(p *Policy) { p.Rules[0].Limit = Limit{Algorithm: AlgorithmLeakyBucket, RatePerSecond: 1} }},
		{name: "action", mutate: func(p *Policy) { p.Rules[0].Action.Kind = "challenge" }},
		{name: "ban duration", mutate: func(p *Policy) { p.Rules[0].Action = Action{Kind: ActionTemporaryBan, BanSeconds: MaxBanSeconds + 1} }},
		{name: "ban site", mutate: func(p *Policy) {
			p.Rules[0].Action = Action{Kind: ActionTemporaryBan, BanSeconds: 1}
			p.Rules[0].Dimension = DimensionSite
		}},
		{name: "ban field on reject", mutate: func(p *Policy) { p.Rules[0].Action.BanSeconds = 1 }},
		{name: "too many rules", mutate: func(p *Policy) { p.Rules = make([]Rule, MaxRules+1) }},
		{name: "too many proxies", mutate: func(p *Policy) { p.TrustedProxies = make([]string, MaxProxyCIDRs+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy()
			test.mutate(&policy)
			if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("CompileJSON() error = %v", err)
			}
		})
	}
}

func TestCompileJSONRejectsAmbiguousJSON(t *testing.T) {
	valid := string(marshalPolicy(t, validPolicy()))
	tests := [][]byte{
		[]byte(`{"schema_version":"cdnca.edge.cc/v1","schema_version":"cdnca.edge.cc/v1","policy_version":1,"trusted_proxies":[],"allowlist":[],"rules":[]}`),
		[]byte(strings.Replace(valid, `"rule_id":"rule-a"`, `"rule_id":"rule-a","rule_id":"rule-b"`, 1)),
		[]byte(valid + `{}`),
		[]byte(strings.Replace(valid, `"priority":1`, `"priority":1,"unknown":true`, 1)),
	}
	for _, raw := range tests {
		if _, _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("CompileJSON(%s) error = %v", raw, err)
		}
	}
}

func validPolicy() Policy {
	return Policy{
		SchemaVersion: SchemaVersion, PolicyVersion: 1,
		TrustedProxies: []string{}, Allowlist: []string{}, Rules: []Rule{validRule("rule-a", 1)},
	}
}

func validRule(id string, priority uint32) Rule {
	return Rule{
		RuleID: id, Priority: priority, TenantID: "tenant-a", SiteID: "site-a",
		Match:     Match{Host: "edge.example.test", Port: 18082, Method: "GET", Path: &PathMatch{Kind: PathExact, Value: "/limited"}},
		Dimension: DimensionClientIP,
		Limit:     Limit{Algorithm: AlgorithmFixedWindow, Requests: 2, WindowSeconds: 10},
		Action:    Action{Kind: ActionReject429},
	}
}

func marshalPolicy(t *testing.T, policy Policy) []byte {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
