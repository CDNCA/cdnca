package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCompileJSONIsCanonicalAndStable(t *testing.T) {
	raw := marshalPolicy(t, Policy{
		SchemaVersion: SchemaVersion,
		PolicyVersion: 7,
		Rules: []Rule{
			{RuleID: "z-rule", Priority: 20, Action: ActionBlock, Flow: FlowStop, Match: Match{SourceCIDR: "10.20.30.40/8"}},
			{RuleID: "b-rule", Priority: 10, Action: ActionLog, Flow: FlowContinue, Match: Match{Header: &ValueMatch{Name: "X-Trace", Operator: OperatorExists}}},
			{RuleID: "a-rule", Priority: 10, Action: ActionAllow, Flow: FlowStop, Match: Match{Host: "EXAMPLE.TEST."}},
		},
	})
	first, compiled, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("identical input did not produce identical canonical JSON")
	}
	if got := []string{compiled.Rules[0].RuleID, compiled.Rules[1].RuleID, compiled.Rules[2].RuleID}; fmt.Sprint(got) != "[a-rule b-rule z-rule]" {
		t.Fatalf("rule order = %v", got)
	}
	if compiled.Rules[0].Match.Host != "example.test" || compiled.Rules[1].Match.Header.Name != "x-trace" {
		t.Fatalf("normalization missing: %#v", compiled.Rules)
	}
	wantCIDR := &CompiledCIDR{Family: 4, Network: []uint16{10, 0, 0, 0}, PrefixLength: 8}
	if fmt.Sprint(compiled.Rules[2].Match.SourceCIDR) != fmt.Sprint(wantCIDR) {
		t.Fatalf("compiled CIDR = %#v, want %#v", compiled.Rules[2].Match.SourceCIDR, wantCIDR)
	}
	if first[len(first)-1] != '\n' {
		t.Fatal("canonical JSON has no final newline")
	}
}

func TestCompileJSONRejectsInvalidPolicies(t *testing.T) {
	validRule := Rule{RuleID: "rule-1", Priority: 1, Action: ActionBlock, Flow: FlowStop, Match: Match{Path: &PathMatch{Kind: PathExact, Value: "/admin"}}}
	tests := []struct {
		name string
		raw  func(*testing.T) []byte
	}{
		{name: "unknown schema", raw: func(t *testing.T) []byte {
			return marshalPolicy(t, Policy{SchemaVersion: "v2", PolicyVersion: 1, Rules: []Rule{validRule}})
		}},
		{name: "zero version", raw: func(t *testing.T) []byte {
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, Rules: []Rule{validRule}})
		}},
		{name: "version exceeds Lua integer limit", raw: func(t *testing.T) []byte {
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: MaxPolicyVersion + 1, Rules: []Rule{validRule}})
		}},
		{name: "duplicate ID", raw: func(t *testing.T) []byte {
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{validRule, validRule}})
		}},
		{name: "invalid CIDR", raw: func(t *testing.T) []byte {
			rule := validRule
			rule.Match = Match{SourceCIDR: "10.0.0.999/24"}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
		}},
		{name: "mapped CIDR", raw: func(t *testing.T) []byte {
			rule := validRule
			rule.Match = Match{SourceCIDR: "::ffff:192.0.2.1/128"}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
		}},
		{name: "invalid header", raw: func(t *testing.T) []byte {
			rule := validRule
			rule.Match = Match{Header: &ValueMatch{Name: "bad header", Operator: OperatorExists}}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
		}},
		{name: "path traversal", raw: func(t *testing.T) []byte {
			rule := validRule
			rule.Match = Match{Path: &PathMatch{Kind: PathExact, Value: "/safe/../secret"}}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
		}},
		{name: "path control", raw: func(t *testing.T) []byte {
			rule := validRule
			rule.Match = Match{Path: &PathMatch{Kind: PathExact, Value: "/safe\nsecret"}}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
		}},
		{name: "empty match", raw: func(t *testing.T) []byte {
			rule := validRule
			rule.Match = Match{}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
		}},
		{name: "long string", raw: func(t *testing.T) []byte {
			rule := validRule
			rule.Match = Match{Query: &ValueMatch{Name: "key", Operator: OperatorExact, Value: strings.Repeat("x", MaxValueBytes+1)}}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
		}},
		{name: "too many rules", raw: func(t *testing.T) []byte {
			rules := make([]Rule, MaxRules+1)
			for index := range rules {
				rules[index] = validRule
				rules[index].RuleID = fmt.Sprintf("rule-%d", index)
			}
			return marshalPolicy(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: rules})
		}},
		{name: "unknown field", raw: func(*testing.T) []byte {
			return []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"unexpected":true,"rules":[]}`)
		}},
		{name: "duplicate JSON key", raw: func(*testing.T) []byte {
			return []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"policy_version":2,"rules":[]}`)
		}},
		{name: "invalid UTF-8", raw: func(*testing.T) []byte {
			return append([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[],"`), 0xff, '"', ':', '0', '}')
		}},
		{name: "unpaired high surrogate", raw: func(*testing.T) []byte {
			return []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[],"\ud800":"value"}`)
		}},
		{name: "unpaired low surrogate", raw: func(*testing.T) []byte {
			return []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[],"\udc00":"value"}`)
		}},
		{name: "high surrogate followed by non-low surrogate", raw: func(*testing.T) []byte {
			return []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[],"\ud800\u0041":"value"}`)
		}},
		{name: "multiple values", raw: func(*testing.T) []byte {
			return []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[]} {}`)
		}},
		{name: "oversized input", raw: func(*testing.T) []byte {
			return []byte(strings.Repeat(" ", MaxPolicyBytes+1))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := CompileJSON(test.raw(t)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("CompileJSON() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestCompileJSONRequiresRulesArray(t *testing.T) {
	invalid := [][]byte{
		[]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":null}`),
		[]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1}`),
	}
	for _, raw := range invalid {
		if _, _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("CompileJSON(%s) error = %v, want ErrInvalidPolicy", raw, err)
		}
	}
	if _, compiled, err := CompileJSON([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[]}`)); err != nil {
		t.Fatalf("CompileJSON(rules:[]) error = %v", err)
	} else if compiled.Rules == nil || len(compiled.Rules) != 0 {
		t.Fatalf("compiled rules = %#v, want non-nil empty array", compiled.Rules)
	}
}

func TestCompileJSONSupportsIPv6AndEmptyExactValue(t *testing.T) {
	raw := marshalPolicy(t, Policy{
		SchemaVersion: SchemaVersion,
		PolicyVersion: 1,
		Rules: []Rule{{
			RuleID: "ipv6", Action: ActionBlock, Flow: FlowContinue,
			Match: Match{SourceCIDR: "2001:db8::1234/64", Query: &ValueMatch{Name: "empty", Operator: OperatorExact}},
		}},
	})
	_, compiled, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	cidr := compiled.Rules[0].Match.SourceCIDR
	if cidr.Family != 6 || cidr.PrefixLength != 64 || len(cidr.Network) != 16 {
		t.Fatalf("compiled IPv6 CIDR = %#v", cidr)
	}
}

func TestCompileJSONAcceptsPairedUTF16Surrogates(t *testing.T) {
	raw := []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[{"rule_id":"unicode","priority":1,"action":"log","flow":"stop","comment":"emoji \ud83d\ude00","match":{"source_cidr":"192.0.2.1/32"}}]}`)
	if _, compiled, err := CompileJSON(raw); err != nil {
		t.Fatal(err)
	} else if compiled.Rules[0].Comment != "emoji \U0001f600" {
		t.Fatalf("comment = %q", compiled.Rules[0].Comment)
	}
}

func TestRejectInvalidJSONUnicodeEscapeBoundaries(t *testing.T) {
	valid := [][]byte{
		[]byte(`"\ud83d\ude00"`),
		[]byte(`"\\ud800"`),
		[]byte(`"before \ud83d\ude00 after"`),
	}
	for _, raw := range valid {
		if err := rejectInvalidJSONUnicode(raw); err != nil {
			t.Errorf("rejectInvalidJSONUnicode(%q) error = %v", raw, err)
		}
	}

	invalid := [][]byte{
		[]byte(`"\u"`),
		[]byte(`"\ud80"`),
		[]byte(`"\ud80x"`),
		[]byte(`"\ud800"`),
		[]byte(`"\ud800\u0041"`),
		[]byte(`"\ud800\ud800"`),
		[]byte(`"\udc00"`),
		[]byte(`"\ud83d\ude00\udc00"`),
	}
	for _, raw := range invalid {
		if err := rejectInvalidJSONUnicode(raw); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("rejectInvalidJSONUnicode(%q) error = %v, want ErrInvalidPolicy", raw, err)
		}
	}
}

func marshalPolicy(t *testing.T, policy Policy) []byte {
	t.Helper()
	value, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
