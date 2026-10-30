package securitypolicy

import (
	"testing"

	"github.com/google/uuid"
)

func TestEvaluateContinueThenStopAndAllowlist(t *testing.T) {
	logID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	blockID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	allowID := uuid.MustParse("018f0000-0000-7000-8000-000000000003")
	policy := Policy{
		ID: uuid.New(), Revision: 7, Enabled: true, DefaultAction: ActionAllow,
		Rules: []Rule{
			{ID: logID, Enabled: true, Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/api"}}}, Action: ActionLog, Flow: FlowContinue},
			{ID: blockID, Enabled: true, Conditions: []Condition{{Field: "country", Operator: "equals", Values: []string{"CN"}}}, Action: ActionBlock, Flow: FlowStop},
			{ID: allowID, Enabled: true, Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.0/8"}}}, Action: ActionAllow, Flow: FlowStop},
		},
	}

	result, err := evaluate(policy, RequestFacts{Path: "/api/v1", Country: "cn", ClientIP: "10.1.2.3"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Action != ActionBlock || result.TerminalRuleID == nil || *result.TerminalRuleID != blockID || result.UsedDefault {
		t.Fatalf("evaluation = %#v", result)
	}
	if len(result.MatchedRuleIDs) != 2 || result.MatchedRuleIDs[0] != logID || result.MatchedRuleIDs[1] != blockID {
		t.Fatalf("matched rules = %v", result.MatchedRuleIDs)
	}

	policy.Rules = policy.Rules[2:]
	policy.DefaultAction = ActionBlock
	result, err = evaluate(policy, RequestFacts{ClientIP: "10.255.255.255"})
	if err != nil {
		t.Fatalf("evaluate allowlist: %v", err)
	}
	if result.Action != ActionAllow || result.TerminalRuleID == nil || *result.TerminalRuleID != allowID {
		t.Fatalf("allowlist evaluation = %#v", result)
	}
}

func TestEvaluateCIDRIPv4IPv6Boundaries(t *testing.T) {
	tests := []struct {
		name  string
		cidr  string
		ip    string
		match bool
	}{
		{name: "IPv4 first", cidr: "192.0.2.0/24", ip: "192.0.2.0", match: true},
		{name: "IPv4 last", cidr: "192.0.2.0/24", ip: "192.0.2.255", match: true},
		{name: "IPv4 outside", cidr: "192.0.2.0/24", ip: "192.0.3.0", match: false},
		{name: "IPv6 first", cidr: "2001:db8::/126", ip: "2001:db8::", match: true},
		{name: "IPv6 last", cidr: "2001:db8::/126", ip: "2001:db8::3", match: true},
		{name: "IPv6 outside", cidr: "2001:db8::/126", ip: "2001:db8::4", match: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matched, err := conditionMatches(Condition{
				Field: "client_ip", Operator: "ip_in_cidr", Values: []string{test.cidr},
			}, RequestFacts{ClientIP: test.ip})
			if err != nil {
				t.Fatalf("conditionMatches: %v", err)
			}
			if matched != test.match {
				t.Fatalf("matched = %v, want %v", matched, test.match)
			}
		})
	}
}

func TestEvaluateUsesDefaultWhenNoRuleMatches(t *testing.T) {
	policy := Policy{
		ID: uuid.New(), Revision: 2, Enabled: true, DefaultAction: ActionBlock,
		Rules: []Rule{{
			ID: uuid.New(), Enabled: true,
			Conditions: []Condition{{Field: "method", Operator: "equals", Values: []string{"POST"}}},
			Action:     ActionAllow, Flow: FlowStop,
		}},
	}
	result, err := evaluate(policy, RequestFacts{Method: "GET"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Action != ActionBlock || !result.UsedDefault || result.TerminalRuleID != nil || len(result.MatchedRuleIDs) != 0 {
		t.Fatalf("evaluation = %#v", result)
	}
}
