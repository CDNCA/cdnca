package waf

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestEvaluateUsesOrderedSinglePassControlSemantics(t *testing.T) {
	policy := compileForTest(t, Policy{
		SchemaVersion: SchemaVersion,
		PolicyVersion: 4,
		Rules: []Rule{
			{RuleID: "block-admin", Priority: 1, Action: ActionBlock, Flow: FlowContinue, Match: Match{Path: &PathMatch{Kind: PathPrefix, Value: "/admin"}}},
			{RuleID: "allow-office", Priority: 500, Action: ActionAllow, Flow: FlowContinue, Match: Match{SourceCIDR: "127.0.0.0/8"}},
			{RuleID: "log-admin", Priority: 2, Action: ActionLog, Flow: FlowContinue, Match: Match{Header: &ValueMatch{Name: "X-Audit", Operator: OperatorExact, Value: "yes"}}},
		},
	})
	request := Request{
		Host: "example.test", Port: 8080, Method: "GET", Path: "/admin/panel",
		Header: map[string][]string{"x-audit": {"yes"}}, SourceAddr: netip.MustParseAddr("127.0.0.1"),
	}
	decision := Evaluate(policy, request)
	if decision.Action != ActionAllow || decision.Reason != reasonAllowlistContinue || decision.RuleID != "allow-office" {
		t.Fatalf("decision = %#v", decision)
	}
	wantReasons := []string{reasonBlock, reasonLog, reasonAllowlistContinue}
	if len(decision.Events) != len(wantReasons) {
		t.Fatalf("events = %#v", decision.Events)
	}
	for index, reason := range wantReasons {
		if decision.Events[index].Reason != reason {
			t.Fatalf("events = %#v, index %d want %q", decision.Events, index, reason)
		}
	}
}

func TestEvaluateStopAndContinue(t *testing.T) {
	tests := []struct {
		name   string
		rules  []Rule
		action Action
		reason string
		events int
	}{
		{
			name: "allow stop skips later log",
			rules: []Rule{
				{RuleID: "allow", Priority: 1, Action: ActionAllow, Flow: FlowStop, Match: Match{Method: "GET"}},
				{RuleID: "log", Priority: 2, Action: ActionLog, Flow: FlowContinue, Match: Match{Method: "GET"}},
			},
			action: ActionAllow, reason: reasonAllowlistStop, events: 1,
		},
		{
			name: "later log stop replaces block continue",
			rules: []Rule{
				{RuleID: "block", Priority: 1, Action: ActionBlock, Flow: FlowContinue, Match: Match{Method: "GET"}},
				{RuleID: "log", Priority: 2, Action: ActionLog, Flow: FlowStop, Match: Match{Method: "GET"}},
				{RuleID: "never", Priority: 3, Action: ActionLog, Flow: FlowContinue, Match: Match{Method: "GET"}},
			},
			action: ActionLog, reason: reasonLog, events: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: test.rules})
			decision := Evaluate(policy, Request{Host: "example.test", Port: 80, Method: "GET", Path: "/", SourceAddr: netip.MustParseAddr("192.0.2.1")})
			if decision.Action != test.action || decision.Reason != test.reason || len(decision.Events) != test.events {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestEvaluateAllMatchersAndDuplicateExactValues(t *testing.T) {
	policy := compileForTest(t, Policy{
		SchemaVersion: SchemaVersion, PolicyVersion: 1,
		Rules: []Rule{{
			RuleID: "all", Priority: 1, Action: ActionBlock, Flow: FlowStop,
			Match: Match{
				Host: "example.test", Port: 8443, Method: "POST",
				Path:       &PathMatch{Kind: PathExact, Value: "/submit"},
				Query:      &ValueMatch{Name: "token", Operator: OperatorExact, Value: "ok"},
				Header:     &ValueMatch{Name: "X-Mode", Operator: OperatorExists},
				SourceCIDR: "2001:db8::/32",
			},
		}},
	})
	request := Request{
		Host: "EXAMPLE.TEST.", Port: 8443, Method: "POST", Path: "/submit",
		Query: map[string][]string{"token": {"ok"}}, Header: map[string][]string{"x-mode": {""}},
		SourceAddr: netip.MustParseAddr("2001:db8::5"),
	}
	if decision := Evaluate(policy, request); decision.Action != ActionBlock || decision.RuleID != "all" {
		t.Fatalf("matching decision = %#v", decision)
	}
	request.Query["token"] = []string{"ok", "ok"}
	if decision := Evaluate(policy, request); decision.Action != ActionAllow {
		t.Fatalf("duplicate exact values matched: %#v", decision)
	}
}

func TestEvaluateRejectsInvalidRequestLimits(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 9, Rules: []Rule{}})
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "invalid port", mutate: func(request *Request) { request.Port = 0 }},
		{name: "too many query names", mutate: func(request *Request) {
			request.Query = requestValues(MaxRequestFields+1, 1, "query")
		}},
		{name: "too many query values", mutate: func(request *Request) {
			request.Query = requestValues(MaxRequestFields/2+1, 2, "query")
		}},
		{name: "too many header names", mutate: func(request *Request) {
			request.Header = requestValues(MaxRequestFields+1, 1, "header")
		}},
		{name: "too many header values", mutate: func(request *Request) {
			request.Header = requestValues(MaxRequestFields/2+1, 2, "header")
		}},
		{name: "query name control", mutate: func(request *Request) {
			request.Query = map[string][]string{"bad\nname": {"value"}}
		}},
		{name: "query name over limit", mutate: func(request *Request) {
			request.Query = map[string][]string{strings.Repeat("q", MaxNameBytes+1): {"value"}}
		}},
		{name: "query value control", mutate: func(request *Request) {
			request.Query = map[string][]string{"name": {"bad\nvalue"}}
		}},
		{name: "query value over limit", mutate: func(request *Request) {
			request.Query = map[string][]string{"name": {strings.Repeat("q", 4097)}}
		}},
		{name: "header name token", mutate: func(request *Request) {
			request.Header = map[string][]string{"bad header": {"value"}}
		}},
		{name: "header name control", mutate: func(request *Request) {
			request.Header = map[string][]string{"bad\nheader": {"value"}}
		}},
		{name: "header name over limit", mutate: func(request *Request) {
			request.Header = map[string][]string{strings.Repeat("h", MaxNameBytes+1): {"value"}}
		}},
		{name: "header value control", mutate: func(request *Request) {
			request.Header = map[string][]string{"header": {"bad\nvalue"}}
		}},
		{name: "header value over limit", mutate: func(request *Request) {
			request.Header = map[string][]string{"header": {strings.Repeat("h", 4097)}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequestForTest()
			test.mutate(&request)
			decision := (&Evaluator{}).EvaluateAt(policy, request, fixedEvaluationTime())
			if decision.Action != ActionBlock || decision.Reason != reasonInvalidRequest ||
				decision.RuleID != "" || decision.Version != policy.PolicyVersion {
				t.Fatalf("decision = %#v, want block/request_limit", decision)
			}
		})
	}
}

func TestEvaluateAcceptsRequestLimitsAtBoundary(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 10, Rules: []Rule{}})
	request := validRequestForTest()
	request.Port = 65535
	request.Query = requestValues(MaxRequestFields, 1, "query")
	request.Header = requestValues(MaxRequestFields, 1, "header")
	decision := (&Evaluator{}).EvaluateAt(policy, request, fixedEvaluationTime())
	if decision.Action != ActionAllow || decision.Reason != reasonNoMatch || decision.Version != policy.PolicyVersion {
		t.Fatalf("decision = %#v, want allow/no_match", decision)
	}
}

func validRequestForTest() Request {
	return Request{
		Host: "example.test", Port: 443, Method: "GET", Path: "/",
		SourceAddr: netip.MustParseAddr("192.0.2.1"),
	}
}

func requestValues(names, valuesPerName int, prefix string) map[string][]string {
	values := make(map[string][]string, names)
	for index := 0; index < names; index++ {
		values[fmt.Sprintf("%s-%d", prefix, index)] = make([]string, valuesPerName)
	}
	return values
}

func compileForTest(t *testing.T, policy Policy) *CompiledPolicy {
	t.Helper()
	_, compiled, err := CompileJSON(marshalPolicy(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}
