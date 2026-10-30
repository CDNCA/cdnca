package waf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type sec11RequestFixture struct {
	CaseID     string              `json:"case_id"`
	Host       string              `json:"host"`
	Port       uint16              `json:"port"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Header     map[string][]string `json:"header"`
	SourceAddr string              `json:"source_addr"`
	WantAction Action              `json:"want_action"`
	WantReason string              `json:"want_reason"`
	WantRuleID string              `json:"want_rule_id"`
	WantEvents []string            `json:"want_events"`
}

func TestSEC11PortHeaderAndFlowFixtureMatchesProductionEvaluator(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "edge", "openresty", "waf-fixtures")
	raw, err := os.ReadFile(filepath.Join(root, "sec11-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, policy, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(root, "sec11-requests.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var fixture sec11RequestFixture
		if err := json.Unmarshal(scanner.Bytes(), &fixture); err != nil {
			t.Fatal(err)
		}
		t.Run(fixture.CaseID, func(t *testing.T) {
			request := Request{Host: fixture.Host, Port: fixture.Port, Method: fixture.Method, Path: fixture.Path,
				Header: fixture.Header, SourceAddr: netip.MustParseAddr(fixture.SourceAddr)}
			decision := Evaluate(policy, request)
			if decision.Action != fixture.WantAction || decision.Reason != fixture.WantReason || decision.RuleID != fixture.WantRuleID {
				t.Fatalf("decision=%#v", decision)
			}
			events := make([]string, len(decision.Events))
			for index, event := range decision.Events {
				events[index] = event.Reason + ":" + event.RuleID
			}
			if !reflect.DeepEqual(events, fixture.WantEvents) {
				t.Fatalf("events=%v want=%v", events, fixture.WantEvents)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSEC11PortCannotBeReplacedByForwardingHeaders(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 11, Rules: []Rule{{
		RuleID: "listener", Priority: 1, Action: ActionBlock, Flow: FlowStop,
		Match: Match{Port: 8443, Header: &ValueMatch{Name: "X-Mode", Operator: OperatorExact, Value: "strict"}},
	}}})
	request := Request{Host: "sec11.example.test", Port: 443, Method: "GET", Path: "/",
		Header:     map[string][]string{"x-mode": {"strict"}, "host": {"sec11.example.test:8443"}, "x-forwarded-port": {"8443"}},
		SourceAddr: netip.MustParseAddr("192.0.2.10")}
	if decision := Evaluate(policy, request); decision.Action != ActionAllow || decision.Reason != reasonNoMatch {
		t.Fatalf("forged forwarding headers changed listener: %#v", decision)
	}
	request.Port = 8443
	request.Header["x-mode"] = []string{"strict", "relaxed"}
	if decision := Evaluate(policy, request); decision.Action != ActionAllow || decision.Reason != reasonNoMatch {
		t.Fatalf("ambiguous exact header matched: %#v", decision)
	}
}

func TestSEC11IndependentUserAgentMatcherIsBoundedAndUnambiguous(t *testing.T) {
	userAgent := &UserAgentMatch{Operator: OperatorExact, Value: "ExampleBrowser/1.0"}
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 12, Rules: []Rule{
		{RuleID: "ua-log", Priority: 1, Action: ActionLog, Flow: FlowContinue, Match: Match{Port: 8443, UserAgent: userAgent}},
		{RuleID: "ua-block", Priority: 2, Action: ActionBlock, Flow: FlowStop, Match: Match{Port: 8443, UserAgent: userAgent}},
	}})
	request := Request{Host: "sec11.example.test", Port: 8443, Method: "GET", Path: "/",
		Header: map[string][]string{"User-Agent": {"ExampleBrowser/1.0"}}, SourceAddr: netip.MustParseAddr("192.0.2.10")}
	decision := Evaluate(policy, request)
	if decision.Action != ActionBlock || decision.Reason != reasonBlock || decision.RuleID != "ua-block" ||
		len(decision.Events) != 2 || decision.Events[0].Reason != reasonLog || decision.Events[1].Reason != reasonBlock {
		t.Fatalf("user-agent flow decision=%#v", decision)
	}

	for name, headers := range map[string]map[string][]string{
		"multiple values":      {"user-agent": {"ExampleBrowser/1.0", "Other/1.0"}},
		"duplicate case names": {"User-Agent": {"ExampleBrowser/1.0"}, "user-agent": {"ExampleBrowser/1.0"}},
		"spoofed alias":        {"user-agent": {"Other/1.0"}, "x-user-agent": {"ExampleBrowser/1.0"}},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.Header = headers
			if got := Evaluate(policy, candidate); got.Action != ActionAllow || got.Reason != reasonNoMatch || len(got.Events) != 0 {
				t.Fatalf("ambiguous or spoofed UA matched: %#v", got)
			}
		})
	}
	request.Port = 443
	request.Header = map[string][]string{"user-agent": {"ExampleBrowser/1.0"}, "x-forwarded-port": {"8443"}}
	if decision := Evaluate(policy, request); decision.Action != ActionAllow || decision.Reason != reasonNoMatch {
		t.Fatalf("forged forwarding port changed listener: %#v", decision)
	}

	tooLarge := Policy{SchemaVersion: SchemaVersion, PolicyVersion: 13, Rules: []Rule{{
		RuleID: "ua", Priority: 1, Action: ActionBlock, Flow: FlowStop,
		Match: Match{UserAgent: &UserAgentMatch{Operator: OperatorExact, Value: strings.Repeat("a", MaxUserAgentBytes+1)}},
	}}}
	if _, _, err := CompileJSON(marshalPolicy(t, tooLarge)); err == nil {
		t.Fatal("oversized user-agent matcher accepted")
	}

	exists := &UserAgentMatch{Operator: OperatorExists}
	existsPolicy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 14, Rules: []Rule{
		{RuleID: "ua-exists-log", Priority: 1, Action: ActionLog, Flow: FlowContinue, Match: Match{UserAgent: exists}},
		{RuleID: "ua-exists-block", Priority: 2, Action: ActionBlock, Flow: FlowStop, Match: Match{UserAgent: exists}},
	}})
	existsRequest := Request{Host: "sec11.example.test", Port: 8443, Method: "GET", Path: "/",
		Header: map[string][]string{"User-Agent": {"ExampleBrowser/1.0"}}, SourceAddr: netip.MustParseAddr("192.0.2.10")}
	if got := Evaluate(existsPolicy, existsRequest); got.Action != ActionBlock || got.RuleID != "ua-exists-block" ||
		len(got.Events) != 2 || got.Events[0].RuleID != "ua-exists-log" || got.Events[1].RuleID != "ua-exists-block" {
		t.Fatalf("canonical user-agent exists flow decision=%#v", got)
	}
	for name, headers := range map[string]map[string][]string{
		"missing":              {},
		"multiple values":      {"user-agent": {"ExampleBrowser/1.0", "Other/1.0"}},
		"duplicate case names": {"User-Agent": {"ExampleBrowser/1.0"}, "user-agent": {"Other/1.0"}},
		"empty":                {"user-agent": {""}},
		"oversized":            {"user-agent": {strings.Repeat("a", MaxUserAgentBytes+1)}},
		"invalid UTF-8":        {"user-agent": {string([]byte{0xff})}},
	} {
		t.Run("exists "+name, func(t *testing.T) {
			candidate := existsRequest
			candidate.Header = headers
			if got := Evaluate(existsPolicy, candidate); got.Action != ActionAllow || got.Reason != reasonNoMatch || len(got.Events) != 0 {
				t.Fatalf("ambiguous or invalid UA exists matched: %#v", got)
			}
		})
	}

	source, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "lua", "cdnca_waf.lua"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("MAX_USER_AGENT_BYTES"),
		[]byte("user_agent = true"),
		[]byte(`name = "user-agent"`),
	} {
		if !bytes.Contains(source, required) {
			t.Errorf("Lua WAF is missing %q", required)
		}
	}
}
