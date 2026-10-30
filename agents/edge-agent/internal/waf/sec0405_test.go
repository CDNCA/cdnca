package waf

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSEC0405AcceptsCanonicalListMetadata(t *testing.T) {
	raw := []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[{"rule_id":"office","priority":1,"action":"block","flow":"stop","comment":"temporary office deny","expires_at":"2030-01-02T03:04:05Z","match":{"source_cidr":"192.0.2.9/24"}}]}`)
	if _, _, err := CompileJSON(raw); err != nil {
		t.Fatalf("CompileJSON() rejected canonical list metadata: %v", err)
	}
}

func TestSEC0405RejectsInvalidListMetadata(t *testing.T) {
	valid := `{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[{"rule_id":"deny","priority":1,"action":"block","flow":"stop",%s"match":{%s}}]}`
	tests := []struct {
		name     string
		metadata string
		matcher  string
	}{
		{name: "comment without CIDR", metadata: `"comment":"temporary",`, matcher: `"method":"GET"`},
		{name: "expiry without CIDR", metadata: `"expires_at":"2030-01-02T03:04:05Z",`, matcher: `"method":"GET"`},
		{name: "empty comment", metadata: `"comment":"",`, matcher: `"source_cidr":"192.0.2.1/32"`},
		{name: "control in comment", metadata: `"comment":"bad\ncomment",`, matcher: `"source_cidr":"192.0.2.1/32"`},
		{name: "long comment", metadata: `"comment":"` + strings.Repeat("x", MaxCommentBytes+1) + `",`, matcher: `"source_cidr":"192.0.2.1/32"`},
		{name: "offset expiry", metadata: `"expires_at":"2030-01-02T03:04:05+00:00",`, matcher: `"source_cidr":"192.0.2.1/32"`},
		{name: "fractional expiry", metadata: `"expires_at":"2030-01-02T03:04:05.1Z",`, matcher: `"source_cidr":"192.0.2.1/32"`},
		{name: "lowercase expiry", metadata: `"expires_at":"2030-01-02t03:04:05z",`, matcher: `"source_cidr":"192.0.2.1/32"`},
		{name: "pre epoch expiry", metadata: `"expires_at":"1969-12-31T23:59:59Z",`, matcher: `"source_cidr":"192.0.2.1/32"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(valid, test.metadata, test.matcher))
			if _, _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("CompileJSON() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestSEC0405RejectsNonCanonicalCIDRText(t *testing.T) {
	tests := []string{
		"2001:0db8::/32",
		"2001:DB8::/32",
	}
	for _, cidr := range tests {
		t.Run(cidr, func(t *testing.T) {
			raw := []byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[{"rule_id":"deny","priority":1,"action":"block","flow":"stop","match":{"source_cidr":"` + cidr + `"}}]}`)
			if _, _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("CompileJSON() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestSEC0405CIDRBoundariesAndMasking(t *testing.T) {
	tests := []struct {
		name   string
		cidr   string
		inside string
		out    string
		want   *CompiledCIDR
	}{
		{name: "IPv4 slash zero", cidr: "192.0.2.9/0", inside: "203.0.113.8", out: "2001:db8::1", want: &CompiledCIDR{Family: 4, Network: []uint16{0, 0, 0, 0}, PrefixLength: 0}},
		{name: "IPv4 slash 31", cidr: "192.0.2.3/31", inside: "192.0.2.2", out: "192.0.2.4", want: &CompiledCIDR{Family: 4, Network: []uint16{192, 0, 2, 2}, PrefixLength: 31}},
		{name: "IPv4 slash 32", cidr: "192.0.2.9/32", inside: "192.0.2.9", out: "192.0.2.8", want: &CompiledCIDR{Family: 4, Network: []uint16{192, 0, 2, 9}, PrefixLength: 32}},
		{name: "IPv6 slash zero", cidr: "2001:db8::1/0", inside: "fd00::1", out: "192.0.2.1", want: &CompiledCIDR{Family: 6, Network: make([]uint16, 16), PrefixLength: 0}},
		{name: "IPv6 slash 127", cidr: "2001:db8::3/127", inside: "2001:db8::2", out: "2001:db8::4", want: &CompiledCIDR{Family: 6, Network: []uint16{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, PrefixLength: 127}},
		{name: "IPv6 slash 128", cidr: "2001:db8::9/128", inside: "2001:db8::9", out: "2001:db8::8", want: &CompiledCIDR{Family: 6, Network: []uint16{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, PrefixLength: 128}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 9, Rules: []Rule{{
				RuleID: "boundary", Action: ActionBlock, Flow: FlowStop, Match: Match{SourceCIDR: test.cidr},
			}}})
			got := policy.Rules[0].Match.SourceCIDR
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("compiled CIDR = %#v, want %#v", got, test.want)
			}
			inside := Request{Host: "example.test", Port: 80, Method: "GET", Path: "/", SourceAddr: netip.MustParseAddr(test.inside)}
			outside := inside
			outside.SourceAddr = netip.MustParseAddr(test.out)
			if decision := (&Evaluator{}).EvaluateAt(policy, inside, fixedEvaluationTime()); decision.Action != ActionBlock || decision.RuleID != "boundary" || decision.Version != 9 {
				t.Fatalf("inside decision = %#v", decision)
			}
			if decision := (&Evaluator{}).EvaluateAt(policy, outside, fixedEvaluationTime()); decision.Action != ActionAllow {
				t.Fatalf("outside decision = %#v", decision)
			}
		})
	}
}

func TestSEC0405MappedIPv6RequestFailsClosed(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{{
		RuleID: "v4", Action: ActionBlock, Flow: FlowStop, Match: Match{SourceCIDR: "192.0.2.0/24"},
	}}})
	request := testRequest("::ffff:192.0.2.1")
	if decision := (&Evaluator{}).EvaluateAt(policy, request, fixedEvaluationTime()); decision.Action != ActionBlock || decision.Reason != reasonInvalidRequest || decision.RuleID != "" || decision.Version != 1 {
		t.Fatalf("mapped IPv6 request decision = %#v", decision)
	}
}

func TestSEC0405ExpiryIsObservableAndClockRollbackCannotReviveRule(t *testing.T) {
	comment := "temporary deny"
	expiresAt := "2026-01-02T03:04:05Z"
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{{
		RuleID: "temporary", Action: ActionBlock, Flow: FlowStop, Comment: &comment, ExpiresAt: &expiresAt,
		Match: Match{SourceCIDR: "192.0.2.0/24"},
	}}})
	request := testRequest("192.0.2.8")
	expiry := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	evaluator := &Evaluator{}
	if decision := evaluator.EvaluateAt(policy, request, expiry.Add(-time.Second)); decision.Action != ActionBlock || decision.RuleID != "temporary" {
		t.Fatalf("pre-expiry decision = %#v", decision)
	}
	wantExpired := Decision{Action: ActionAllow, Reason: reasonNoMatch, Version: 1, Events: []Event{{Reason: reasonExpiredRule, RuleID: "temporary"}}}
	if decision := evaluator.EvaluateAt(policy, request, expiry); !reflect.DeepEqual(decision, wantExpired) {
		t.Fatalf("at-expiry decision = %#v, want %#v", decision, wantExpired)
	}
	if decision := evaluator.EvaluateAt(policy, request, expiry.Add(-time.Hour)); !reflect.DeepEqual(decision, wantExpired) {
		t.Fatalf("rollback decision = %#v, want %#v", decision, wantExpired)
	}
	policy.PolicyVersion = 2
	if decision := evaluator.EvaluateAt(policy, request, expiry.Add(-2*time.Hour)); decision.Action != ActionAllow || decision.Version != 2 || len(decision.Events) != 1 || decision.Events[0].Reason != reasonExpiredRule {
		t.Fatalf("rollback after policy reload decision = %#v", decision)
	}
}

func TestSEC0405ExpiredAllowDoesNotSuppressBlock(t *testing.T) {
	expiresAt := "2026-01-02T03:04:05Z"
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 3, Rules: []Rule{
		{RuleID: "expired-allow", Priority: 1, Action: ActionAllow, Flow: FlowContinue, ExpiresAt: &expiresAt, Match: Match{SourceCIDR: "192.0.2.0/24"}},
		{RuleID: "active-block", Priority: 2, Action: ActionBlock, Flow: FlowStop, Match: Match{SourceCIDR: "192.0.2.0/24"}},
	}})
	decision := (&Evaluator{}).EvaluateAt(policy, testRequest("192.0.2.8"), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	wantEvents := []Event{{Reason: reasonExpiredRule, RuleID: "expired-allow"}, {Reason: reasonBlock, RuleID: "active-block"}}
	if decision.Action != ActionBlock || decision.Reason != reasonBlock || decision.RuleID != "active-block" || decision.Version != 3 || !reflect.DeepEqual(decision.Events, wantEvents) {
		t.Fatalf("decision = %#v, events want %#v", decision, wantEvents)
	}
}

func TestSEC0405OrderedEventsRemainDeterministic(t *testing.T) {
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 8, Rules: []Rule{
		{RuleID: "allow", Priority: 100, Action: ActionAllow, Flow: FlowContinue, Match: Match{SourceCIDR: "192.0.2.0/24"}},
		{RuleID: "a-log", Priority: 1, Action: ActionLog, Flow: FlowContinue, Match: Match{Method: "GET"}},
		{RuleID: "b-block", Priority: 2, Action: ActionBlock, Flow: FlowContinue, Match: Match{Path: &PathMatch{Kind: PathExact, Value: "/"}}},
		{RuleID: "c-log-stop", Priority: 3, Action: ActionLog, Flow: FlowStop, Match: Match{Method: "GET"}},
		{RuleID: "d-never", Priority: 4, Action: ActionLog, Flow: FlowContinue, Match: Match{Method: "GET"}},
	}})
	decision := (&Evaluator{}).EvaluateAt(policy, testRequest("192.0.2.8"), fixedEvaluationTime())
	want := []Event{
		{Reason: reasonLog, RuleID: "a-log"},
		{Reason: reasonBlock, RuleID: "b-block"},
		{Reason: reasonLog, RuleID: "c-log-stop"},
	}
	if decision.Action != ActionLog || decision.Reason != reasonLog || decision.RuleID != "c-log-stop" || decision.Version != 8 || !reflect.DeepEqual(decision.Events, want) {
		t.Fatalf("decision = %#v, want events %#v", decision, want)
	}
}

func TestSEC0405LuaEvaluatorUsesTheSameSinglePassShape(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "lua", "cdnca_waf.lua"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{"local allowlisted = false", "local pending_block = nil", "allowlist_suppressed_block"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Lua evaluator still contains allow-first state %q", forbidden)
		}
	}
	for _, required := range []string{"local action = \"allow\"", "action = rule.action", "if rule.flow == \"stop\" then"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Lua evaluator missing ordered single-pass marker %q", required)
		}
	}
}

func TestSEC0405ClockHighWaterIsConcurrent(t *testing.T) {
	expiresAt := "2026-01-02T03:04:05Z"
	policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{{
		RuleID: "temporary", Action: ActionBlock, Flow: FlowStop, ExpiresAt: &expiresAt, Match: Match{SourceCIDR: "192.0.2.0/24"},
	}}})
	evaluator := &Evaluator{}
	request := testRequest("192.0.2.8")
	expiry := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if decision := evaluator.EvaluateAt(policy, request, expiry); decision.Action != ActionAllow {
		t.Fatalf("expiry decision = %#v", decision)
	}
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			now := expiry.Add(time.Duration(index-8) * time.Hour)
			if decision := evaluator.EvaluateAt(policy, request, now); decision.Action != ActionAllow {
				t.Errorf("concurrent rollback decision = %#v", decision)
			}
		}(index)
	}
	wait.Wait()
}

func TestSEC0405MalformedCompiledCIDRFailsClosedWithoutPanic(t *testing.T) {
	policy := &CompiledPolicy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []CompiledRule{{
		RuleID: "broken", Action: ActionBlock, Flow: FlowStop,
		Match: CompiledMatch{SourceCIDR: &CompiledCIDR{Family: 4, Network: []uint16{192}, PrefixLength: 32}},
	}}}
	if decision := (&Evaluator{}).EvaluateAt(policy, testRequest("192.0.2.8"), fixedEvaluationTime()); decision.Action != ActionBlock || decision.Reason != reasonInvalidPolicy || decision.Version != 1 {
		t.Fatalf("malformed compiled CIDR decision = %#v", decision)
	}
}

func fixedEvaluationTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func testRequest(source string) Request {
	return Request{Host: "example.test", Port: 80, Method: "GET", Path: "/", SourceAddr: netip.MustParseAddr(source)}
}
