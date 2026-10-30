package waf

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

type preindexedEvaluator struct {
	clock     Evaluator
	policy    *CompiledPolicy
	rulesIPv4 []*CompiledRule
	rulesIPv6 []*CompiledRule
}

func newPreindexedEvaluator(policy *CompiledPolicy) *preindexedEvaluator {
	indexed := &preindexedEvaluator{policy: policy}
	if policy == nil || !policy.valid {
		return indexed
	}
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		indexed.rulesIPv4, indexed.rulesIPv6 = appendByFamily(indexed.rulesIPv4, indexed.rulesIPv6, rule)
	}
	return indexed
}

func appendByFamily(ipv4, ipv6 []*CompiledRule, rule *CompiledRule) ([]*CompiledRule, []*CompiledRule) {
	if rule.Match.SourceCIDR == nil {
		return append(ipv4, rule), append(ipv6, rule)
	}
	if rule.Match.SourceCIDR.Family == 4 {
		return append(ipv4, rule), ipv6
	}
	return ipv4, append(ipv6, rule)
}

func (indexed *preindexedEvaluator) evaluateAt(request Request, now time.Time) Decision {
	decision := Decision{Action: ActionAllow, Reason: reasonNoMatch}
	if indexed == nil || indexed.policy == nil {
		return Decision{Action: ActionBlock, Reason: reasonInvalidRequest}
	}
	decision.Version = indexed.policy.PolicyVersion
	if !indexed.policy.valid {
		decision.Action = ActionBlock
		decision.Reason = reasonInvalidPolicy
		return decision
	}
	if !validRequest(request) {
		decision.Action = ActionBlock
		decision.Reason = reasonInvalidRequest
		return decision
	}
	effectiveNow, ok := indexed.clock.observe(now)
	if !ok {
		decision.Action = ActionBlock
		decision.Reason = reasonInvalidRequest
		return decision
	}
	rules := indexed.rulesIPv6
	if request.SourceAddr.Is4() {
		rules = indexed.rulesIPv4
	}
	for _, rule := range rules {
		if !matches(rule.Match, request) {
			continue
		}
		if expired(*rule, effectiveNow) {
			decision.Events = append(decision.Events, Event{Reason: reasonExpiredRule, RuleID: rule.RuleID})
			continue
		}
		switch rule.Action {
		case ActionAllow:
			decision.Action = ActionAllow
			decision.Reason = reasonAllowlistContinue
			if rule.Flow == FlowStop {
				decision.Reason = reasonAllowlistStop
			}
		case ActionLog:
			decision.Action = ActionLog
			decision.Reason = reasonLog
		case ActionBlock:
			decision.Action = ActionBlock
			decision.Reason = reasonBlock
		}
		decision.RuleID = rule.RuleID
		decision.Events = append(decision.Events, Event{Reason: decision.Reason, RuleID: rule.RuleID})
		if rule.Flow == FlowStop {
			break
		}
	}
	return decision
}

func TestPreindexedEvaluatorMatchesLinear(t *testing.T) {
	random := rand.New(rand.NewSource(40405))
	now := fixedEvaluationTime()
	for iteration := 0; iteration < 200; iteration++ {
		rules := make([]Rule, 1+random.Intn(64))
		for index := range rules {
			actions := [...]Action{ActionAllow, ActionLog, ActionBlock}
			flows := [...]Flow{FlowContinue, FlowStop}
			rule := Rule{
				RuleID: fmt.Sprintf("rule-%03d", index), Priority: uint32(index),
				Action: actions[random.Intn(len(actions))], Flow: flows[random.Intn(len(flows))],
				Match: Match{Method: [...]string{"GET", "POST"}[random.Intn(2)]},
			}
			switch random.Intn(3) {
			case 0:
				rule.Match.SourceCIDR = fmt.Sprintf("192.0.%d.9/24", index%8)
			case 1:
				rule.Match.SourceCIDR = ipv6BenchmarkCIDR(index % 8)
			}
			if rule.Match.SourceCIDR != "" && random.Intn(8) == 0 {
				expiry := "2025-12-31T23:59:59Z"
				rule.ExpiresAt = &expiry
			}
			rules[index] = rule
		}
		policy := compileForTest(t, Policy{SchemaVersion: SchemaVersion, PolicyVersion: uint64(iteration + 1), Rules: rules})
		indexed := newPreindexedEvaluator(policy)
		for requestIndex := 0; requestIndex < 12; requestIndex++ {
			source := fmt.Sprintf("192.0.%d.%d", random.Intn(8), 1+random.Intn(250))
			if requestIndex%2 == 1 {
				source = fmt.Sprintf("2001:db8:%x::%x", random.Intn(8), 1+random.Intn(250))
			}
			request := testRequest(source)
			request.Method = [...]string{"GET", "POST"}[random.Intn(2)]
			linear := (&Evaluator{}).EvaluateAt(policy, request, now)
			candidate := indexed.evaluateAt(request, now)
			if !reflect.DeepEqual(linear, candidate) {
				t.Fatalf("iteration %d request %d: linear=%#v candidate=%#v", iteration, requestIndex, linear, candidate)
			}
		}
	}
}

func BenchmarkEvaluators(b *testing.B) {
	for _, fixture := range benchmarkFixtures(b) {
		b.Run(fixture.name, func(b *testing.B) {
			b.Run("linear", func(b *testing.B) {
				evaluator := &Evaluator{}
				b.ReportAllocs()
				b.ResetTimer()
				for index := 0; index < b.N; index++ {
					benchmarkDecision = evaluator.EvaluateAt(fixture.policy, fixture.request, fixture.now)
				}
			})
			b.Run("preindexed", func(b *testing.B) {
				evaluator := newPreindexedEvaluator(fixture.policy)
				b.ReportAllocs()
				b.ResetTimer()
				for index := 0; index < b.N; index++ {
					benchmarkDecision = evaluator.evaluateAt(fixture.request, fixture.now)
				}
			})
		})
	}
}

func BenchmarkPreindexedBuild512(b *testing.B) {
	fixture := makeBenchmarkFixture(b, "build", 512, "multi-cidr")
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		benchmarkIndex = newPreindexedEvaluator(fixture.policy)
	}
}

type benchmarkFixture struct {
	name    string
	policy  *CompiledPolicy
	request Request
	now     time.Time
}

var (
	benchmarkDecision Decision
	benchmarkIndex    *preindexedEvaluator
)

func benchmarkFixtures(tb testing.TB) []benchmarkFixture {
	return []benchmarkFixture{
		makeBenchmarkFixture(tb, "steady_late_match_128", 128, "steady"),
		makeBenchmarkFixture(tb, "worst_miss_512", 512, "miss"),
		makeBenchmarkFixture(tb, "multi_cidr_512", 512, "multi-cidr"),
		makeBenchmarkFixture(tb, "allowlist_stop_512", 512, "allow-stop"),
		makeBenchmarkFixture(tb, "continue_chain_512", 512, "continue"),
	}
}

func makeBenchmarkFixture(tb testing.TB, name string, count int, kind string) benchmarkFixture {
	tb.Helper()
	rules := make([]Rule, count)
	for index := range rules {
		rule := Rule{
			RuleID: fmt.Sprintf("rule-%04d", index), Priority: uint32(index), Action: ActionLog, Flow: FlowContinue,
			Match: Match{Path: &PathMatch{Kind: PathExact, Value: fmt.Sprintf("/miss/%d", index)}},
		}
		switch kind {
		case "steady":
			if index == count-1 {
				rule.Action = ActionBlock
				rule.Flow = FlowStop
				rule.Match.Path.Value = "/target"
			}
		case "multi-cidr":
			rule.Action = ActionBlock
			if index%2 == 0 {
				rule.Match = Match{SourceCIDR: fmt.Sprintf("192.0.%d.9/24", index%255), Method: "POST"}
			} else {
				rule.Match = Match{SourceCIDR: ipv6BenchmarkCIDR(index % 255), Method: "POST"}
			}
		case "allow-stop":
			rule.Action = ActionBlock
			if index == count-1 {
				rule.Action = ActionAllow
				rule.Flow = FlowStop
				rule.Match.Path.Value = "/target"
			}
		case "continue":
			rule.Match.Path.Value = "/target"
			if index%8 == 0 {
				rule.Action = ActionBlock
			}
		}
		rules[index] = rule
	}
	policy := compileForTestTB(tb, Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: rules})
	request := testRequest("192.0.2.200")
	request.Path = "/target"
	return benchmarkFixture{name: name, policy: policy, request: request, now: fixedEvaluationTime()}
}

func compileForTestTB(tb testing.TB, policy Policy) *CompiledPolicy {
	tb.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		tb.Fatal(err)
	}
	_, compiled, err := CompileJSON(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return compiled
}

func ipv6BenchmarkCIDR(segment int) string {
	if segment == 0 {
		return "2001:db8::9/64"
	}
	return fmt.Sprintf("2001:db8:%x::9/64", segment)
}
