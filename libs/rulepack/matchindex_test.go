package rulepack

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Every key condition precedes any side-effecting condition, inspect keys
// carry needles, and the index is a deterministic function of the plan.
func TestMatchIndexInvariants(t *testing.T) {
	for _, total := range []int{1, 50, 1000, 10000} {
		g := newRuleGen(uint64(total))
		plan := genPlan(t, g, total, true)
		var index MatchIndex
		if err := json.Unmarshal(plan.Index, &index); err != nil {
			t.Fatal(err)
		}
		var rules []edgeconfig.RulePlanRule
		for _, segment := range plan.Segments {
			rules = append(rules, segment.Rules...)
		}
		if len(index.Keys) != len(rules) || index.Cost.Rules != len(rules) {
			t.Fatalf("%d rules: %d keys", len(rules), len(index.Keys))
		}
		for number, key := range index.Keys {
			if key == 0 {
				continue
			}
			conditions := rules[number].Conditions
			for _, before := range conditions[:key-1] {
				if before.Op == edgeconfig.RuleOpInspect || before.Op == edgeconfig.RuleOpIPIntel && conditions[key-1].Op != edgeconfig.RuleOpInspect {
					t.Fatalf("rule %d key %d after %s", number+1, key, before.Op)
				}
			}
			if conditions[key-1].Op == edgeconfig.RuleOpInspect && len(index.Needles[itoa(number+1)]) == 0 {
				t.Fatalf("rule %d inspect key without needles", number+1)
			}
		}
		again := genPlan(t, newRuleGen(uint64(total)), total, true)
		if string(again.Index) != string(plan.Index) {
			t.Fatalf("%d rules: index is not deterministic", total)
		}
		t.Logf("%d rules: cost %+v", total, index.Cost)
		if total >= 1000 && index.Cost.Unkeyed != 0 {
			t.Fatalf("generated rules all have a key, %d unkeyed", index.Cost.Unkeyed)
		}
	}
}

func itoa(value int) string { return strconv.Itoa(value) }

// regexLiterals: every string the pattern matches (Go RE2, the same
// language for the accepted patterns) contains, lower-cased, one of the
// literals. Checked on strings built around each literal and on mutations.
func TestRegexLiteralsAreRequired(t *testing.T) {
	patterns := []string{`(?i)union\s+select`, `\.(php|asp)$`, `(?i)sqlmap|nikto`, `atk1[a-z]{0,8}`, `^/?(?:x|y)atk2(?:\.php|\.asp)$`,
		`(?i)(?:ATK3|rx3)`, `(?:union|atk4)\s+select`, `(?i)atk5\s*=\s*\d+`, `a(bc)+d`, `(ab|cd)(ef|gh)`, `x?yz`, `(?:abc)*def`,
		`[a-c]bcd`, `\x41BC`, `(?s).+eval\(`, `(?i)<script[^>]*>`, `\bselect\b.*\bfrom\b`, `(?:abc){2,3}`}
	rng := rand.New(rand.NewPCG(7, 11))
	alphabet := "abcdefghxyzABCSELECTUNION<>=.( /\\12-_"
	for _, pattern := range patterns {
		literals := regexLiterals(pattern)
		compiled := regexp.MustCompile(pattern)
		for attempt := 0; attempt < 20000; attempt++ {
			var sample strings.Builder
			for length := rng.IntN(14); length > 0; length-- {
				if rng.IntN(4) == 0 && len(literals) > 0 {
					literal := literals[rng.IntN(len(literals))]
					sample.WriteString(literal[:rng.IntN(len(literal)+1)])
				}
				sample.WriteByte(alphabet[rng.IntN(len(alphabet))])
			}
			value := sample.String()
			if !compiled.MatchString(value) || literals == nil {
				continue
			}
			found := false
			for _, literal := range literals {
				found = found || strings.Contains(asciiLower(value), literal)
			}
			if !found {
				t.Fatalf("%q matches %q without any of %q", pattern, value, literals)
			}
		}
		t.Logf("%-32s -> %q", pattern, literals)
	}
	for _, pattern := range []string{`.*`, `a|.`, `\d+`, `(?:ab)?`, `\1`, `a{,3}b`} {
		if literals := regexLiterals(pattern); literals != nil {
			t.Fatalf("%q must have no required literal, got %q", pattern, literals)
		}
	}
}

func TestClauseNeedles(t *testing.T) {
	cases := []struct {
		clause edgeconfig.WAFInspect
		want   []string
	}{
		{edgeconfig.WAFInspect{Target: "query", Operator: "contains", Values: []string{"<Script", "1=1"}}, []string{"1=1", "<script"}},
		{edgeconfig.WAFInspect{Target: "body", Operator: "contains_all", Values: []string{"or", "union"}}, []string{"union"}},
		{edgeconfig.WAFInspect{Target: "args", Operator: "equals", Values: []string{"Admin"}}, []string{"admin"}},
		{edgeconfig.WAFInspect{Target: "args", Operator: "not_contains", Values: []string{"x"}}, nil},
		{edgeconfig.WAFInspect{Target: "args", Operator: "detect", Values: []string{"sqli"}}, nil},
		{edgeconfig.WAFInspect{Target: "uri_length", Operator: "gt", Values: []string{"9"}}, nil},
		{edgeconfig.WAFInspect{Target: "user_agent", Operator: "eq", Values: []string{"0"}, Filters: []string{"length"}}, nil},
		{edgeconfig.WAFInspect{Target: "body", Operator: "contains", Values: []string{"x"}, BodyOverflow: "match"}, nil},
		{edgeconfig.WAFInspect{Target: "path", Operator: "regex", Values: []string{`.*`}}, nil},
	}
	for _, item := range cases {
		got := clauseNeedles(item.clause)
		if strings.Join(got, "|") != strings.Join(item.want, "|") || (got == nil) != (item.want == nil) {
			t.Fatalf("%+v: %q, want %q", item.clause, got, item.want)
		}
	}
}

// A plan over budget fails at compile time with ErrBudgetExceeded.
func TestMatchIndexBudget(t *testing.T) {
	g := newRuleGen(3)
	plan := genPlan(t, g, 2000, false)
	if _, err := CompileMatchIndex(plan, DefaultMatchBudget); err != nil {
		t.Fatal(err)
	}
	for name, budget := range map[string]MatchBudget{
		"rules":  {Rules: 100, Unkeyed: 256, MaxBucket: 256, Groups: 64, States: 1 << 22, Regexes: 1 << 16, PrefixLengths: 128},
		"bucket": {Rules: 1 << 16, Unkeyed: 256, MaxBucket: 1, Groups: 64, States: 1 << 22, Regexes: 1 << 16, PrefixLengths: 128},
		"states": {Rules: 1 << 16, Unkeyed: 256, MaxBucket: 256, Groups: 64, States: 10, Regexes: 1 << 16, PrefixLengths: 128},
	} {
		if _, err := CompileMatchIndex(plan, budget); !errors.Is(err, ErrBudgetExceeded) || !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("%s budget: %v", name, err)
		}
	}
	// Rules without any key are bounded: every request verifies them.
	var segments []edgeconfig.RulePlanSegmentInput
	policy := edgeconfig.SecurityPolicy{Kind: edgeconfig.SecurityWAF, PolicyID: genUUID(1, 9), PolicyVersion: 1, BindingRevision: 1,
		RuntimeSHA256: strings.Repeat("ab", 32), Enabled: true, DefaultAction: edgeconfig.WAFAllow}
	for n := 0; n < 300; n++ {
		policy.Rules = append(policy.Rules, edgeconfig.WAFRule{RuleID: genUUID(n, 1), Action: edgeconfig.WAFLog, Control: edgeconfig.WAFContinue,
			Match: edgeconfig.WAFMatch{Inspect: []edgeconfig.WAFInspect{{Target: "args", Operator: "detect", Values: []string{"sqli"}}}}})
	}
	segments = append(segments, edgeconfig.RulePlanSegmentInput{Layer: edgeconfig.RulePlanLayerSystem, Policy: policy})
	unkeyed, err := edgeconfig.CompileLayeredRulePlan(segments, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachMatchIndex(&unkeyed); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("300 unkeyed rules: %v", err)
	}
}

// Rules sharing their literals (needle and second literal) past MaxBucket
// fail at compile time naming the shared literals and the rules.
func TestMatchIndexSharedLiteral(t *testing.T) {
	policy := edgeconfig.SecurityPolicy{Kind: edgeconfig.SecurityWAF, PolicyID: genUUID(1, 9), PolicyVersion: 1, BindingRevision: 1,
		RuntimeSHA256: strings.Repeat("ab", 32), Enabled: true, DefaultAction: edgeconfig.WAFAllow}
	plan := func(rules int, distinct bool) edgeconfig.RulePlan {
		policy.Rules = nil
		for n := 0; n < rules; n++ {
			pattern := `(?:union|atk` + itoa(n) + `)\s+select`
			if distinct {
				pattern += `\s+col` + itoa(n)
			}
			policy.Rules = append(policy.Rules, edgeconfig.WAFRule{RuleID: genUUID(n, 2), Action: edgeconfig.WAFLog, Control: edgeconfig.WAFContinue,
				Match: edgeconfig.WAFMatch{Inspect: []edgeconfig.WAFInspect{{Target: "query", Operator: "regex", Values: []string{pattern}}}}})
		}
		compiled, err := edgeconfig.CompileLayeredRulePlan([]edgeconfig.RulePlanSegmentInput{{Layer: edgeconfig.RulePlanLayerSystem, Policy: policy}}, false, true)
		if err != nil {
			t.Fatal(err)
		}
		return compiled
	}
	shared := plan(300, false)
	err := AttachMatchIndex(&shared)
	var budget *MatchBudgetError
	if !errors.Is(err, ErrBudgetExceeded) || !errors.As(err, &budget) || budget.Bucket == nil {
		t.Fatalf("300 rules sharing union / select: %v", err)
	}
	bucket := budget.Bucket
	if budget.Got != 300 || budget.Limit != 256 || bucket.Target != "query" || bucket.Rules != 300 || len(bucket.RuleIDs) != maxReportedRules ||
		bucket.RuleIDs[0] != genUUID(0, 2) || bucket.Literal+"/"+bucket.Second != "select/union" && bucket.Literal+"/"+bucket.Second != "union/select" {
		t.Fatalf("bucket %+v", budget)
	}
	if !strings.Contains(err.Error(), `literal "`) || !strings.Contains(err.Error(), "and 268 more") {
		t.Fatalf("message %q", err)
	}
	// One per-rule literal more and each rule has its own pair.
	distinct := plan(300, true)
	if err := AttachMatchIndex(&distinct); err != nil {
		t.Fatal(err)
	}
	var index MatchIndex
	_ = json.Unmarshal(distinct.Index, &index)
	if index.Cost.MaxBucket != 1 || len(index.Second) != 300 {
		t.Fatalf("distinct cost %+v, %d second sets", index.Cost, len(index.Second))
	}
}

// ADR 0011 §6.5: publish / precheck compile 10 000 rules in <= 2 s.
func BenchmarkCompile10k(b *testing.B) {
	g := newRuleGen(10000)
	plan := genPlan(b, g, 10000, false)
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		copy := plan
		if err := AttachMatchIndex(&copy); err != nil {
			b.Fatal(err)
		}
		if _, err := edgeconfig.EncodeRulePlan(copy); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPlanAndIndex10k includes building the plan from 10 000 rules.
func BenchmarkPlanAndIndex10k(b *testing.B) {
	for iteration := 0; iteration < b.N; iteration++ {
		g := newRuleGen(10000)
		plan := genPlan(b, g, 10000, true)
		if _, err := edgeconfig.EncodeRulePlan(plan); err != nil {
			b.Fatal(err)
		}
	}
}
