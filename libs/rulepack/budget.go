package rulepack

import (
	"fmt"
	"regexp/syntax"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Cost is what a set of rules costs a node per request. Units are a static
// estimate (condition count weighted by what the node does for it: a body
// regex is far dearer than a method check); the weights are an initial model,
// not a measurement.
type Cost struct {
	Rules   int `json:"rules"`
	Regexes int `json:"regexes"`
	Units   int `json:"units"`
}

// Budget limits a Cost.
type Budget struct {
	Rules   int `json:"rules"`
	Regexes int `json:"regexes"`
	Units   int `json:"units"`
}

var (
	// PackBudget limits one pack (defaults and every parameter boundary).
	PackBudget = Budget{Rules: 256, Regexes: 64, Units: 4096}
	// SiteBudget limits every effective mount of one site together.
	SiteBudget = Budget{Rules: 1024, Regexes: 256, Units: 16384}

	packBudget = PackBudget
	siteBudget = SiteBudget
)

const (
	maxCCRules         = 128
	maxRegexBytes      = 512
	maxRegexRepeat     = 256
	maxUnboundedRepeat = 4
)

func (cost Cost) add(other Cost) Cost {
	return Cost{Rules: cost.Rules + other.Rules, Regexes: cost.Regexes + other.Regexes, Units: cost.Units + other.Units}
}

func (cost Cost) within(budget Budget) error {
	if cost.Rules > budget.Rules || cost.Regexes > budget.Regexes || cost.Units > budget.Units {
		return fmt.Errorf("%w: %d rules / %d regexes / %d units over %d / %d / %d", ErrBudgetExceeded,
			cost.Rules, cost.Regexes, cost.Units, budget.Rules, budget.Regexes, budget.Units)
	}
	return nil
}

var inspectTargetWeight = map[string]int{
	"body": 8, "args": 2, "query": 2, "cookie": 2, "header": 2, "request_uri": 1, "path": 1, "user_agent": 1, "referer": 1,
}

var inspectOperatorWeight = map[string]int{"contains": 1, "regex": 4, "detect": 8}

// rulesCost prices rules and rejects regexes with backtracking risk.
func rulesCost(rules []Rule) (Cost, error) {
	var cost Cost
	for _, rule := range rules {
		ruleCost, err := ruleCost(rule)
		if err != nil {
			return Cost{}, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		cost = cost.add(ruleCost)
	}
	return cost, nil
}

func ruleCost(rule Rule) (Cost, error) {
	if rule.Tuning != nil {
		// a CRS tuning entry is not an interpreted rule: the node renders
		// it into ModSecurity once (edgeconfig.RenderDynamicWAFRules), its
		// count is bounded by maxCRSTuningEntries
		return Cost{}, nil
	}
	cost := Cost{Rules: 1, Units: 1}
	switch {
	case rule.WAF != nil:
		match := rule.WAF.Match
		for _, present := range []bool{match.Method != "", match.Path != nil, match.Header != nil,
			match.SourceCIDR != "", match.JA4 != nil} {
			if present {
				cost.Units++
			}
		}
		cost.Units += 2 * len(match.IPIntel)
		for _, inspect := range match.Inspect {
			cost.Units += inspectTargetWeight[inspect.Target] * inspectOperatorWeight[inspect.Operator] * len(inspect.Values)
			if inspect.Operator != "regex" {
				continue
			}
			for _, value := range inspect.Values {
				if err := checkRegex(value); err != nil {
					return Cost{}, err
				}
				cost.Regexes++
			}
		}
	case rule.CC != nil:
		match := rule.CC.Match
		cost.Units += 2 + len(match.PathContains) + len(match.ClientIP)
		for _, header := range match.Headers {
			weight := 1
			if header.Kind == edgeconfig.CCV2HeaderRegex {
				weight = 4
				for _, value := range header.Values {
					if err := checkRegex(value); err != nil {
						return Cost{}, err
					}
					cost.Regexes++
				}
			}
			cost.Units += weight * len(header.Values)
		}
		if rule.CC.Action.Challenge != nil {
			cost.Units += 2
		}
	case rule.CRS != nil, rule.App != nil:
		cost.Units += 100
	}
	return cost, nil
}

// checkRegex accepts patterns the node can run without catastrophic
// backtracking. The node uses PCRE (backtracking), so linear-time RE2 is not
// a guarantee there: the pattern must parse as RE2 (no backreferences or
// lookaround), have no nested unbounded repetition ("(a+)+"), no large
// counted repeats and few unbounded repeats in total.
func checkRegex(pattern string) error {
	if len(pattern) == 0 || len(pattern) > maxRegexBytes {
		return fmt.Errorf("%w: regex length", ErrBudgetExceeded)
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("%w: regex %q: %v", ErrInvalidPack, pattern, err)
	}
	unbounded := 0
	var walk func(node *syntax.Regexp, depth int) error
	walk = func(node *syntax.Regexp, depth int) error {
		repeated := false
		switch node.Op {
		case syntax.OpStar, syntax.OpPlus:
			repeated, unbounded = true, unbounded+1
		case syntax.OpRepeat:
			if node.Max == -1 {
				unbounded++
			}
			if node.Max > maxRegexRepeat || node.Min > maxRegexRepeat {
				return fmt.Errorf("%w: regex %q repeat count over %d", ErrBudgetExceeded, pattern, maxRegexRepeat)
			}
			repeated = node.Max == -1 || node.Max > 1
		}
		if repeated {
			depth++
			if depth > 1 {
				return fmt.Errorf("%w: regex %q nests repetition (backtracking risk)", ErrBudgetExceeded, pattern)
			}
		}
		for _, sub := range node.Sub {
			if err := walk(sub, depth); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(parsed, 0); err != nil {
		return err
	}
	if unbounded > maxUnboundedRepeat {
		return fmt.Errorf("%w: regex %q has %d unbounded repeats (max %d)", ErrBudgetExceeded, pattern, unbounded, maxUnboundedRepeat)
	}
	return nil
}
