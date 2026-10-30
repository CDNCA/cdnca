package rulepack

// Compiled match index of a rule plan (ADR 0011 §6.5, RI-16): rules only ever
// grow, so the node must not try every rule on every request. The index picks
// for each rule of a cdnca.edge.rule-plan/v1 one key condition:
//
//   - a pure condition (host / method / path / path prefix / header / source
//     CIDR / JA4 / port) placed before any side-effecting condition: the
//     interpreter looks the request's own value up in a hash (or per-length
//     prefix) bucket, so a rule whose key does not hold is never visited;
//   - or its first inspect clause, a positive text clause,
//     with the literals any match must contain (lower-cased, any-of): the
//     interpreter
//     merges every such clause of one (target, key, filters) into one
//     Aho-Corasick automaton and scans the values once;
//   - or none (key 0): the rule is visited on every request.
//
// Candidates are then verified with their whole condition chain in plan
// order, so the decision is the linear interpreter's, rule for rule: a
// skipped rule is one whose chain fails at a pure condition or at its key
// inspect clause (which would have returned false). Only IP library lookups
// (no request side effect) may be skipped that the linear chain runs.
//
// Both the control plane and the node precheck compile the same plan to the
// same index (encoding/json over typed structs, sorted map keys).

import (
	"encoding/json"
	"fmt"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const MatchIndexSchema = "cdnca.edge.rule-index/v1"

// MatchIndex rides in the plan (RulePlan.Index).
type MatchIndex struct {
	Schema string `json:"schema"`
	// Keys has one entry per rule in plan order (segments concatenated):
	// 0 = no key, else the 1-based number of the key condition.
	Keys []int `json:"keys"`
	// Needles of inspect-keyed rules by 1-based rule number: a match of the
	// clause implies its lower-cased values contain one of them.
	Needles map[string][]string `json:"needles,omitempty"`
	// Second: a second literal set of the same clause, also required (any
	// of): a rule is a candidate only when the values contain one of its
	// needles and one of these (prefilter before verification).
	Second map[string][]string `json:"second,omitempty"`
	Cost   MatchCost           `json:"cost"`
}

// MatchCost is what the compiled index costs a node per request.
type MatchCost struct {
	Rules int `json:"rules"`
	// Unkeyed rules are verified on every request.
	Unkeyed int `json:"unkeyed"`
	// MaxBucket: most rules behind one key value, one needle (rules without
	// a second literal) or one needle pair (needle + second literal): the
	// worst number of verifications one request value can cause.
	MaxBucket int `json:"max_bucket"`
	// Groups: automata (one per inspect target / key / filters); States:
	// their trie states together.
	Groups int `json:"groups"`
	States int `json:"states"`
	// Regexes: regex clauses (each runs only on a candidate rule).
	Regexes int `json:"regexes"`
	// PrefixLengths: distinct raw path prefix lengths (one lookup each).
	PrefixLengths int `json:"prefix_lengths"`
}

// MatchBudget limits a MatchCost; Rules also bounds the plan.
type MatchBudget struct {
	Rules         int `json:"rules"`
	Unkeyed       int `json:"unkeyed"`
	MaxBucket     int `json:"max_bucket"`
	Groups        int `json:"groups"`
	States        int `json:"states"`
	Regexes       int `json:"regexes"`
	PrefixLengths int `json:"prefix_lengths"`
}

// DefaultMatchBudget keeps a 50 000-rule plan within ADR 0011 §6.5 (p99
// <= 150 us, <= 96 MiB per worker).
// MaxBucket: a request carrying a common literal (and the second literal of
// the rules behind it) verifies at most that many rules.
var DefaultMatchBudget = MatchBudget{Rules: edgeconfig.MaxRulePlanRules, Unkeyed: 256, MaxBucket: 256, Groups: 64,
	States: 4_000_000, Regexes: edgeconfig.MaxRulePlanRules, PrefixLengths: 128}

// MatchBudgetError is a compiled match index over budget (wraps
// ErrBudgetExceeded). Bucket names the rules sharing one key when the
// limit is "rules behind one key" (for the quality gate's report).
type MatchBudgetError struct {
	Item   string        `json:"item"`
	Got    int           `json:"got"`
	Limit  int           `json:"limit"`
	Bucket *SharedBucket `json:"bucket,omitempty"`
}

// SharedBucket is the largest bucket: Key is the pure key bucket
// ("<op>\x00<value>") or, for inspect keys, the clause group (target, key,
// filters) with the shared needle Literal and, when the rules also share
// it, the Second literal. RuleIDs lists the first maxReportedRules of them.
type SharedBucket struct {
	Key     string   `json:"key,omitempty"`
	Target  string   `json:"target,omitempty"`
	Field   string   `json:"field,omitempty"`
	Filters []string `json:"filters,omitempty"`
	Literal string   `json:"literal,omitempty"`
	Second  string   `json:"second,omitempty"`
	Rules   int      `json:"rules"`
	RuleIDs []string `json:"rule_ids"`
}

const maxReportedRules = 32

func (e *MatchBudgetError) Error() string {
	message := fmt.Sprintf("%v: compiled match index: %d %s over %d", ErrBudgetExceeded, e.Got, e.Item, e.Limit)
	if bucket := e.Bucket; bucket != nil {
		if bucket.Literal != "" {
			message += fmt.Sprintf(" (%s %q filters %v literal %q", bucket.Target, bucket.Field, bucket.Filters, bucket.Literal)
			if bucket.Second != "" {
				message += fmt.Sprintf(" with %q", bucket.Second)
			}
		} else {
			message += fmt.Sprintf(" (key %q", strings.ReplaceAll(bucket.Key, "\x00", " "))
		}
		message += fmt.Sprintf(": rules %s", strings.Join(bucket.RuleIDs, ", "))
		if bucket.Rules > len(bucket.RuleIDs) {
			message += fmt.Sprintf(" and %d more", bucket.Rules-len(bucket.RuleIDs))
		}
		message += ")"
	}
	return message
}

func (e *MatchBudgetError) Unwrap() error { return ErrBudgetExceeded }

func (cost MatchCost) within(budget MatchBudget, bucket *SharedBucket) error {
	type limit struct {
		name       string
		got, limit int
	}
	for _, item := range []limit{{"rules", cost.Rules, budget.Rules}, {"unkeyed rules", cost.Unkeyed, budget.Unkeyed},
		{"rules behind one key", cost.MaxBucket, budget.MaxBucket}, {"automata", cost.Groups, budget.Groups},
		{"automaton states", cost.States, budget.States}, {"regexes", cost.Regexes, budget.Regexes},
		{"raw prefix lengths", cost.PrefixLengths, budget.PrefixLengths}} {
		if item.got > item.limit {
			err := &MatchBudgetError{Item: item.name, Got: item.got, Limit: item.limit}
			if item.name == "rules behind one key" {
				err.Bucket = bucket
			}
			return err
		}
	}
	return nil
}

// pureKeyLimit: a pure key shared by more rules than this (and than the
// inspect key's hottest needle) loses to an inspect key of the same rule.
const pureKeyLimit = 16

// maxNeedles bounds the any-of literal set of one clause.
const maxNeedles = 64

type keyOption struct {
	condition int // 1-based
	buckets   []string
}

// CompileMatchIndex compiles plan's index within budget.
func CompileMatchIndex(plan edgeconfig.RulePlan, budget MatchBudget) (*MatchIndex, error) {
	var rules []edgeconfig.RulePlanRule
	for _, segment := range plan.Segments {
		rules = append(rules, segment.Rules...)
	}
	index := &MatchIndex{Schema: MatchIndexSchema, Keys: make([]int, len(rules)), Cost: MatchCost{Rules: len(rules)}}
	pure := make([][]keyOption, len(rules))
	inspects := make([]*edgeconfig.WAFInspect, len(rules))
	needles := make([][]string, len(rules))
	seconds := make([][]string, len(rules))
	needleOptions := make([][][]string, len(rules))
	inspectAt := make([]int, len(rules))
	popularity := map[string]int{}
	needleHeat := map[string]int{}
	for number, rule := range rules {
		for _, condition := range rule.Conditions {
			if condition.Op == edgeconfig.RuleOpInspect {
				var clause edgeconfig.WAFInspect
				if err := json.Unmarshal([]byte(condition.Value), &clause); err != nil {
					return nil, fmt.Errorf("%w: rule %d inspect clause: %v", ErrInvalidPack, number+1, err)
				}
				if clause.Operator == "regex" || clause.Operator == "not_regex" {
					index.Cost.Regexes += len(clause.Values)
				}
			}
		}
		pureRun := true
		for position, condition := range rule.Conditions {
			if condition.Op == edgeconfig.RuleOpIPIntel || condition.Op == edgeconfig.RuleOpIPList {
				// cdnca_iplib.match / cdnca_waf.ip_list are lookups without side effects on
				// the request: an inspect key may follow it, a pure key
				// may not (the index reads no IP library).
				pureRun = false
				continue
			}
			if condition.Op == edgeconfig.RuleOpInspect {
				// The first inspect clause only (the interpreter runs the
				// conditions before it ahead of reading a body group, so
				// the body is read exactly when the chain would read it).
				var clause edgeconfig.WAFInspect
				_ = json.Unmarshal([]byte(condition.Value), &clause)
				if options := clauseNeedleOptions(clause); options != nil {
					inspects[number], needleOptions[number], inspectAt[number] = &clause, options, position+1
					group := inspectGroup(clause)
					for _, option := range options {
						for _, needle := range option {
							needleHeat[group+"\x00"+needle]++
						}
					}
				}
				break
			}
			if buckets := pureBuckets(condition); pureRun && buckets != nil {
				pure[number] = append(pure[number], keyOption{condition: position + 1, buckets: buckets})
				for _, bucket := range buckets {
					popularity[bucket]++
				}
			}
		}
	}
	// The coldest needle set of each inspect key (fewest rules sharing its
	// hottest needle; ties keep the preferred order), then the coldest other
	// set as its second literal.
	for number, options := range needleOptions {
		if options == nil {
			continue
		}
		group := inspectGroup(*inspects[number])
		heat := func(set []string) int {
			hottest := 0
			for _, needle := range set {
				hottest = max(hottest, needleHeat[group+"\x00"+needle])
			}
			return hottest
		}
		coldest := func(skip int) int {
			best, bestHeat := -1, 0
			for option, set := range options {
				if option == skip {
					continue
				}
				if value := heat(set); best < 0 || value < bestHeat {
					best, bestHeat = option, value
				}
			}
			return best
		}
		first := coldest(-1)
		needles[number] = options[first]
		if second := coldest(first); second >= 0 {
			seconds[number] = options[second]
		}
	}
	chosen := map[string][]int{}
	// Inspect buckets: rules behind a needle without a second literal, and
	// behind a (needle, second literal) pair.
	single := map[string][]int{}
	pairs := map[string][]int{}
	groups := map[string]map[string]bool{}
	rawLengths := map[int]bool{}
	for number := range rules {
		best, bestCost := -1, 0
		for option, candidate := range pure[number] {
			cost := 0
			for _, bucket := range candidate.buckets {
				cost = max(cost, popularity[bucket])
			}
			if best < 0 || cost < bestCost {
				best, bestCost = option, cost
			}
		}
		// A pure key wins unless it is shared by more rules than both
		// pureKeyLimit and the hottest needle of the inspect key.
		needleCost := 0
		if inspects[number] != nil {
			group := inspectGroup(*inspects[number])
			for _, needle := range needles[number] {
				needleCost = max(needleCost, needleHeat[group+"\x00"+needle])
			}
		}
		switch {
		case best >= 0 && (bestCost <= max(pureKeyLimit, needleCost) || inspects[number] == nil):
			option := pure[number][best]
			index.Keys[number] = option.condition
			for _, bucket := range option.buckets {
				chosen[bucket] = append(chosen[bucket], number)
			}
			if condition := rules[number].Conditions[option.condition-1]; condition.Op == edgeconfig.RuleOpPathRawPrefix {
				rawLengths[len(condition.Value)] = true
			}
		case inspects[number] != nil:
			index.Keys[number] = inspectAt[number]
			if index.Needles == nil {
				index.Needles = map[string][]string{}
			}
			index.Needles[strconv.Itoa(number+1)] = needles[number]
			group := inspectGroup(*inspects[number])
			if groups[group] == nil {
				groups[group] = map[string]bool{}
			}
			for _, needle := range needles[number] {
				groups[group][needle] = true
				if seconds[number] == nil {
					single[group+"\x00"+needle] = append(single[group+"\x00"+needle], number)
				}
				for _, second := range seconds[number] {
					pairs[group+"\x00"+needle+"\x00"+second] = append(pairs[group+"\x00"+needle+"\x00"+second], number)
				}
			}
			if seconds[number] != nil {
				if index.Second == nil {
					index.Second = map[string][]string{}
				}
				index.Second[strconv.Itoa(number+1)] = seconds[number]
				for _, second := range seconds[number] {
					groups[group][second] = true
				}
			}
		default:
			index.Cost.Unkeyed++
		}
	}
	// The largest bucket (ties: the lexically first name, deterministic).
	var largest string
	var largestRules []int
	consider := func(name string, numbers []int) {
		if len(numbers) > len(largestRules) || len(numbers) == len(largestRules) && name < largest {
			largest, largestRules = name, numbers
		}
	}
	for name, numbers := range chosen {
		consider("pure\x00"+name, numbers)
	}
	for name, numbers := range single {
		consider("inspect\x00"+name, numbers)
	}
	for name, numbers := range pairs {
		// A request with the pair also verifies the needle's single rules.
		needle := name[:strings.LastIndexByte(name, 0)]
		consider("inspect\x00"+name, append(append([]int(nil), single[needle]...), numbers...))
	}
	index.Cost.MaxBucket = len(largestRules)
	index.Cost.Groups = len(groups)
	for _, set := range groups {
		index.Cost.States += trieStates(set)
	}
	index.Cost.PrefixLengths = len(rawLengths)
	if err := index.Cost.within(budget, sharedBucket(largest, largestRules, rules)); err != nil {
		return nil, err
	}
	return index, nil
}

// sharedBucket describes the bucket name (see CompileMatchIndex) of rules.
func sharedBucket(name string, numbers []int, rules []edgeconfig.RulePlanRule) *SharedBucket {
	if numbers == nil {
		return nil
	}
	bucket := &SharedBucket{Rules: len(numbers)}
	for _, number := range numbers[:min(len(numbers), maxReportedRules)] {
		bucket.RuleIDs = append(bucket.RuleIDs, rules[number].RuleID)
	}
	parts := strings.Split(name, "\x00")
	if parts[0] == "pure" {
		bucket.Key = strings.Join(parts[1:], "\x00")
		return bucket
	}
	// inspect, target, key, filters, needle[, second]
	bucket.Target, bucket.Field, bucket.Literal = parts[1], parts[2], parts[4]
	if parts[3] != "" {
		bucket.Filters = strings.Split(parts[3], ",")
	}
	if len(parts) > 5 {
		bucket.Second = parts[5]
	}
	return bucket
}

// AttachMatchIndex compiles plan's index with DefaultMatchBudget into
// plan.Index.
func AttachMatchIndex(plan *edgeconfig.RulePlan) error {
	index, err := CompileMatchIndex(*plan, DefaultMatchBudget)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		return err
	}
	plan.Index = encoded
	return nil
}

// pureBuckets names the buckets a pure condition sits in (nil: not
// indexable). The interpreter keys its tables the same way.
func pureBuckets(condition edgeconfig.RulePlanCondition) []string {
	switch condition.Op {
	case edgeconfig.RuleOpHostEq, edgeconfig.RuleOpMethodEq, edgeconfig.RuleOpPathExact, edgeconfig.RuleOpPathPrefix,
		edgeconfig.RuleOpPathRawPrefix, edgeconfig.RuleOpSourceCIDR:
		return []string{condition.Op + "\x00" + condition.Value}
	case edgeconfig.RuleOpHeaderExists:
		return []string{condition.Op + "\x00" + condition.Name}
	case edgeconfig.RuleOpHeaderEq:
		return []string{condition.Op + "\x00" + condition.Name + "\x00" + condition.Value}
	case edgeconfig.RuleOpPortEq:
		if condition.Number != nil {
			return []string{condition.Op + "\x00" + strconv.FormatInt(*condition.Number, 10)}
		}
	case edgeconfig.RuleOpJA4In:
		buckets := make([]string, len(condition.Values))
		for index, value := range condition.Values {
			buckets[index] = condition.Op + "\x00" + value
		}
		return buckets
	}
	return nil
}

func inspectGroup(clause edgeconfig.WAFInspect) string {
	return clause.Target + "\x00" + clause.Key + "\x00" + strings.Join(clause.Filters, ",")
}

// Text targets whose values cdnca_waf.inspect_text_values returns.
var indexTextTargets = map[string]bool{"args": true, "query": true, "body": true, "request_uri": true, "path": true,
	"header": true, "header_names": true, "cookie": true, "user_agent": true, "referer": true,
	"upload_filename": true, "upload_extension": true, "multipart_field_names": true}

// clauseNeedleOptions: alternative sets of lower-cased literals, each such
// that every value the clause matches contains one of its literals (the
// preferred set first), or nil. Only positive text operators qualify; a clause
// that matches on body overflow does so without any value.
func clauseNeedleOptions(clause edgeconfig.WAFInspect) [][]string {
	if clause.BodyOverflow != "" || !indexTextTargets[clause.Target] {
		return nil
	}
	for _, filter := range clause.Filters {
		if filter == "length" {
			return nil
		}
	}
	set := map[string]bool{}
	switch clause.Operator {
	case "contains", "equals", "prefix", "suffix":
		for _, value := range clause.Values {
			set[asciiLower(value)] = true
		}
	case "contains_all":
		// Every value is required: the longest first, then the others.
		values := append([]string(nil), clause.Values...)
		sort.SliceStable(values, func(a, b int) bool { return len(values[a]) > len(values[b]) })
		var options [][]string
		seen := map[string]bool{}
		for _, value := range values {
			if lowered := asciiLower(value); lowered != "" && !seen[lowered] {
				seen[lowered] = true
				options = append(options, []string{lowered})
			}
		}
		if options == nil {
			return nil
		}
		return options
	case "regex":
		if len(clause.Values) == 1 {
			return regexLiteralOptions(clause.Values[0])
		}
		for _, pattern := range clause.Values {
			literals := regexLiterals(pattern)
			if literals == nil {
				return nil
			}
			for _, literal := range literals {
				set[literal] = true
			}
		}
	default:
		return nil
	}
	if len(set) == 0 || len(set) > maxNeedles || set[""] {
		return nil
	}
	return [][]string{sortedKeys(set)}
}

// clauseNeedles is the first (preferred) needle set of clause, or nil.
func clauseNeedles(clause edgeconfig.WAFInspect) []string {
	options := clauseNeedleOptions(clause)
	if options == nil {
		return nil
	}
	return options[0]
}

// asciiLower is Lua's string.lower: A-Z only.
func asciiLower(value string) string {
	out := []byte(value)
	for index, char := range out {
		if char >= 'A' && char <= 'Z' {
			out[index] = char + 'a' - 'A'
		}
	}
	return string(out)
}

func sortedKeys(set map[string]bool) []string {
	list := make([]string, 0, len(set))
	for key := range set {
		list = append(list, key)
	}
	sort.Strings(list)
	return list
}

// regexLiterals: lower-cased literals one of which every match of pattern
// contains, as the node's PCRE (ngx.re "jo", no UTF mode) reads it, or nil.
// Literals come only from printable ASCII literal runes, and patterns where
// RE2 syntax and PCRE2 may read characters differently (digit escapes,
// "{,n}") yield none: a literal that is not really required would drop rules.
func regexLiterals(pattern string) []string {
	options := regexLiteralOptions(pattern)
	if options == nil {
		return nil
	}
	return options[0]
}

// regexLiteralOptions: every required literal set of pattern (each one is
// sufficient), the preferred one first; nil when there is none.
func regexLiteralOptions(pattern string) [][]string {
	if strings.Contains(pattern, "{,") {
		return nil
	}
	for index := 0; index+1 < len(pattern); index++ {
		if pattern[index] == '\\' {
			if next := pattern[index+1]; next >= '0' && next <= '9' {
				return nil
			}
			index++
		}
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	sets := []map[string]bool{}
	if parsed.Op == syntax.OpConcat {
		sets = concatCandidates(parsed)
	}
	best := requiredLiterals(parsed)
	if best == nil {
		return nil
	}
	options := [][]string{sortedKeys(best)}
	seen := map[string]bool{strings.Join(options[0], "\x00"): true}
	for _, set := range sets {
		if len(set) == 0 || len(set) > maxNeedles || set[""] {
			continue
		}
		keys := sortedKeys(set)
		if name := strings.Join(keys, "\x00"); !seen[name] {
			seen[name] = true
			options = append(options, keys)
		}
	}
	return options
}

// requiredLiterals: any-of set of literals (lower-cased) one of which every
// match of node contains, nil when there is none.
func requiredLiterals(node *syntax.Regexp) map[string]bool {
	switch node.Op {
	case syntax.OpLiteral:
		return bestOf(literalRuns(node.Rune))
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(node.Sub[0])
	case syntax.OpRepeat:
		if node.Min >= 1 {
			return requiredLiterals(node.Sub[0])
		}
	case syntax.OpAlternate:
		union := map[string]bool{}
		for _, sub := range node.Sub {
			set := requiredLiterals(sub)
			if set == nil {
				return nil
			}
			for literal := range set {
				union[literal] = true
			}
		}
		if len(union) > maxNeedles {
			return nil
		}
		return union
	case syntax.OpConcat:
		return bestOf(concatCandidates(node))
	}
	return nil
}

// concatCandidates: adjacent literal children of a concatenation form one
// run; every run and every child's own set is required.
func concatCandidates(node *syntax.Regexp) []map[string]bool {
	var candidates []map[string]bool
	var run []rune
	flush := func() {
		candidates = append(candidates, literalRuns(run)...)
		run = nil
	}
	for _, sub := range node.Sub {
		if sub.Op == syntax.OpLiteral {
			run = append(run, sub.Rune...)
			continue
		}
		flush()
		if set := requiredLiterals(sub); set != nil {
			candidates = append(candidates, set)
		}
	}
	flush()
	return candidates
}

// literalRuns splits runes into maximal printable ASCII runs (lower-cased),
// each a one-literal set.
func literalRuns(runes []rune) []map[string]bool {
	var sets []map[string]bool
	var current strings.Builder
	end := func() {
		if current.Len() > 0 {
			sets = append(sets, map[string]bool{asciiLower(current.String()): true})
			current.Reset()
		}
	}
	for _, char := range runes {
		if char < 0x20 || char > 0x7e {
			end()
			continue
		}
		current.WriteRune(char)
	}
	end()
	return sets
}

// bestOf prefers the set whose shortest literal is longest, then the
// smaller set, then the lexically first.
func bestOf(sets []map[string]bool) map[string]bool {
	var best map[string]bool
	score := func(set map[string]bool) (int, int, string) {
		shortest := -1
		for literal := range set {
			if shortest < 0 || len(literal) < shortest {
				shortest = len(literal)
			}
		}
		return shortest, len(set), strings.Join(sortedKeys(set), "\x00")
	}
	for _, set := range sets {
		if best == nil {
			best = set
			continue
		}
		short, size, name := score(set)
		bestShort, bestSize, bestName := score(best)
		if short > bestShort || short == bestShort && (size < bestSize || size == bestSize && name < bestName) {
			best = set
		}
	}
	return best
}

// trieStates counts the states (root included) of the trie of needles.
func trieStates(needles map[string]bool) int {
	prefixes := map[string]bool{}
	for needle := range needles {
		for end := 1; end <= len(needle); end++ {
			prefixes[needle[:end]] = true
		}
	}
	return len(prefixes) + 1
}
