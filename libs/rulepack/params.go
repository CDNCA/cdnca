package rulepack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// ParamExclusions is the reserved parameter every pack has: the exported
// rule IDs that are switched off (rule-level disable, CRS ctl:ruleRemoveById
// for modsecurity). It is not declared in params_schema.
const ParamExclusions = "exclusions"

// Params are parameter values by name. After normalization each value is in
// canonical JSON (integers without exponent, sorted rule ID lists), so the
// encoding of a Params map is deterministic.
type Params map[string]json.RawMessage

// ParamSpec is a JSON Schema subset: an integer range, a string enum or a
// boolean, bound to one fixed target in the rules (no expressions).
type ParamSpec struct {
	Type    string   `json:"type"`
	Minimum *int64   `json:"minimum,omitempty"`
	Maximum *int64   `json:"maximum,omitempty"`
	Enum    []string `json:"enum,omitempty"`
	Bind    Bind     `json:"bind"`
}

// Bind names the rule field a parameter sets and the rules it applies to
// (empty = every rule of the pack).
type Bind struct {
	Target string   `json:"target"`
	Rules  []string `json:"rules"`
}

const (
	typeInteger = "integer"
	typeString  = "string"
	typeBoolean = "boolean"
	maxInteger  = 1<<31 - 1
)

type bindTarget struct {
	kind      string
	engines   []Engine
	enum      []string
	challenge bool
}

// Challenge settings a pack rule gets when a parameter switches its action
// to challenge (waf.action / cc.action.kind): the JS proof-of-work page the
// security policy editor and smart auto defense default to.
var (
	DefaultWAFChallenge = edgeconfig.WAFActionConfig{PassSeconds: 3600, PowBits: 16}
	DefaultCCChallenge  = edgeconfig.CCV2Challenge{Mode: "js", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600,
		PowBits: 16, ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}
	DefaultCCChallengeBanSeconds uint32 = 600
)

var wafEngines = []Engine{EngineWAFV2, EngineACL}
var ccEngines = []Engine{EngineCCV2, EngineChallenge}

var bindTargets = map[string]bindTarget{
	"waf.action": {kind: typeString, engines: wafEngines, enum: []string{"allow", "block", "challenge", "log"}},
	// waf.inspect.number: the single value of the rule's first number
	// inspect clause (a threshold such as multipart_part_count gt N).
	// Every bound rule must have one (normalizeParamSpec).
	"waf.inspect.number":        {kind: typeInteger, engines: []Engine{EngineWAFV2}},
	"cc.action.kind":            {kind: typeString, engines: []Engine{EngineCCV2}, enum: []string{"challenge", "log", "reject_429"}},
	"rule.enabled":              {kind: typeBoolean, engines: []Engine{EngineWAFV2, EngineACL, EngineCCV2, EngineChallenge}},
	"cc.limit.requests":         {kind: typeInteger, engines: ccEngines},
	"cc.limit.window_seconds":   {kind: typeInteger, engines: ccEngines},
	"cc.limit.requests_per_uri": {kind: typeInteger, engines: ccEngines},
	"cc.limit.rate_per_second":  {kind: typeInteger, engines: ccEngines},
	"cc.limit.burst":            {kind: typeInteger, engines: ccEngines},
	"cc.action.ban_seconds":     {kind: typeInteger, engines: ccEngines},
	"cc.challenge.mode":         {kind: typeString, engines: ccEngines, enum: edgeconfig.CCV2ChallengeModes, challenge: true},
	"cc.challenge.pass_seconds": {kind: typeInteger, engines: ccEngines, challenge: true},
}

func normalizeParamSpec(pack Pack, spec ParamSpec) (ParamSpec, error) {
	target, ok := bindTargets[spec.Bind.Target]
	if !ok || !containsEngine(target.engines, pack.Engine) || spec.Type != target.kind {
		return ParamSpec{}, fmt.Errorf("bind target %q (%s) is not available for %s", spec.Bind.Target, spec.Type, pack.Engine)
	}
	out := ParamSpec{Type: spec.Type, Bind: Bind{Target: spec.Bind.Target}}
	switch spec.Type {
	case typeInteger:
		if spec.Minimum == nil || spec.Maximum == nil || *spec.Minimum < 0 || *spec.Minimum > *spec.Maximum ||
			*spec.Maximum > maxInteger || spec.Enum != nil {
			return ParamSpec{}, errors.New("integer needs 0 <= minimum <= maximum")
		}
		minimum, maximum := *spec.Minimum, *spec.Maximum
		out.Minimum, out.Maximum = &minimum, &maximum
	case typeString:
		if spec.Minimum != nil || spec.Maximum != nil || len(spec.Enum) == 0 {
			return ParamSpec{}, errors.New("string needs an enum")
		}
		out.Enum = append([]string{}, spec.Enum...)
		sort.Strings(out.Enum)
		for index, value := range out.Enum {
			if !containsString(target.enum, value) || index > 0 && out.Enum[index-1] == value {
				return ParamSpec{}, fmt.Errorf("enum value %q is not allowed", value)
			}
		}
	case typeBoolean:
		if spec.Minimum != nil || spec.Maximum != nil || spec.Enum != nil {
			return ParamSpec{}, errors.New("boolean takes no range or enum")
		}
	}
	out.Bind.Rules = append([]string{}, spec.Bind.Rules...)
	sort.Strings(out.Bind.Rules)
	for index, id := range out.Bind.Rules {
		if index > 0 && out.Bind.Rules[index-1] == id {
			return ParamSpec{}, fmt.Errorf("bind rule %q repeated", id)
		}
		if _, ok := findRule(pack, id); !ok {
			return ParamSpec{}, fmt.Errorf("bind rule %q is not a rule of the pack", id)
		}
	}
	if spec.Bind.Target == "waf.inspect.number" {
		for _, rule := range pack.Rules {
			if bindsRule(out.Bind, rule.ID) && numberInspect(rule.WAF) < 0 {
				return ParamSpec{}, fmt.Errorf("rule %s has no number inspect clause for %s", rule.ID, spec.Bind.Target)
			}
		}
	}
	if target.challenge {
		for _, rule := range pack.Rules {
			if bindsRule(out.Bind, rule.ID) && rule.CC.Action.Challenge == nil {
				return ParamSpec{}, fmt.Errorf("rule %s has no challenge for %s", rule.ID, spec.Bind.Target)
			}
		}
	}
	return out, nil
}

// uniqueBindTargets rejects two parameters setting the same field of one
// rule: the result would depend on which one is applied last. Parameters
// binding one target to disjoint, explicit rule lists are fine
// (one action for the blocking rules, another for a log-only
// signal); an empty list means every rule and overlaps everything.
func uniqueBindTargets(schema map[string]ParamSpec) error {
	seen := map[string][]string{}
	for _, name := range sortedParamNames(schema) {
		bind := schema[name].Bind
		for _, other := range seen[bind.Target] {
			if bindsOverlap(schema[other].Bind, bind) {
				return fmt.Errorf("params %s and %s both bind %s", other, name, bind.Target)
			}
		}
		seen[bind.Target] = append(seen[bind.Target], name)
	}
	return nil
}

func bindsOverlap(left, right Bind) bool {
	if len(left.Rules) == 0 || len(right.Rules) == 0 {
		return true
	}
	for _, id := range left.Rules {
		if bindsRule(right, id) {
			return true
		}
	}
	return false
}

func findRule(pack Pack, id string) (Rule, bool) {
	index := sort.Search(len(pack.Rules), func(i int) bool { return pack.Rules[i].ID >= id })
	if index < len(pack.Rules) && pack.Rules[index].ID == id {
		return pack.Rules[index], true
	}
	return Rule{}, false
}

func bindsRule(bind Bind, id string) bool {
	if len(bind.Rules) == 0 {
		return true
	}
	index := sort.SearchStrings(bind.Rules, id)
	return index < len(bind.Rules) && bind.Rules[index] == id
}

func sortedParamNames(schema map[string]ParamSpec) []string {
	names := make([]string, 0, len(schema))
	for name := range schema {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// normalizeParams validates values against the pack's schema and returns
// them canonically. requireAll demands every declared parameter (defaults).
// The result always carries exclusions.
func normalizeParams(pack Pack, values Params, requireAll bool) (Params, error) {
	out := Params{ParamExclusions: json.RawMessage(`[]`)}
	for name, raw := range values {
		canonical, err := normalizeParamValue(pack, name, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: param %s: %v", ErrInvalidPack, name, err)
		}
		out[name] = canonical
	}
	if requireAll {
		for name := range pack.ParamsSchema {
			if _, ok := out[name]; !ok {
				return nil, fmt.Errorf("%w: defaults miss param %s", ErrInvalidPack, name)
			}
		}
	}
	return out, nil
}

func normalizeParamValue(pack Pack, name string, raw json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("value is not JSON")
	}
	if name == ParamExclusions {
		list, ok := value.([]any)
		if !ok || len(list) > maxCRSExclusions {
			return nil, errors.New("must be a list of exported rule IDs")
		}
		ids := make([]string, 0, len(list))
		for _, item := range list {
			id, ok := item.(string)
			if !ok || !pack.Exported(id) {
				return nil, fmt.Errorf("%v is not an exported rule", item)
			}
			ids = append(ids, id)
		}
		return json.Marshal(sortUnique(ids))
	}
	spec, ok := pack.ParamsSchema[name]
	if !ok {
		return nil, errors.New("not declared in params_schema")
	}
	switch spec.Type {
	case typeInteger:
		number, ok := value.(json.Number)
		if !ok {
			return nil, errors.New("must be an integer")
		}
		parsed, err := strconv.ParseInt(number.String(), 10, 64)
		if err != nil || parsed < *spec.Minimum || parsed > *spec.Maximum {
			return nil, fmt.Errorf("must be an integer in %d..%d", *spec.Minimum, *spec.Maximum)
		}
		return json.RawMessage(strconv.FormatInt(parsed, 10)), nil
	case typeString:
		text, ok := value.(string)
		if !ok || !containsString(spec.Enum, text) {
			return nil, fmt.Errorf("must be one of %v", spec.Enum)
		}
		return json.Marshal(text)
	default:
		flag, ok := value.(bool)
		if !ok {
			return nil, errors.New("must be a boolean")
		}
		return json.Marshal(flag)
	}
}

// MergeParams is the parameters a mount runs with: the pack defaults,
// overlaid by overrides, then the rule-level states (true = enabled) applied
// to exclusions. Every key in the result is canonical.
func MergeParams(pack Pack, overrides Params, ruleStates map[string]bool) (Params, error) {
	merged := Params{}
	for name, value := range pack.Defaults {
		merged[name] = value
	}
	normalized, err := normalizeParams(pack, overrides, false)
	if err != nil {
		return nil, err
	}
	for name, value := range normalized {
		if name == ParamExclusions && overrides[ParamExclusions] == nil {
			continue
		}
		merged[name] = value
	}
	var excluded []string
	if err := json.Unmarshal(merged[ParamExclusions], &excluded); err != nil {
		return nil, fmt.Errorf("%w: exclusions", ErrInvalidPack)
	}
	set := map[string]bool{}
	for _, id := range excluded {
		set[id] = true
	}
	for id, enabled := range ruleStates {
		if !pack.Exported(id) {
			return nil, fmt.Errorf("%w: rule %s is not exported", ErrUnknownExport, id)
		}
		set[id] = !enabled
	}
	ids := make([]string, 0, len(set))
	for id, off := range set {
		if off {
			ids = append(ids, id)
		}
	}
	merged[ParamExclusions], _ = json.Marshal(sortUnique(ids))
	return merged, nil
}

// ErrUnknownExport: a rule-level state or exclusion names a rule the pack
// does not export.
var ErrUnknownExport = fmt.Errorf("%w: unknown export", ErrInvalidPack)

type typedParams struct {
	values     map[string]any
	exclusions map[string]bool
	excluded   []string
}

func parseParams(pack Pack, params Params) (typedParams, error) {
	out := typedParams{values: map[string]any{}, exclusions: map[string]bool{}}
	for name, value := range params {
		// Whitespace is not part of a value (json.Marshal compacts it, so it
		// never reaches a digest); anything else must already be canonical.
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, value); err != nil {
			return typedParams{}, fmt.Errorf("%w: param %s is not JSON", ErrInvalidPack, name)
		}
		raw := json.RawMessage(compacted.Bytes())
		canonical, err := normalizeParamValue(pack, name, raw)
		if err != nil || !bytes.Equal(canonical, raw) {
			return typedParams{}, fmt.Errorf("%w: param %s is invalid or not canonical", ErrInvalidPack, name)
		}
		if name == ParamExclusions {
			_ = json.Unmarshal(raw, &out.excluded)
			for _, id := range out.excluded {
				out.exclusions[id] = true
			}
			continue
		}
		switch pack.ParamsSchema[name].Type {
		case typeInteger:
			value, _ := strconv.ParseInt(string(raw), 10, 64)
			out.values[name] = value
		case typeString:
			var value string
			_ = json.Unmarshal(raw, &value)
			out.values[name] = value
		default:
			out.values[name] = string(raw) == "true"
		}
	}
	for name := range pack.ParamsSchema {
		if _, ok := out.values[name]; !ok {
			return typedParams{}, fmt.Errorf("%w: param %s missing", ErrInvalidPack, name)
		}
	}
	if _, ok := params[ParamExclusions]; !ok {
		return typedParams{}, fmt.Errorf("%w: exclusions missing", ErrInvalidPack)
	}
	return out, nil
}

// instantiate returns the rules a pack runs with params (canonical, complete):
// excluded and switched-off rules removed, parameters applied, each result
// re-validated by the node model.
func instantiate(pack Pack, params Params) ([]Rule, error) {
	typed, err := parseParams(pack, params)
	if err != nil {
		return nil, err
	}
	if IsCRSTuningPack(pack.PackID) {
		// Tuning entries are no node rules: the node renders every entry
		// into ModSecurity (TuningOf); exclusions are the entries a site
		// disables (c3 u=), resolved_sha256 covers them in the mount.
		return []Rule{}, nil
	}
	names := sortedParamNames(pack.ParamsSchema)
	rules := make([]Rule, 0, len(pack.Rules))
	for _, source := range pack.Rules {
		if pack.Engine != EngineModSecurity && typed.exclusions[source.ID] {
			continue
		}
		rule := Rule{ID: source.ID, Name: source.Name}
		switch {
		case source.WAF != nil:
			copied := copyWAFRule(*source.WAF)
			rule.WAF = &copied
		case source.CC != nil:
			copied := copyCCRule(*source.CC)
			rule.CC = &copied
		case source.App != nil:
			copied := *source.App
			rule.App = &copied
		default:
			copied := copyCRS(*source.CRS)
			rule.CRS = &copied
		}
		keep := true
		for _, name := range names {
			spec := pack.ParamsSchema[name]
			if !bindsRule(spec.Bind, rule.ID) {
				continue
			}
			if keep, err = applyBind(&rule, spec.Bind.Target, typed.values[name]); err != nil {
				return nil, fmt.Errorf("%w: rule %s param %s: %v", ErrInvalidPack, rule.ID, name, err)
			}
			if !keep {
				break
			}
		}
		if !keep {
			continue
		}
		if err := validateInstance(&rule, typed.excluded); err != nil {
			return nil, fmt.Errorf("%w: rule %s with these params: %v", ErrInvalidPack, rule.ID, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func applyBind(rule *Rule, target string, value any) (bool, error) {
	switch target {
	case "rule.enabled":
		return value.(bool), nil
	case "waf.action":
		rule.WAF.Action = edgeconfig.WAFAction(value.(string))
		rule.WAF.ActionConfig = nil
		switch rule.WAF.Action {
		case edgeconfig.WAFBlock:
			rule.WAF.Control = edgeconfig.WAFStop
		case edgeconfig.WAFChallenge:
			rule.WAF.Control = edgeconfig.WAFStop
			config := DefaultWAFChallenge
			rule.WAF.ActionConfig = &config
		case edgeconfig.WAFLog:
			rule.WAF.Control = edgeconfig.WAFContinue
		}
		return true, nil
	case "cc.action.kind":
		action := edgeconfig.CCV2Action{Kind: edgeconfig.CCV2ActionKind(value.(string))}
		rule.CC.Flow = edgeconfig.CCV2FlowStop
		switch action.Kind {
		case edgeconfig.CCV2ActionLog:
			rule.CC.Flow = edgeconfig.CCV2FlowContinue
		case edgeconfig.CCV2ActionChallenge:
			challenge := DefaultCCChallenge
			action.BanSeconds, action.Challenge = DefaultCCChallengeBanSeconds, &challenge
		}
		rule.CC.Action = action
		return true, nil
	case "cc.challenge.mode":
		rule.CC.Action.Challenge.Mode = value.(string)
		return true, nil
	case "waf.inspect.number":
		rule.WAF.Match.Inspect[numberInspect(rule.WAF)].Values = []string{strconv.FormatInt(value.(int64), 10)}
		return true, nil
	}
	number := uint32(value.(int64))
	cc := rule.CC
	switch target {
	case "cc.limit.requests":
		cc.Limit.Requests = number
	case "cc.limit.window_seconds":
		cc.Limit.WindowSeconds = number
	case "cc.limit.requests_per_uri":
		cc.Limit.PerURI = number
	case "cc.limit.rate_per_second":
		cc.Limit.RatePerSecond = number
	case "cc.limit.burst":
		cc.Limit.Burst = number
	case "cc.action.ban_seconds":
		cc.Action.BanSeconds = number
	case "cc.challenge.pass_seconds":
		cc.Action.Challenge.PassSeconds = number
	default:
		return false, fmt.Errorf("unknown target %s", target)
	}
	return true, nil
}

// numberInspect is the index of the rule's first inspect clause with a
// number operator, -1 without one (or without a waf body).
func numberInspect(rule *edgeconfig.WAFRule) int {
	if rule == nil {
		return -1
	}
	for index, inspect := range rule.Match.Inspect {
		if _, number := edgeconfig.WAFInspectOperator(inspect.Operator); number {
			return index
		}
	}
	return -1
}

func validateInstance(rule *Rule, excluded []string) error {
	switch {
	case rule.WAF != nil:
		_, err := edgeconfig.NormalizeSecurityRule(withRuleID(*rule.WAF, placeholderRuleID))
		return err
	case rule.CC != nil:
		return validateCCRule(*rule.CC)
	case rule.App != nil:
		return nil
	}
	ids := append([]int{}, rule.CRS.ExcludeIDs...)
	for _, id := range excluded {
		value, _ := strconv.Atoi(id)
		ids = append(ids, value)
	}
	sort.Ints(ids)
	unique := ids[:0]
	for index, id := range ids {
		if index == 0 || ids[index-1] != id {
			unique = append(unique, id)
		}
	}
	rule.CRS.ExcludeIDs = unique
	return validateCRS(*rule.CRS)
}

// probeParams compiles the pack at every boundary of every parameter (range
// ends, each enum value, both booleans), so no value the schema allows can
// produce a rule the node would refuse or a pack over budget.
func probeParams(pack Pack) error {
	for _, name := range sortedParamNames(pack.ParamsSchema) {
		spec := pack.ParamsSchema[name]
		var probes []json.RawMessage
		switch spec.Type {
		case typeInteger:
			probes = []json.RawMessage{json.RawMessage(strconv.FormatInt(*spec.Minimum, 10)),
				json.RawMessage(strconv.FormatInt(*spec.Maximum, 10))}
		case typeString:
			for _, value := range spec.Enum {
				encoded, _ := json.Marshal(value)
				probes = append(probes, encoded)
			}
		default:
			probes = []json.RawMessage{json.RawMessage("true"), json.RawMessage("false")}
		}
		for _, probe := range probes {
			params := Params{}
			for key, value := range pack.Defaults {
				params[key] = value
			}
			params[name] = probe
			rules, err := instantiate(pack, params)
			if err != nil {
				return fmt.Errorf("%w: param %s=%s does not compile: %v", ErrInvalidPack, name, probe, err)
			}
			cost, err := rulesCost(rules)
			if err != nil {
				return err
			}
			if err := cost.within(packBudget); err != nil {
				return fmt.Errorf("param %s=%s: %w", name, probe, err)
			}
		}
	}
	return nil
}

func sortUnique(values []string) []string {
	sort.Strings(values)
	out := make([]string, 0, len(values))
	for index, value := range values {
		if index == 0 || values[index-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsEngine(values []Engine, value Engine) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
