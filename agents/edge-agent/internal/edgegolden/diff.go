package edgegolden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// RulesSchema names the compare rules file.
const RulesSchema = "cdnca.edge-golden.compare/v1"

// Rules say which differences are not defects.
type Rules struct {
	Schema string `json:"schema"`
	// Incomparable paths differ by construction for every runtime (an
	// implementation detail the golden records for reading only).
	Incomparable []Rule `json:"incomparable"`
	// SemanticChanges are the documented behaviour changes of a runtime
	// (ADR 0009 §6); they waive a difference only for the renderers listed.
	SemanticChanges []Rule `json:"semantic_changes"`
}

// Rule matches observation paths "<scenario>/<step>/<field>/...": "*" is one
// segment (path.Match syntax within it), "**" any number; a rule that
// matches a prefix of a path covers the whole subtree.
type Rule struct {
	Path      string   `json:"path"`
	Reason    string   `json:"reason"`
	Renderers []string `json:"renderers,omitempty"`
}

func LoadRules(file string) (Rules, error) {
	if file == "" {
		return Rules{Schema: RulesSchema}, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return Rules{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var rules Rules
	if err := decoder.Decode(&rules); err != nil || rules.Schema != RulesSchema {
		return Rules{}, fmt.Errorf("%s: not a %s file: %v", file, RulesSchema, err)
	}
	for _, rule := range append(append([]Rule(nil), rules.Incomparable...), rules.SemanticChanges...) {
		if rule.Path == "" || rule.Reason == "" {
			return Rules{}, fmt.Errorf("%s: every rule needs path and reason", file)
		}
		for _, segment := range strings.Split(rule.Path, "/") {
			if _, err := path.Match(segment, ""); err != nil {
				return Rules{}, fmt.Errorf("%s: rule %q: %w", file, rule.Path, err)
			}
		}
	}
	return rules, nil
}

// Difference is one value that differs between expected and actual.
type Difference struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"` // changed, missing, extra
	Expected any    `json:"expected,omitempty"`
	Actual   any    `json:"actual,omitempty"`
	// Waived names why the difference is not a defect; empty for a defect.
	Waived string `json:"waived,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// ScenarioReport is the comparison of one scenario.
type ScenarioReport struct {
	Scenario    string       `json:"scenario"`
	Status      string       `json:"status"` // same, different, skipped, no_golden, stale_golden, error
	Detail      string       `json:"detail,omitempty"`
	Differences []Difference `json:"differences,omitempty"`
}

// Report is a whole comparison.
type Report struct {
	Renderer  string           `json:"renderer"`
	Expected  string           `json:"expected"`
	Scenarios []ScenarioReport `json:"scenarios"`
}

// Defects counts the differences no rule waives plus scenarios that could
// not be compared (missing or stale golden, errors).
func (report *Report) Defects() int {
	count := 0
	for _, scenario := range report.Scenarios {
		switch scenario.Status {
		case "no_golden", "stale_golden", "error":
			count++
		}
		for _, difference := range scenario.Differences {
			if difference.Waived == "" {
				count++
			}
		}
	}
	return count
}

// Compare diffs actual against expected; steps are matched by ID.
func Compare(rules Rules, renderer string, expected, actual *Observation) (ScenarioReport, error) {
	report := ScenarioReport{Scenario: expected.Scenario, Status: "same"}
	if expected.Digest != actual.Digest {
		report.Status, report.Detail = "stale_golden", "the scenario changed after the golden was recorded: record again"
		return report, nil
	}
	left, err := stepsByID(expected)
	if err != nil {
		return report, err
	}
	right, err := stepsByID(actual)
	if err != nil {
		return report, err
	}
	walk(expected.Scenario, left, right, &report.Differences)
	for index := range report.Differences {
		difference := &report.Differences[index]
		if rule, ok := matchRule(rules.Incomparable, difference.Path, ""); ok {
			difference.Waived, difference.Reason = "incomparable", rule.Reason
		} else if rule, ok := matchRule(rules.SemanticChanges, difference.Path, renderer); ok {
			difference.Waived, difference.Reason = "semantic_change", rule.Reason
		}
	}
	if len(report.Differences) != 0 {
		report.Status = "different"
	}
	return report, nil
}

func stepsByID(observation *Observation) (map[string]any, error) {
	steps := map[string]any{}
	for _, step := range observation.Steps {
		raw, err := json.Marshal(step)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		steps[step.ID] = value
	}
	return steps, nil
}

func walk(at string, expected, actual any, differences *[]Difference) {
	switch left := expected.(type) {
	case map[string]any:
		right, ok := actual.(map[string]any)
		if !ok {
			*differences = append(*differences, Difference{Path: at, Kind: "changed", Expected: expected, Actual: actual})
			return
		}
		keys := map[string]bool{}
		for key := range left {
			keys[key] = true
		}
		for key := range right {
			keys[key] = true
		}
		for _, key := range sortedKeys(keys) {
			child := at + "/" + key
			leftValue, inLeft := left[key]
			rightValue, inRight := right[key]
			switch {
			case !inRight:
				*differences = append(*differences, Difference{Path: child, Kind: "missing", Expected: leftValue})
			case !inLeft:
				*differences = append(*differences, Difference{Path: child, Kind: "extra", Actual: rightValue})
			default:
				walk(child, leftValue, rightValue, differences)
			}
		}
	case []any:
		right, ok := actual.([]any)
		if !ok {
			*differences = append(*differences, Difference{Path: at, Kind: "changed", Expected: expected, Actual: actual})
			return
		}
		for index := 0; index < max(len(left), len(right)); index++ {
			child := at + "/" + strconv.Itoa(index)
			switch {
			case index >= len(right):
				*differences = append(*differences, Difference{Path: child, Kind: "missing", Expected: left[index]})
			case index >= len(left):
				*differences = append(*differences, Difference{Path: child, Kind: "extra", Actual: right[index]})
			default:
				walk(child, left[index], right[index], differences)
			}
		}
	default:
		if fmt.Sprint(expected) != fmt.Sprint(actual) || fmt.Sprintf("%T", expected) != fmt.Sprintf("%T", actual) {
			*differences = append(*differences, Difference{Path: at, Kind: "changed", Expected: expected, Actual: actual})
		}
	}
}

func matchRule(rules []Rule, at, renderer string) (Rule, bool) {
	segments := strings.Split(at, "/")
	for _, rule := range rules {
		if renderer != "" && !contains(rule.Renderers, renderer) && !contains(rule.Renderers, "*") {
			continue
		}
		pattern := strings.Split(rule.Path, "/")
		for end := len(segments); end > 0; end-- {
			if matchSegments(pattern, segments[:end]) {
				return rule, true
			}
		}
	}
	return Rule{}, false
}

func matchSegments(pattern, segments []string) bool {
	if len(pattern) == 0 {
		return len(segments) == 0
	}
	if pattern[0] == "**" {
		for skip := 0; skip <= len(segments); skip++ {
			if matchSegments(pattern[1:], segments[skip:]) {
				return true
			}
		}
		return false
	}
	if len(segments) == 0 {
		return false
	}
	matched, err := path.Match(pattern[0], segments[0])
	return err == nil && matched && matchSegments(pattern[1:], segments[1:])
}

// WriteText writes a readable report.
func (report *Report) WriteText(output io.Writer) {
	fmt.Fprintf(output, "cdnca edge golden: renderer %s against %s\n", report.Renderer, report.Expected)
	counts := map[string]int{}
	waived := 0
	for _, scenario := range report.Scenarios {
		counts[scenario.Status]++
		defects := 0
		for _, difference := range scenario.Differences {
			if difference.Waived == "" {
				defects++
			} else {
				waived++
			}
		}
		line := fmt.Sprintf("%-14s %s", strings.ToUpper(scenario.Status), scenario.Scenario)
		if len(scenario.Differences) != 0 {
			line += fmt.Sprintf(" (%d differences, %d waived)", defects, len(scenario.Differences)-defects)
		}
		if scenario.Detail != "" {
			line += ": " + scenario.Detail
		}
		fmt.Fprintln(output, line)
		for _, difference := range scenario.Differences {
			label := "  DIFF"
			if difference.Waived != "" {
				label = "  WAIVED(" + difference.Waived + ")"
			}
			fmt.Fprintf(output, "%s %s [%s] expected=%s actual=%s\n", label, difference.Path, difference.Kind,
				brief(difference.Expected), brief(difference.Actual))
			if difference.Reason != "" {
				fmt.Fprintf(output, "      reason: %s\n", difference.Reason)
			}
		}
	}
	statuses := make([]string, 0, len(counts))
	for _, status := range []string{"same", "different", "skipped", "no_golden", "stale_golden", "error"} {
		if counts[status] != 0 {
			statuses = append(statuses, fmt.Sprintf("%s=%d", status, counts[status]))
		}
	}
	sort.Strings(statuses)
	fmt.Fprintf(output, "summary: %d scenarios (%s), %d defects, %d waived\n", len(report.Scenarios), strings.Join(statuses, " "),
		report.Defects(), waived)
}

func brief(value any) string {
	if value == nil {
		return "-"
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	if len(raw) > 160 {
		return string(raw[:157]) + "..."
	}
	return string(raw)
}
