package rulepack

import (
	"errors"
	"strings"
	"testing"
)

// rule packs do not carry the WAF v6 conditions (/
// 0026 cover bound security policies only). A string set exists per tenant
// and has no pack-level content, and a pack has no WAF version requirement
// for the others, so a pack using one would reach v5 nodes; the pack is
// refused instead.
func TestCompileRejectsWAFV6Conditions(t *testing.T) {
	for name, value := range map[string]any{
		"string_sets":     []any{map[string]any{"set_id": "0190a000-0000-7000-8000-0000000000c7", "revision": 1, "target": "user_agent"}},
		"browser":         map[string]any{"names": []any{"google_chrome"}},
		"browser_version": map[string]any{"name": "google_chrome", "op": "lt", "version": []any{100, 0, 0}},
		"device":          map[string]any{"kinds": []any{"bot"}},
		"time":            map[string]any{"ranges": []any{[]any{1, 2}}},
	} {
		err := mutate(t, "system-sqli.json", func(d map[string]any) {
			firstRule(d)["waf"].(map[string]any)["match"].(map[string]any)[name] = value
		})
		if !errors.Is(err, ErrInvalidPack) || !strings.Contains(err.Error(), "rule packs") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
