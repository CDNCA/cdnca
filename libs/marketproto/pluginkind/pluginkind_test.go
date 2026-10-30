package pluginkind

import "testing"

func TestValid(t *testing.T) {
	for _, k := range All {
		if !Valid(k) {
			t.Fatalf("Valid(%q) = false", k)
		}
	}
	for _, k := range []string{"", "waf_rule_pack", "edge_script", "Module"} {
		if Valid(k) {
			t.Fatalf("Valid(%q) = true", k)
		}
	}
}
