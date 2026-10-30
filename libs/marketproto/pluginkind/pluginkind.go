// Package pluginkind is the single source of the plugin market kinds
// (ADR 0007 §8.5, market migration 030_plugin_kinds market_plugins_kind_030).
// market-service validates new plugins against it and control-api filters the
// buyer catalogue with it, so the two cannot drift again.
package pluginkind

// All lists the kinds in migration 030 order.
var All = []string{
	"module", "rule_pack", "dataset", "engine_module",
	"theme", "provider", "external_service", "ui_page",
}

// Valid reports whether kind is one of All.
func Valid(kind string) bool {
	for _, k := range All {
		if k == kind {
			return true
		}
	}
	return false
}
