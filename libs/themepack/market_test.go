package themepack

import (
	"encoding/json"
	"testing"
)

// PA-18: a theme sold on the plugin market is named after its plugin
// (market.<plugin id>), so it can never collide with an official, default or
// operator upload theme, and one plugin owns exactly one theme id.
func TestMarketThemeID(t *testing.T) {
	if got := MarketThemeID("io.cdnca.examples.slate-dark"); got != "market.io.cdnca.examples.slate-dark" {
		t.Fatalf("MarketThemeID = %q", got)
	}
	var document map[string]any
	if err := json.Unmarshal(BuiltinCatalog()[0].Raw, &document); err != nil {
		t.Fatal(err)
	}
	document["id"] = MarketThemeID("io.cdnca.examples.slate-dark")
	raw, _ := json.Marshal(document)
	pkg, err := Parse(raw)
	if err != nil {
		t.Fatalf("market theme id rejected: %v", err)
	}
	if plugin, ok := MarketThemePlugin(pkg.ID); !ok || plugin != "io.cdnca.examples.slate-dark" {
		t.Fatalf("plugin=%q ok=%v", plugin, ok)
	}
	for _, id := range []string{"market.", "market.IO.x", "market.io..x", "custom.x"} {
		if _, ok := MarketThemePlugin(id); ok {
			t.Errorf("%s accepted as a market theme", id)
		}
	}
}
