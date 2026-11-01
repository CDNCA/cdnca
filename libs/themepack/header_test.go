package themepack

import (
	"encoding/json"
	"strings"
	"testing"
)

// layout_slots.header picks the top bar's look. "dark" joins
// it to the dark sidebar (one L-shaped frame); a package without the slot
// keeps the light top bar and renders byte for byte as before (no "header"
// key in the document).
func renderedHeader(t *testing.T, raw []byte) (string, bool) {
	t.Helper()
	rendered, err := Render(raw)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Layout map[string]any `json:"layout"`
	}
	if err := json.Unmarshal(rendered.JSON, &document); err != nil {
		t.Fatal(err)
	}
	value, ok := document.Layout["header"].(string)
	return value, ok
}

func TestHeaderSlot(t *testing.T) {
	for _, mode := range []string{"light", "dark"} {
		raw := customPackage(t, func(d map[string]any) { d["layout_slots"].(map[string]any)["header"] = mode })
		if got, ok := renderedHeader(t, raw); !ok || got != mode {
			t.Errorf("header %q rendered as %q (present %v)", mode, got, ok)
		}
	}
	// Absent: omitted from the document, so older packages render unchanged.
	raw := customPackage(t, func(d map[string]any) { delete(d["layout_slots"].(map[string]any), "header") })
	if got, ok := renderedHeader(t, raw); ok {
		t.Errorf("absent header rendered as %q", got)
	}
	if strings.Contains(string(DefaultRendered().JSON), `"header"`) {
		t.Error("default theme document carries a header slot")
	}
	bad := customPackage(t, func(d map[string]any) { d["layout_slots"].(map[string]any)["header"] = "purple" })
	if _, err := Render(bad); err == nil || validationCode(t, err) != "layout_value" {
		t.Fatalf("header purple: %v", err)
	}
}
