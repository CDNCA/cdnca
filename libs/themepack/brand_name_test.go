package themepack

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// fix-e1 #6: a theme package may name the product the consoles show; the
// rendered document carries it, and packages without it render as before.
func TestBrandNameRendersAndIsOptional(t *testing.T) {
	plain, err := Render(customPackage(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain.JSON, []byte("brand_name")) {
		t.Fatalf("package without brand_name renders it: %s", plain.JSON)
	}
	named, err := Render(customPackage(t, func(d map[string]any) {
		d["layout_slots"].(map[string]any)["brand_name"] = map[string]any{"zh-CN": "示例云", "en-US": "Example Cloud"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Layout struct {
			BrandName map[string]string `json:"brand_name"`
		} `json:"layout"`
	}
	if err := json.Unmarshal(named.JSON, &document); err != nil {
		t.Fatal(err)
	}
	if document.Layout.BrandName["zh-CN"] != "示例云" || document.Layout.BrandName["en-US"] != "Example Cloud" {
		t.Fatalf("brand_name = %v", document.Layout.BrandName)
	}
	for name, value := range map[string]any{
		"no zh-CN":  map[string]any{"en-US": "Example"},
		"too long":  map[string]any{"zh-CN": strings.Repeat("云", 65)},
		"untrimmed": map[string]any{"zh-CN": " 示例云"},
	} {
		_, err := Render(customPackage(t, func(d map[string]any) {
			d["layout_slots"].(map[string]any)["brand_name"] = value
		}))
		if err == nil {
			t.Errorf("%s: brand_name accepted", name)
		}
	}
}
