package themepack

// Role tokens, layout look/motion and shadow validation (from the removed
// official.tech theme tests; the community edition ships only the default theme).

import (
	"encoding/json"
	"strings"
	"testing"
)

// The default theme keeps classic/off and renders a single block.
func TestDefaultThemeIsClassicWithoutRoleBlocks(t *testing.T) {
	rendered := DefaultRendered()
	if strings.Count(string(rendered.CSS), "{") != 1 {
		t.Fatalf("css = %s", rendered.CSS)
	}
	var document struct {
		Layout           map[string]any `json:"layout"`
		AntdTokensByRole map[string]any `json:"antd_tokens_by_role"`
	}
	if err := json.Unmarshal(rendered.JSON, &document); err != nil {
		t.Fatal(err)
	}
	if document.Layout["look"] != "classic" || document.Layout["motion"] != "off" || document.AntdTokensByRole != nil {
		t.Fatalf("document = %+v", document)
	}
}

func TestRoleTokensAndNewKindsValidate(t *testing.T) {
	ok := customPackage(t, func(d map[string]any) {
		d["tokens_by_role"] = map[string]any{"admin": map[string]any{"colorPrimary": "#123456", "shadowCard": "none"}}
		d["layout_slots"].(map[string]any)["look"] = "tech"
		d["layout_slots"].(map[string]any)["motion"] = "subtle"
	})
	rendered, err := Render(ok)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		AntdTokensByRole map[string]map[string]any `json:"antd_tokens_by_role"`
	}
	if err := json.Unmarshal(rendered.JSON, &document); err != nil {
		t.Fatal(err)
	}
	if document.AntdTokensByRole["admin"]["colorPrimary"] != "#123456" || len(document.AntdTokensByRole["admin"]) != 1 {
		t.Fatalf("antd by role = %+v", document.AntdTokensByRole)
	}
	if !strings.Contains(string(rendered.CSS), ":root[data-cdnca-theme][data-cdnca-role=\"admin\"] {\n  --cdnca-color-primary: #123456;\n") {
		t.Fatalf("css = %s", rendered.CSS)
	}
	cases := map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"unknown role": {func(d map[string]any) { d["tokens_by_role"] = map[string]any{"guest": map[string]any{}} }, "token_role"},
		"role unknown token": {func(d map[string]any) {
			d["tokens_by_role"] = map[string]any{"user": map[string]any{"colorDanger": "#ff0000"}}
		}, "token_unknown"},
		"role bad value": {func(d map[string]any) {
			d["tokens_by_role"] = map[string]any{"user": map[string]any{"colorPrimary": "blue"}}
		}, "token_value"},
		"bad look":   {func(d map[string]any) { d["layout_slots"].(map[string]any)["look"] = "neon" }, "layout_value"},
		"bad motion": {func(d map[string]any) { d["layout_slots"].(map[string]any)["motion"] = "max" }, "layout_value"},
		"shadow function": {func(d map[string]any) {
			d["tokens"].(map[string]any)["shadowCard"] = "0 1px var(--x) #000000"
		}, "token_value"},
		"shadow braces": {func(d map[string]any) {
			d["tokens"].(map[string]any)["shadowPopup"] = "0 1px 2px #000000; } body { color: #ff0000"
		}, "token_value"},
		"button weight range": {func(d map[string]any) { d["tokens"].(map[string]any)["buttonFontWeight"] = 900 }, "token_value"},
	}
	for name, test := range cases {
		_, err := Render(customPackage(t, test.mutate))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if code := validationCode(t, err); code != test.code {
			t.Errorf("%s: code %q, want %q", name, code, test.code)
		}
	}
	for _, shadow := range []string{"none", "0 1px 2px #000000", "inset 0 0 0 1px rgb(37 99 235 / 24%), 0 -1px 0 #ffffff"} {
		if !validShadow(shadow) {
			t.Errorf("%q rejected", shadow)
		}
	}
}

// A shadow token can never reach an error page: no errorpagestyle property
// takes a shadow, so "token:shadowCard" fails the declaration check.
func TestShadowTokenNotUsableInTemplates(t *testing.T) {
	_, err := Render(customPackage(t, func(d map[string]any) { firstStyle(d)["color"] = "token:shadowCard" }))
	if err == nil || validationCode(t, err) != "style_value" {
		t.Fatalf("err = %v", err)
	}
}
