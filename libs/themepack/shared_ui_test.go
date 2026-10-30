package themepack

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
)

// The four front ends take their theme from packages/cdnca-ui. Its token
// file and the defaults in its stylesheet must equal tokenSpecs, so this
// file stays the single source of the default look.
const sharedUIDir = "../../packages/cdnca-ui/src/"

func TestSharedUITokensMatchDefaults(t *testing.T) {
	raw, err := os.ReadFile(sharedUIDir + "tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	// "antd" holds the ConfigProvider tokens (TokenSpec.Antd), "css" the rest.
	var shared struct {
		Antd map[string]any `json:"antd"`
		CSS  map[string]any `json:"css"`
	}
	if err := json.Unmarshal(raw, &shared); err != nil {
		t.Fatal(err)
	}
	if len(shared.Antd)+len(shared.CSS) != len(tokenSpecs) {
		t.Errorf("tokens.json has %d tokens, tokens.go has %d", len(shared.Antd)+len(shared.CSS), len(tokenSpecs))
	}
	for _, spec := range tokenSpecs {
		group, name := shared.CSS, "css"
		if spec.Antd {
			group, name = shared.Antd, "antd"
		}
		if group[spec.Name] != spec.Default {
			t.Errorf("tokens.json %s.%s = %#v, tokens.go default %#v", name, spec.Name, group[spec.Name], spec.Default)
		}
	}
}

func TestSharedUIStylesheetDeclaresDefaults(t *testing.T) {
	css, err := os.ReadFile(sharedUIDir + "styles.css")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]string{}
	for _, match := range regexp.MustCompile(`(?m)^\s*(--cdnca-[a-z0-9-]+):\s*([^;]+);`).FindAllSubmatch(css, -1) {
		declared[string(match[1])] = string(match[2])
	}
	for _, spec := range tokenSpecs {
		name := CSSVariable(spec.Name)
		if want := cssValue(spec, spec.Default); declared[name] != want {
			t.Errorf("styles.css %s = %q, want %q", name, declared[name], want)
		}
	}
}

func TestRenderedCSSCarriesSharedAndLegacyNames(t *testing.T) {
	variables := cssVariables(DefaultRendered().Tokens)
	for name, want := range map[string]string{
		"--cdnca-color-primary": "#2d8cf0", "--cdnca-sidebar-width": "256px", "--cdnca-line-height": "1.5",
		"--cdnca-control-height": "32px", "--setting-primary": "#2d8cf0",
	} {
		if variables[name] != want {
			t.Errorf("%s = %q, want %q", name, variables[name], want)
		}
	}
	if got := CSSVariable("colorBgContainer"); got != "--cdnca-color-bg-container" {
		t.Errorf("CSSVariable = %q", got)
	}
}

// The theme customizer (apps/web theme management) edits tokens from
// apps/web/src/theme/tokenSpecs.json: kind, group, range, antd flag and CSS aliases
// must equal tokenSpecs (defaults come from tokens.json above).
func TestWebTokenSpecsMatch(t *testing.T) {
	raw, err := os.ReadFile("../../apps/web/src/theme/tokenSpecs.json")
	if err != nil {
		t.Fatal(err)
	}
	var web map[string]struct {
		Kind         string   `json:"kind"`
		Min          *float64 `json:"min"`
		Max          *float64 `json:"max"`
		Antd         bool     `json:"antd"`
		CSSVariables []string `json:"css_variables"`
		Group        string   `json:"group"`
	}
	if err := json.Unmarshal(raw, &web); err != nil {
		t.Fatal(err)
	}
	if len(web) != len(tokenSpecs) {
		t.Errorf("tokenSpecs.json has %d tokens, tokens.go has %d", len(web), len(tokenSpecs))
	}
	for _, spec := range tokenSpecs {
		got, ok := web[spec.Name]
		ranged := spec.Kind == TokenLength || spec.Kind == TokenNumber
		switch {
		case !ok:
			t.Errorf("tokenSpecs.json lacks %s", spec.Name)
		case got.Kind != string(spec.Kind) || got.Group != string(spec.Group) || got.Antd != spec.Antd || fmt.Sprint(got.CSSVariables) != fmt.Sprint(spec.CSSVariables):
			t.Errorf("tokenSpecs.json %s = %+v, tokens.go %+v", spec.Name, got, spec)
		case ranged && (got.Min == nil || got.Max == nil || *got.Min != spec.Min || *got.Max != spec.Max):
			t.Errorf("tokenSpecs.json %s range differs from tokens.go %v..%v", spec.Name, spec.Min, spec.Max)
		case !ranged && (got.Min != nil || got.Max != nil):
			t.Errorf("tokenSpecs.json %s has a range", spec.Name)
		}
	}
}

func TestEveryTokenHasAGroup(t *testing.T) {
	groups := map[TokenGroup]bool{GroupBase: true, GroupStatus: true, GroupTable: true, GroupChart: true, GroupDark: true, GroupScale: true}
	for _, spec := range tokenSpecs {
		if !groups[spec.Group] {
			t.Errorf("%s has group %q", spec.Name, spec.Group)
		}
	}
}
