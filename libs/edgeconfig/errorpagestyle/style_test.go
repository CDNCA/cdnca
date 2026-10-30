package errorpagestyle

import (
	"strings"
	"testing"
)

func sampleSheet() Sheet {
	return Sheet{Rules: []Rule{
		{Selector: "body", Declarations: []Declaration{
			{Property: "background-color", Value: "#f5f7f9"},
			{Property: "color", Value: "#515a6e"},
			{Property: "font-family", Value: `"Helvetica Neue", Arial, sans-serif`},
		}},
		{Selector: ".cf-card", Declarations: []Declaration{
			{Property: "border-radius", Value: "4px"},
			{Property: "padding", Value: "24px 32px"},
		}},
	}}
}

func TestRenderParseRoundTrip(t *testing.T) {
	sheet := sampleSheet()
	text, err := Render(sheet)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	parsed, err := Parse(text)
	if err != nil {
		t.Fatalf("parse canonical text: %v\n%s", err, text)
	}
	again, err := Render(parsed)
	if err != nil || again != text {
		t.Fatalf("round trip differs: %v\n%q\n%q", err, text, again)
	}
	classes := parsed.Classes()
	if _, ok := classes["cf-card"]; !ok || len(classes) != 1 {
		t.Fatalf("classes = %v", classes)
	}
}

func TestRejectsUnsafeOrNonCanonicalStyle(t *testing.T) {
	canonical, err := Render(sampleSheet())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"url":            strings.Replace(canonical, "#f5f7f9", "url(https://evil.example/x.png)", 1),
		"import":         "@import \"https://evil.example/a.css\";\n" + canonical,
		"expression":     strings.Replace(canonical, "#515a6e", "expression(alert(1))", 1),
		"escape":         strings.Replace(canonical, "#515a6e", `\75rl(x)`, 1),
		"comment":        "/* x */" + canonical,
		"unknown prop":   strings.Replace(canonical, "color:", "behavior:", 1),
		"bad selector":   strings.Replace(canonical, ".cf-card", "a[href]", 1),
		"star selector":  strings.Replace(canonical, "body", "*", 1),
		"non canonical":  strings.Replace(canonical, ": ", ":", 1),
		"upper hex":      strings.Replace(canonical, "#f5f7f9", "#F5F7F9", 1),
		"close tag":      strings.Replace(canonical, "#515a6e", "</style><script>", 1),
		"font url":       strings.Replace(canonical, "Arial", "url(x)", 1),
		"empty":          "",
		"angle in value": strings.Replace(canonical, "Arial", "<b>", 1),
	}
	for name, text := range cases {
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: unsafe style accepted:\n%s", name, text)
		}
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	bad := []Declaration{
		{Property: "color", Value: "red"},
		{Property: "padding", Value: "10vw"},
		{Property: "padding", Value: "1px 2px 3px 4px 5px"},
		{Property: "border-radius", Value: "-1px"},
		{Property: "font-weight", Value: "950"},
		{Property: "font-size", Value: "900px"},
		{Property: "display", Value: "contents;color:red"},
		{Property: "font-family", Value: "a(b)"},
	}
	for _, declaration := range bad {
		sheet := Sheet{Rules: []Rule{{Selector: "body", Declarations: []Declaration{declaration}}}}
		if _, err := Render(sheet); err == nil {
			t.Errorf("declaration %+v accepted", declaration)
		}
	}
}

func TestClassAttribute(t *testing.T) {
	declared := map[string]struct{}{"cf-card": {}, "cf-title": {}}
	if err := CheckClassAttribute("cf-card cf-title", declared); err != nil {
		t.Fatalf("declared classes rejected: %v", err)
	}
	for _, value := range []string{"", "cf-card other", "cf-card  cf-title", " cf-card", "cf-card\tx"} {
		if err := CheckClassAttribute(value, declared); err == nil {
			t.Errorf("class attribute %q accepted", value)
		}
	}
}

func TestSourceHashIsCSPStyleHash(t *testing.T) {
	// sha256("a{}") base64, computed independently.
	if got := SourceHash("a{}"); got != "sha256-X1RutGBrXCt9KkSaXMK7tHftWiRscFHOhxsS8tv8hBk=" {
		t.Fatalf("hash = %s", got)
	}
}
