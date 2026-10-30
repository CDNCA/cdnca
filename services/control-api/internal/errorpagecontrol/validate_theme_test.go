package errorpagecontrol

import (
	"errors"
	"strings"
	"testing"
)

const themedTestStyle = "body { background-color: #f5f7f9; color: #515a6e; }\n.cf-card { border-radius: 4px; padding: 24px; }\n"

func themedTestPage(style, class string) []byte {
	return []byte("<!doctype html><html><head><title>502</title><style>" + style +
		"</style></head><body><main class=\"" + class + "\"><h1>502</h1></main></body></html>")
}

// ADR 0007 §7.2: theme pages may carry class attributes naming declared
// classes and one control-generated <style>; uploads keep the strict rule.
func TestValidateThemedHTML(t *testing.T) {
	page := themedTestPage(themedTestStyle, "cf-card")
	if err := ValidateThemedHTML(page); err != nil {
		t.Fatalf("themed page rejected: %v", err)
	}
	// errpage-2: an uploaded asset may be a theme-shaped page too (an admin
	// saves an edited built-in page back).
	if err := validateStaticBody("text/html", page); err != nil {
		t.Fatalf("uploaded theme-shaped page rejected: %v", err)
	}
	cases := map[string][]byte{
		"undeclared class": themedTestPage(themedTestStyle, "cf-other"),
		"url":              themedTestPage(strings.Replace(themedTestStyle, "#f5f7f9", "url(https://x.test/a.png)", 1), "cf-card"),
		"import":           themedTestPage("@import \"https://x.test/a.css\";\n"+themedTestStyle, "cf-card"),
		"two styles":       []byte(strings.Replace(string(page), "</head>", "<style>"+themedTestStyle+"</style></head>", 1)),
		"style in body":    []byte(strings.Replace(string(page), "<h1>", "<style>"+themedTestStyle+"</style><h1>", 1)),
		"style attribute":  []byte(strings.Replace(string(page), "<h1>", "<h1 style=\"color:#000000\">", 1)),
		"img":              []byte(strings.Replace(string(page), "<h1>", "<img src=\"https://x.test/a.png\">", 1)),
		"link":             []byte(strings.Replace(string(page), "<title>", "<link rel=\"stylesheet\" href=\"https://x.test/a.css\"><title>", 1)),
		"template marker":  []byte(strings.Replace(string(page), "502</h1>", "{{status}}</h1>", 1)),
	}
	for name, body := range cases {
		if err := ValidateThemedHTML(body); !errors.Is(err, ErrUnsafeContent) {
			t.Errorf("%s: unsafe themed page accepted: %v", name, err)
		}
		if err := validateStaticBody("text/html", body); !errors.Is(err, ErrUnsafeContent) {
			t.Errorf("%s: unsafe uploaded page accepted: %v", name, err)
		}
	}
}
