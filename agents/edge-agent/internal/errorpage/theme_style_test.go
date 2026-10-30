package errorpage

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
)

const themedStyle = "body { background-color: #f5f7f9; color: #515a6e; }\n.cf-card { border-radius: 4px; padding: 24px; }\n"

func themedPage(style, class string) string {
	return "<!doctype html><html><head><title>502</title><style>" + style + "</style></head><body><main class=\"" + class + "\"><h1>502</h1></main></body></html>"
}

// ADR 0007 §7.2: a theme-rendered default error page carries one canonical
// <style> and class attributes naming only classes that style declares; the
// handler pins that style by hash in the page's CSP.
func TestCompileAcceptsThemedPageAndPinsStyleHash(t *testing.T) {
	body := themedPage(themedStyle, "cf-card")
	artifact, err := Compile(testPolicy(testRule("themed", CategoryEdgeConnect, StatusMatch{Codes: []int{502}}, "text/html", body)), "")
	if err != nil {
		t.Fatalf("themed page rejected: %v", err)
	}
	resource, found := artifact.Lookup("", CategoryEdgeConnect, 502)
	if !found || resource.StyleHash != errorpagestyle.SourceHash(themedStyle) {
		t.Fatalf("style hash = %q found=%v", resource.StyleHash, found)
	}
	if !bytes.Contains(artifact.RuntimeLua, []byte(`style_hash = "`+resource.StyleHash+`"`)) {
		t.Fatalf("runtime lua does not carry the style hash:\n%s", artifact.RuntimeLua)
	}

	plain, err := Compile(testPolicy(testRule("plain", CategoryEdgeConnect, StatusMatch{Codes: []int{502}}, "text/plain", "down\n")), "")
	if err != nil || bytes.Contains(plain.RuntimeLua, []byte("style_hash")) {
		t.Fatalf("unstyled resource gained a style hash: %v", err)
	}
}

func TestCompileRejectsUnsafeThemedPages(t *testing.T) {
	cases := map[string]string{
		"undeclared class": themedPage(themedStyle, "cf-other"),
		"url in style":     themedPage(strings.Replace(themedStyle, "#f5f7f9", "url(https://x.test/a.png)", 1), "cf-card"),
		"import":           themedPage("@import \"https://x.test/a.css\";\n"+themedStyle, "cf-card"),
		"non canonical":    themedPage(strings.Replace(themedStyle, ": ", ":", 1), "cf-card"),
		"two styles":       strings.Replace(themedPage(themedStyle, "cf-card"), "</head>", "<style>"+themedStyle+"</style></head>", 1),
		"style in body":    strings.Replace(themedPage(themedStyle, "cf-card"), "<h1>", "<style>"+themedStyle+"</style><h1>", 1),
		"class no style":   "<!doctype html><html><head><title>x</title></head><body><main class=\"cf-card\">x</main></body></html>",
	}
	for name, body := range cases {
		policy := testPolicy(testRule("bad", CategoryEdgeConnect, StatusMatch{Codes: []int{502}}, "text/html", body))
		if _, err := Compile(policy, ""); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: unsafe themed page accepted: %v", name, err)
		}
	}
}
