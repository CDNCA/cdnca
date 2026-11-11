package contentrewrite

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestWriteLuaVectors: with CONTENTREWRITE_VECTORS=<file> it writes the
// cases cdnca_rewrite.lua must reproduce byte for byte
// (scripts/edge/content-rewrite-parity.sh runs them in OpenResty).
func TestWriteLuaVectors(t *testing.T) {
	file := os.Getenv("CONTENTREWRITE_VECTORS")
	if file == "" {
		t.Skip("CONTENTREWRITE_VECTORS not set")
	}
	css := sample()
	for index := range css.Rules {
		css.Rules[index].ContentTypes = []string{TypeCSS}
	}
	truncate := Settings{MaxBytes: MinMaxBytes, Rules: []Rule{
		{ID: "a", Enabled: true, Kind: KindReplace, Find: "abc", Replace: "X", ContentTypes: []string{TypeCSS}},
		{ID: "b", Enabled: true, Kind: KindReplace, Find: "X-", Replace: "Y", ContentTypes: []string{TypeCSS}},
	}}
	folded := Settings{Rules: []Rule{
		{ID: "i", Enabled: true, Kind: KindReplace, Find: "Hello $", Replace: "Bye $", IgnoreCase: true},
		{ID: "g", Enabled: true, Kind: KindReplace, Find: `(?:foo|ba[rz])(x?)`, Replace: "<$1|$0|$$>", Regex: true, Paths: []string{"/blog/*"}},
	}}
	cases := []struct {
		name     string
		settings Settings
		typeKey  string
		path     string
		body     string
	}{
		{"html", sample(), "html", "/", page},
		{"css", css, "css", "/", `a{background:url(HTTP://old.example.com/x.png)} b{src:url(//old.example.com/y)} c{u:url(http://site.example.org/z)} d{u:"http://x.old.example.com/"} e{u:url(http://old.example.com.:9/z)}`},
		{"truncate", truncate, "css", "/", strings.Repeat("abc-", int(MinMaxBytes)/4) + "abc-tail"},
		{"folded", folded, "html", "/blog/a.html", "hello $ HELLO $ foox barbaz <p>bazx</p> HeLLo $"},
		{"glob-miss", folded, "html", "/other", "hello $ foo"},
		{"long-tag", sample(), "html", "/", "<a href='http://old.example.com/" + strings.Repeat("x", MaxTag) + "'>" + "<a href=http://old.example.com/>"},
	}
	type vector struct {
		Name    string `json:"name"`
		Node    *Node  `json:"node"`
		Type    string `json:"type"`
		Path    string `json:"path"`
		Body    string `json:"body"`
		Want    string `json:"want"`
		Matched bool   `json:"matched"`
	}
	out := []vector{}
	for _, c := range cases {
		node := mustNode(t, c.settings, "site.example.org")
		active := node.Active(c.path, c.typeKey)
		want := c.body
		if len(active) > 0 {
			want = string(NewStream(node, active, c.typeKey).Write([]byte(c.body), true))
		}
		// the chunked Go result must agree before Lua is asked to
		if got, _ := run(node, c.typeKey, c.path, c.body, 3); len(active) > 0 && got != want {
			t.Fatalf("%s: chunked Go differs", c.name)
		}
		out = append(out, vector{c.name, node, c.typeKey, c.path, c.body, want, len(active) > 0})
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
