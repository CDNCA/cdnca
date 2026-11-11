package contentrewrite

import (
	"errors"
	"strings"
	"testing"
)

func mustNode(t *testing.T, settings Settings, hosts ...string) *Node {
	t.Helper()
	normalized, err := Normalize(settings)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	node, err := Compile(normalized, hosts)
	if err != nil || node == nil {
		t.Fatalf("compile: %v %v", node, err)
	}
	return node
}

// run feeds body in chunks of size (0: one chunk).
func run(node *Node, typeKey, path, body string, size int) (string, *Stream) {
	stream := NewStream(node, node.Active(path, typeKey), typeKey)
	if size == 0 {
		return string(stream.Write([]byte(body), true)), stream
	}
	var out strings.Builder
	for start := 0; start < len(body); start += size {
		end := min(start+size, len(body))
		out.Write(stream.Write([]byte(body[start:end]), false))
	}
	out.Write(stream.Write(nil, true))
	return out.String(), stream
}

func sample() Settings {
	return Settings{Rules: []Rule{
		{ID: "l", Enabled: true, Kind: KindLink, FromHosts: []string{"Old.Example.com"}, ToHost: "www.example.com", Scheme: SchemeHTTPS},
		{ID: "h", Enabled: true, Kind: KindHTTPS, IncludeSiteDomains: true, Hosts: []string{"*.cdn.example.net"}},
		{ID: "r", Enabled: true, Kind: KindReplace, Find: "© 2025", Replace: "© 2026 $1"},
		{ID: "x", Enabled: true, Kind: KindReplace, Find: `item-([0-9]{1,4})`, Replace: "goods-$1", Regex: true},
		{ID: "off", Enabled: false, Kind: KindReplace, Find: "never", Replace: "x"},
	}}
}

const page = `<html><head><link href="http://old.example.com/a.css" rel=stylesheet>
<script>if (a<b && c>d) x="http://old.example.com/no"</script></head>
<body><a HREF='//old.example.com/p'>x</a><img srcset="http://a.cdn.example.net/1.png 1x, https://old.example.com/2.png 2x" src=http://site.example.org/i.png>
<form action="http://site.example.org:8080/f"></form><p title="href=http://old.example.com/t">item-12 item-12345 © 2025</p></body></html>`

const want = `<html><head><link href="https://www.example.com/a.css" rel=stylesheet>
<script>if (a<b && c>d) x="http://old.example.com/no"</script></head>
<body><a HREF='//www.example.com/p'>x</a><img srcset="https://a.cdn.example.net/1.png 1x, https://www.example.com/2.png 2x" src=https://site.example.org/i.png>
<form action="http://site.example.org:8080/f"></form><p title="href=http://old.example.com/t">goods-12 goods-12345 © 2026 $1</p></body></html>`

func TestHTMLRewriteAnyChunking(t *testing.T) {
	node := mustNode(t, sample(), "site.example.org")
	for _, size := range []int{0, 1, 2, 3, 7, 13, 64, 4096} {
		got, _ := run(node, "html", "/", page, size)
		if got != want {
			t.Fatalf("chunk %d:\n%s", size, got)
		}
	}
}

func TestRawRewriteCSS(t *testing.T) {
	settings := sample()
	for index := range settings.Rules {
		settings.Rules[index].ContentTypes = []string{TypeCSS}
	}
	node := mustNode(t, settings, "site.example.org")
	body := `a{background:url(HTTP://old.example.com/x.png)} b{src:url(//old.example.com/y)} c{u:url(http://site.example.org/z)} d{u:"http://x.old.example.com/"}`
	expected := `a{background:url(https://www.example.com/x.png)} b{src:url(//old.example.com/y)} c{u:url(https://site.example.org/z)} d{u:"http://x.old.example.com/"}`
	for _, size := range []int{0, 1, 5, 9} {
		if got, _ := run(node, "css", "/", body, size); got != expected {
			t.Fatalf("chunk %d:\n%s", size, got)
		}
	}
}

func TestTruncateKeepsOrder(t *testing.T) {
	node := mustNode(t, Settings{MaxBytes: MinMaxBytes, Rules: []Rule{
		{ID: "a", Enabled: true, Kind: KindReplace, Find: "abc", Replace: "X", ContentTypes: []string{TypeCSS}},
		{ID: "b", Enabled: true, Kind: KindReplace, Find: "X-", Replace: "Y", ContentTypes: []string{TypeCSS}},
	}})
	body := strings.Repeat("abc-", int(MinMaxBytes)/4) + "abc-tail"
	got, stream := run(node, "css", "/", body, 1000)
	// at the limit each stage's held bytes go out unchanged, the last
	// stage's first: stage 2 holds "X" (from the last "abc"), stage 1 "-"
	expected := strings.Repeat("Y", int(MinMaxBytes)/4-1) + "X-abc-tail"
	if got != expected || !stream.Truncated {
		t.Fatalf("truncated=%v len=%d tail=%q", stream.Truncated, len(got), got[len(got)-20:])
	}
}

func TestRestrictedPatterns(t *testing.T) {
	refused := []string{`a*`, `a+`, `a{2,}`, `^a`, `a$`, `\bx`, `(a{1,3}){1,3}`, `(?s).`, `a{1,65}`, `x?`, `é`, `[^\x00-\x7f]`, `.{1,64}.{1,64}.{1,64}.{1,64}.{1,64}.{1,64}.{1,64}.{1,64}.`}
	for _, source := range refused {
		if _, err := compilePattern(source, false); err == nil {
			t.Errorf("%q accepted", source)
		}
	}
	accepted := map[string]int{`item-([0-9]{1,4})`: 9, `(?:foo|ba[rz])x?`: 4, `a.b`: 3, `[^"]{2}`: 2}
	for source, maxLen := range accepted {
		compiled, err := compilePattern(source, false)
		if err != nil || compiled.maxLen != maxLen {
			t.Errorf("%q: %v max %d", source, err, compiled.maxLen)
		}
	}
	// canonical form: ASCII bytes only, the same matches as the source
	compiled, err := compilePattern(`k[a-c].`, true)
	if err != nil || compiled.source != `[\x4B\x6B][\x41-\x43\x61-\x63][\x00-\x09\x0B-\x7F]` {
		t.Fatalf("canonical %q %v", compiled.source, err)
	}
	if compiled.re.MatchString("K\u212a") || !compiled.re.MatchString("kB!") || compiled.re.MatchString("kb\u00e9") {
		t.Fatal("canonical pattern matches non-ASCII or misses ASCII")
	}
}

func TestNormalizeFieldErrors(t *testing.T) {
	cases := map[string]Rule{
		"rules[0].find":    {ID: "a", Kind: KindReplace, Find: "a+", Regex: true},
		"rules[0].replace": {ID: "a", Kind: KindReplace, Find: "(a)", Regex: true, Replace: "$2"},
		"rules[0].to_host": {ID: "a", Kind: KindLink, FromHosts: []string{"a.com"}, ToHost: "a.com"},
		"rules[0].paths":   {ID: "a", Kind: KindReplace, Find: "x", Paths: []string{"nope"}},
		"rules[0].hosts":   {ID: "a", Kind: KindHTTPS},
		"rules[0].kind":    {ID: "a", Kind: "insert"},
	}
	for field, rule := range cases {
		_, err := Normalize(Settings{Rules: []Rule{rule}})
		var refused *FieldError
		if !errors.As(err, &refused) || refused.Field != field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", field, err)
		}
	}
}

func TestPathMatches(t *testing.T) {
	cases := []struct {
		pattern, path string
		ok            bool
	}{
		{"/blog/", "/blog/a", true}, {"/blog/", "/blo", false}, {"/*.html", "/a/b.html", true},
		{"/*.html", "/a.htm", false}, {"/a*b*b", "/abb", true}, {"/a*b*b", "/ab", false}, {"*", "/x", true},
	}
	for _, c := range cases {
		if PathMatches([]string{c.pattern}, c.path) != c.ok {
			t.Errorf("%s %s", c.pattern, c.path)
		}
	}
}

func TestTesterReportsRules(t *testing.T) {
	settings, _ := Normalize(sample())
	result, err := Test(settings, []string{"site.example.org"}, "/", "text/html; charset=utf-8", []byte(page))
	if err != nil || result.Body != want || strings.Join(result.MatchedRules, ",") != "l,h,r,x" || result.Replacements != 8 {
		t.Fatalf("%v rules=%v n=%d same=%v", err, result.MatchedRules, result.Replacements, result.Body == want)
	}
	if result, _ := Test(settings, nil, "/", "image/png", []byte(page)); result.Body != page || len(result.MatchedRules) != 0 {
		t.Fatal("non-text type was rewritten")
	}
}
