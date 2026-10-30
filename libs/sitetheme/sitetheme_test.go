package sitetheme

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestV1Compatible(t *testing.T) {
	raw := encode(t, v1Package())
	pkg, images, err := ParseV1(raw)
	if err != nil {
		t.Fatalf("v1 rejected: %v", err)
	}
	if pkg.Layout != "xmf" || len(images) != 1 || images[0].Slot != "logo" || images[0].SHA256 != sum(svgBody) {
		t.Fatalf("v1 parse: %+v %+v", pkg, images)
	}
	theme, err := Parse(raw, thirdParty())
	if err != nil {
		t.Fatalf("Parse v1: %v", err)
	}
	if theme.Schema != SchemaV1 || !reflect.DeepEqual(theme.AppliesTo, []Scope{ScopeSite}) || theme.V1 == nil ||
		theme.V1.ID != "custom.orange" || !theme.Allows(ScopeSite) || theme.Allows(ScopeUser) || theme.Allows(ScopeAdmin) ||
		theme.Bundle != nil || theme.Console != nil {
		t.Fatalf("v1 theme: %+v", theme)
	}
	var nilTheme *Theme
	if nilTheme.Allows(ScopeSite) {
		t.Fatal("nil theme allows")
	}
}

// The v1 rejections controlsite has always made, with the same codes.
func TestV1Rejects(t *testing.T) {
	svg := func(body string) map[string]any {
		return map[string]any{"mime_type": "image/svg+xml", "body_base64": b64(body)}
	}
	images := func(v map[string]any) map[string]any { return v["images"].(map[string]any) }
	brand := func(v map[string]any) map[string]any { return v["seed"].(map[string]any)["brand"].(map[string]any) }
	for name, test := range map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"schema":        {func(v map[string]any) { v["schema"] = "cdnca.theme/v1" }, "schema"},
		"id":            {func(v map[string]any) { v["id"] = "evil" }, "id"},
		"version":       {func(v map[string]any) { v["version"] = "1.0" }, "version"},
		"layout":        {func(v map[string]any) { v["layout"] = "custom" }, "layout"},
		"script field":  {func(v map[string]any) { v["script"] = "alert(1)" }, "package_json"},
		"unknown token": {func(v map[string]any) { v["tokens"] = map[string]any{"background": "#ffffff"} }, "token"},
		"css injection": {func(v map[string]any) { v["tokens"] = map[string]any{"colorPrimary": "red;background:url(https://x)"} }, "token"},
		"font url":      {func(v map[string]any) { v["tokens"] = map[string]any{"fontFamily": "url(https://x)"} }, "token"},
		"svg script":    {func(v map[string]any) { images(v)["logo"] = svg(`<svg><script>alert(1)</script></svg>`) }, "image_body"},
		"svg handler":   {func(v map[string]any) { images(v)["logo"] = svg(`<svg onload="x()"/>`) }, "image_body"},
		"svg external":  {func(v map[string]any) { images(v)["logo"] = svg(`<svg><image href="https://x/a.png"/></svg>`) }, "image_body"},
		"bad slot":      {func(v map[string]any) { images(v)["Bad_Slot"] = svg(svgBody) }, "image_slot"},
		"seed external": {func(v map[string]any) { brand(v)["logo"] = "https://example.com/x.png" }, "seed"},
		"seed asset":    {func(v map[string]any) { brand(v)["logo"] = "asset:" + strings.Repeat("a", 64) }, "seed"},
		"seed bad slot": {func(v map[string]any) { brand(v)["logo"] = "theme:missing" }, "seed"},
		"name markup":   {func(v map[string]any) { v["name"] = map[string]any{"zh-CN": "<b>x</b>"} }, "i18n_value"},
		"name missing":  {func(v map[string]any) { delete(v, "name") }, "i18n_required"},
	} {
		pkg := v1Package()
		test.mutate(pkg)
		_, _, err := ParseV1(encode(t, pkg))
		expectCode(t, name, err, test.code)
		_, err = Parse(encode(t, pkg), official())
		expectCode(t, "Parse "+name, err, test.code)
	}
	if _, _, err := ParseV1([]byte(`{"schema":"cdnca.site-theme/v1","schema":"x"}`)); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	if _, _, err := ParseV1(append(encode(t, v1Package()), []byte(` {}`)...)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

// The control plane's own built-in packages must still parse unchanged.
func TestV1BuiltinSeeds(t *testing.T) {
	for _, layout := range []string{"jidun", "xmf"} {
		raw, err := os.ReadFile("../../services/control-api/internal/controlsite/seed/" + layout + ".json")
		if err != nil {
			t.Skipf("seed not found: %v", err)
		}
		var seed SeedContent
		if err := json.Unmarshal(raw, &seed); err != nil {
			t.Fatal(err)
		}
		if !ValidateSeed(seed, nil) {
			t.Fatalf("%s seed rejected", layout)
		}
		refs, ok := ValidateContent(seed.Brand, seed.Contact, map[string]LayoutContent{layout: seed.LayoutContent})
		if !ok || len(refs) != 0 {
			t.Fatalf("%s content rejected", layout)
		}
	}
	if _, ok := ValidateContent(Brand{Name: "x"}, Contact{}, map[string]LayoutContent{"other": {}}); ok {
		t.Fatal("unknown layout accepted")
	}
}

func TestV2Valid(t *testing.T) {
	theme, err := Parse(encode(t, fixtureV2()), thirdParty())
	if err != nil {
		t.Fatalf("v2 rejected: %v", err)
	}
	if theme.Schema != SchemaV2 || theme.ID != "market.acme.blue" || theme.Version != "1.2.3" ||
		!reflect.DeepEqual(theme.AppliesTo, []Scope{ScopeUser, ScopeSite}) || theme.V1 != nil {
		t.Fatalf("theme: %+v", theme)
	}
	if !theme.Allows(ScopeUser) || !theme.Allows(ScopeSite) || theme.Allows(ScopeAdmin) {
		t.Fatal("Allows")
	}
	var console map[string]any
	if json.Unmarshal(theme.Console, &console) != nil || console["schema"] != ConsoleSchema {
		t.Fatalf("console: %s", theme.Console)
	}
	if theme.Bundle == nil || theme.Bundle.Entry != DefaultEntry || len(theme.Bundle.Files) != 4 {
		t.Fatalf("bundle: %+v", theme.Bundle)
	}
	for i, f := range theme.Bundle.Files {
		if i > 0 && theme.Bundle.Files[i-1].Path >= f.Path {
			t.Fatal("files not sorted")
		}
		if f.SHA256 != sum(string(f.Data)) || f.Size != int64(len(f.Data)) {
			t.Fatalf("file %s metadata", f.Path)
		}
	}
	if theme.AuthStyle == nil || len(theme.AuthStyle.Images) != 1 || theme.AuthStyle.Images[0].MIMEType != "image/png" {
		t.Fatalf("auth style: %+v", theme.AuthStyle)
	}
	if len(theme.ContentSchema) != 6 || theme.ContentSchema[5].Type != FieldList || len(theme.ContentSchema[5].Fields) != 2 {
		t.Fatalf("content schema: %+v", theme.ContentSchema)
	}
}

// applies_to: third parties get user+site, user and site; the official
// publisher additionally the admin sets. Order in the package is free.
func TestAppliesTo(t *testing.T) {
	userOnly := func(pkg map[string]any) {
		delete(pkg, "site_bundle")
		delete(pkg, "content_schema")
	}
	siteOnly := func(pkg map[string]any) { delete(pkg, "console_theme") }
	adminConsole := func(pkg map[string]any) {
		pkg["console_theme"].(map[string]any)["tokens_by_role"] = map[string]any{"admin": map[string]any{"colorPrimary": "#000000"}}
	}
	cases := []struct {
		name      string
		scopes    []any
		mutate    func(map[string]any)
		publisher Publisher
		want      []Scope
		code      string
	}{
		{"third user+site", []any{"site", "user"}, nil, PublisherThirdParty, []Scope{ScopeUser, ScopeSite}, ""},
		{"third user", []any{"user"}, userOnly, PublisherThirdParty, []Scope{ScopeUser}, ""},
		{"third site", []any{"site"}, siteOnly, PublisherThirdParty, []Scope{ScopeSite}, ""},
		{"third admin", []any{"admin"}, userOnly, PublisherThirdParty, nil, "admin_forbidden"},
		{"third admin+user", []any{"admin", "user"}, userOnly, PublisherThirdParty, nil, "admin_forbidden"},
		{"third admin+user+site", []any{"admin", "user", "site"}, nil, PublisherThirdParty, nil, "admin_forbidden"},
		{"third empty", []any{}, nil, PublisherThirdParty, nil, "applies_to"},
		{"third missing", nil, nil, PublisherThirdParty, nil, "applies_to"},
		{"unknown scope", []any{"operator"}, nil, PublisherThirdParty, nil, "applies_to"},
		{"duplicate", []any{"user", "user"}, nil, PublisherThirdParty, nil, "applies_to"},
		{"case", []any{"User"}, nil, PublisherThirdParty, nil, "applies_to"},
		{"official admin", []any{"admin"}, func(p map[string]any) { userOnly(p); adminConsole(p) }, PublisherOfficial, []Scope{ScopeAdmin}, ""},
		{"official admin+user", []any{"user", "admin"}, func(p map[string]any) { userOnly(p); adminConsole(p) }, PublisherOfficial, []Scope{ScopeAdmin, ScopeUser}, ""},
		{"official admin+user+site", []any{"admin", "user", "site"}, adminConsole, PublisherOfficial, []Scope{ScopeAdmin, ScopeUser, ScopeSite}, ""},
		{"official user+site", []any{"user", "site"}, nil, PublisherOfficial, []Scope{ScopeUser, ScopeSite}, ""},
		{"official admin+site", []any{"admin", "site"}, adminConsole, PublisherOfficial, nil, "applies_to"},
	}
	for _, c := range cases {
		pkg := fixtureV2()
		if c.scopes == nil {
			delete(pkg, "applies_to")
		} else {
			pkg["applies_to"] = c.scopes
		}
		if c.mutate != nil {
			c.mutate(pkg)
		}
		theme, err := Parse(encode(t, pkg), ParseOptions{Publisher: c.publisher})
		if c.code != "" {
			expectCode(t, c.name, err, c.code)
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(theme.AppliesTo, c.want) {
			t.Errorf("%s: applies_to %v, want %v", c.name, theme.AppliesTo, c.want)
		}
	}
}

// The zero ParseOptions is third party: the strict rules by default.
func TestDefaultPublisherIsThirdParty(t *testing.T) {
	pkg := fixtureV2()
	pkg["applies_to"] = []any{"admin", "user", "site"}
	_, err := Parse(encode(t, pkg), ParseOptions{})
	expectCode(t, "zero options", err, "admin_forbidden")
	pkg = fixtureV2()
	pkg["id"] = "official.site-blue"
	_, err = Parse(encode(t, pkg), ParseOptions{})
	expectCode(t, "official id", err, "id")
	v1 := v1Package()
	v1["id"] = "official.site-jidun"
	_, err = Parse(encode(t, v1), ParseOptions{})
	expectCode(t, "official v1 id", err, "id")
	if _, err := Parse(encode(t, v1), official()); err != nil {
		t.Fatalf("official v1: %v", err)
	}
}

// A console theme of a third party (or an official one not declaring admin)
// may not carry admin tokens or an admin scope anywhere.
func TestConsoleAdminRejected(t *testing.T) {
	console := func(pkg map[string]any) map[string]any { return pkg["console_theme"].(map[string]any) }
	cases := map[string]func(map[string]any){
		"tokens_by_role.admin": func(p map[string]any) {
			console(p)["tokens_by_role"] = map[string]any{"admin": map[string]any{"colorPrimary": "#000000"}}
		},
		"empty admin role": func(p map[string]any) { console(p)["tokens_by_role"] = map[string]any{"admin": map[string]any{}} },
		"scope field":      func(p map[string]any) { console(p)["scope"] = "admin" },
		"scopes list":      func(p map[string]any) { console(p)["scopes"] = []any{"user", "admin"} },
		"applies_to":       func(p map[string]any) { console(p)["applies_to"] = "admin+user" },
		"nested role":      func(p map[string]any) { console(p)["extra"] = map[string]any{"roles": []any{"admin"}} },
		"role selector": func(p map[string]any) {
			console(p)["templates"] = map[string]any{"styles": []any{map[string]any{"selector": `html[data-cdnca-role="admin"] .x`}}}
		},
		"selector unquoted": func(p map[string]any) { console(p)["x"] = "[data-cdnca-role=ADMIN]" },
	}
	for name, mutate := range cases {
		pkg := fixtureV2()
		mutate(pkg)
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, "third "+name, err, "admin_forbidden")
		_, err = Parse(encode(t, pkg), official())
		expectCode(t, "official user+site "+name, err, "console_admin")
	}
	// "administrator" in free text is not an admin scope.
	pkg := fixtureV2()
	console(pkg)["description"] = map[string]any{"zh-CN": "适合 administrator 与 sysadmin 阅读"}
	if _, err := Parse(encode(t, pkg), thirdParty()); err != nil {
		t.Fatalf("free text admin word: %v", err)
	}
}

func TestConsoleTheme(t *testing.T) {
	cases := map[string]struct {
		value any
		code  string
	}{
		"not object":   {[]any{1}, "console_theme"},
		"string":       {"x", "console_theme"},
		"no schema":    {map[string]any{"id": "x"}, "console_theme_schema"},
		"wrong schema": {map[string]any{"schema": "cdnca.theme/v2"}, "console_theme_schema"},
		"bad roles":    {map[string]any{"schema": ConsoleSchema, "tokens_by_role": "admin"}, "console_theme"},
	}
	for name, c := range cases {
		pkg := fixtureV2()
		pkg["console_theme"] = c.value
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, name, err, c.code)
	}
	pkg := fixtureV2()
	pkg["console_theme"] = nil
	_, err := Parse(encode(t, pkg), thirdParty())
	expectCode(t, "null console for user", err, "console_theme_required")
	pkg = fixtureV2()
	delete(pkg, "console_theme")
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "missing console for user", err, "console_theme_required")
	pkg = fixtureV2()
	pkg["applies_to"] = []any{"site"}
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "console for site only", err, "console_theme_unexpected")
	pkg = fixtureV2()
	pkg["applies_to"] = []any{"user"}
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "bundle for user only", err, "site_bundle_unexpected")
	pkg = fixtureV2()
	delete(pkg, "site_bundle")
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "site without bundle", err, "site_bundle_required")
	pkg = fixtureV2()
	pkg["applies_to"] = []any{"user"}
	delete(pkg, "site_bundle")
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "content schema for user only", err, "content_schema_unexpected")
}

func TestV2Envelope(t *testing.T) {
	cases := map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"unknown field": {func(p map[string]any) { p["script"] = "x" }, "package_json"},
		"bad id":        {func(p map[string]any) { p["id"] = "acme" }, "id"},
		"bad version":   {func(p map[string]any) { p["version"] = "v1" }, "version"},
		"name markup":   {func(p map[string]any) { p["name"] = map[string]any{"zh-CN": "<i>x</i>"} }, "i18n_value"},
		"no name":       {func(p map[string]any) { delete(p, "name") }, "i18n_required"},
		"bundle field":  {func(p map[string]any) { p["site_bundle"].(map[string]any)["url"] = "https://x" }, "package_json"},
		"file field":    {func(p map[string]any) { bundleFiles(p)[0].(map[string]any)["url"] = "https://x" }, "package_json"},
	}
	for name, c := range cases {
		pkg := fixtureV2()
		c.mutate(pkg)
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, name, err, c.code)
	}
	for name, raw := range map[string]string{
		"empty": "", "not json": "{", "array": "[]", "unknown schema": `{"schema":"cdnca.site-theme/v3"}`,
		"duplicate": `{"schema":"cdnca.site-theme/v2","schema":"cdnca.site-theme/v2"}`, "invalid utf8": "{\"schema\":\"\xff\"}",
	} {
		if _, err := Parse([]byte(raw), thirdParty()); err == nil {
			t.Errorf("%s accepted", name)
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v is not ErrInvalid", name, err)
		}
	}
	var e *Error
	_, err := Parse([]byte(`{"schema":"cdnca.site-theme/v3"}`), thirdParty())
	if !errors.As(err, &e) || e.Code != "site_theme.schema" || e.Field != "schema" || !strings.Contains(e.Error(), "schema") {
		t.Fatalf("schema error: %v", err)
	}
}

func TestSize(t *testing.T) {
	big := strings.Repeat("a", MaxContentBytes+1)
	_, err := Parse([]byte(big), thirdParty())
	expectCode(t, "over limit", err, "package_size")
	_, _, err = ParseV1([]byte(big))
	expectCode(t, "v1 over limit", err, "package_size")
	// A package just under the limit with a large image file parses.
	pkg := fixtureV2()
	body := pngBody + strings.Repeat("x", 5<<20)
	withFile("assets/big.png", body)(pkg)
	raw := encode(t, pkg)
	if len(raw) >= MaxContentBytes {
		t.Fatalf("fixture too large: %d", len(raw))
	}
	if _, err := Parse(raw, thirdParty()); err != nil {
		t.Fatalf("large bundle rejected: %v", err)
	}
	pkg = fixtureV2()
	withFile("assets/huge.png", pngBody+strings.Repeat("x", 6<<20))(pkg)
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "bundle over limit", err, "package_size")
	pkg = fixtureV2()
	pkg["auth_style"].(map[string]any)["css"] = strings.Repeat("a", AuthStyleMaxCSS+1)
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "css over limit", err, "auth_style_size")
}

func TestImages(t *testing.T) {
	if SniffImage("image/png", []byte(pngBody)) != "image/png" || SniffImage("image/png", []byte("GIF89a")) != "" ||
		SniffImage("image/gif", []byte("GIF89a")) != "" || SniffImage("image/webp", []byte("RIFF\x00\x00\x00\x00WEBPVP8 ")) != "image/webp" ||
		SniffImage("image/jpeg", []byte{0xff, 0xd8, 0xff, 0}) != "image/jpeg" || SniffImage("image/x-icon", []byte{0, 0, 1, 0}) != "image/x-icon" ||
		SniffImage("image/svg+xml", []byte(svgBody)) != "image/svg+xml" || SniffImage("image/png", nil) != "" ||
		SniffImage("image/png", []byte(pngBody+strings.Repeat("x", ImageMaxBytes))) != "" {
		t.Fatal("image sniffing")
	}
	good := []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g"/></defs><rect fill="url(#g)"/></svg>`,
		`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><use href="#a"/></svg>`,
	}
	bad := []string{
		`<svg><script>alert(1)</script></svg>`, `<svg onload="alert(1)"></svg>`,
		`<svg><a href="javascript:alert(1)"><text>x</text></a></svg>`, `<svg><image href="https://example.com/x.png"/></svg>`,
		`<svg><foreignObject><div/></foreignObject></svg>`, `<svg><style>@import url(https://x)</style></svg>`,
		`<svg><rect style="fill:url(https://x)"/></svg>`, `<!DOCTYPE svg [<!ENTITY x "y">]><svg/>`, `<html><svg/></html>`,
		`<svg/><svg/>`, `<svg><set attributeName="href" to="javascript:alert(1)"/></svg>`, "<svg>\xff</svg>",
		`<?php x ?><svg/>`,
	}
	for _, body := range good {
		if !SafeSVG([]byte(body)) {
			t.Errorf("rejected %s", body)
		}
	}
	for _, body := range bad {
		if SafeSVG([]byte(body)) {
			t.Errorf("accepted %s", body)
		}
	}
}

func TestAuthStyle(t *testing.T) {
	good := []string{
		"", ".a{color:#fff}", `.a{background:url(img/bg.png)}`, `.a{background:url('./img/bg.png')}`,
		`.a{background:url("/static/bg.png")}`, `.a{background:url(data:image/svg+xml;base64,PHN2Zz4=)}`,
		`.a{background:url( "img/a.webp" )}`, "@media (max-width:600px){.a{display:none}}", "@font-face{font-family:x;src:local(x)}",
	}
	for _, css := range good {
		if code := checkAuthCSS(css); code != "" {
			t.Errorf("rejected %q: %s", css, code)
		}
	}
	bad := map[string]string{
		`@import url(https://evil/x.css);`:               "auth_style_css",
		`@IMPORT "x.css";`:                               "auth_style_css",
		`.a{width:expression(alert(1))}`:                 "auth_style_css",
		`.a{width:EXPRESSION (alert(1))}`:                "auth_style_css",
		`</style><script>alert(1)</script>`:              "auth_style_css",
		`</STYLE >`:                                      "auth_style_css",
		`<script>`:                                       "auth_style_css",
		`.a{background:url(https://evil/x.png)}`:         "auth_style_url",
		`.a{background:url(//evil/x.png)}`:               "auth_style_url",
		`.a{background:url(javascript:alert(1))}`:        "auth_style_css",
		`.a{background:url(data:text/html,<b>)}`:         "auth_style_url",
		`.a{background:url(../../etc/passwd)}`:           "auth_style_url",
		`.a{background:url(img/x.png}`:                   "auth_style_url",
		`.a{background:url()}`:                           "auth_style_url",
		`.a{background:url(ftp:x)}`:                      "auth_style_url",
		`.a{content:"\75rl(https://x)"}`:                 "auth_style_css",
		`.a{behavior:url(x.htc)}`:                        "auth_style_css",
		`.a{-moz-binding:url(x.xml)}`:                    "auth_style_css",
		`.a{background:image-set("https://x/a.png" 1x)}`: "auth_style_css",
		`.a{font:"https://evil"}`:                        "auth_style_url",
		"\x00":                                           "auth_style_css",
		`html[data-cdnca-role="admin"] .a{color:red}`:    "admin_forbidden",
	}
	for css, code := range bad {
		if got := checkAuthCSS(css); got != code {
			t.Errorf("%q: %q, want %q", css, got, code)
		}
	}
	pkg := fixtureV2()
	pkg["auth_style"].(map[string]any)["css"] = `@import "https://evil/x.css";`
	_, err := Parse(encode(t, pkg), thirdParty())
	expectCode(t, "import via Parse", err, "auth_style_css")
	for name, images := range map[string]map[string]any{
		"bad slot":   {"Bad Slot": b64(pngBody)},
		"not base64": {"logo": "%%%"},
		"not image":  {"logo": b64("<html>")},
		"svg script": {"logo": b64(`<svg><script>alert(1)</script></svg>`)},
	} {
		pkg := fixtureV2()
		pkg["auth_style"].(map[string]any)["images"] = images
		_, err := Parse(encode(t, pkg), thirdParty())
		want := "image_body"
		if name == "bad slot" {
			want = "image_slot"
		}
		expectCode(t, name, err, want)
	}
	many := map[string]any{}
	for i := 0; i <= AuthStyleMaxImages; i++ {
		many["s"+strings.Repeat("a", i+1)] = b64(pngBody)
	}
	pkg = fixtureV2()
	pkg["auth_style"].(map[string]any)["images"] = many
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "too many images", err, "auth_style_images")
	pkg = fixtureV2()
	pkg["auth_style"].(map[string]any)["js"] = "x"
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "unknown auth field", err, "package_json")
}

func TestContentSchema(t *testing.T) {
	text := func(key string) map[string]any {
		return map[string]any{"key": key, "type": "text", "label": map[string]any{"zh-CN": "x"}}
	}
	list := func(fields ...any) map[string]any {
		return map[string]any{"key": "items", "type": "list", "label": map[string]any{"zh-CN": "列表"}, "fields": fields}
	}
	cases := map[string]struct {
		schema []any
		code   string
	}{
		"empty":         {[]any{}, "content_schema"},
		"bad key":       {[]any{text("Hero")}, "content_key"},
		"digit key":     {[]any{text("1a")}, "content_key"},
		"dash key":      {[]any{text("a-b")}, "content_key"},
		"duplicate":     {[]any{text("a"), text("a")}, "content_key_duplicate"},
		"bad type":      {[]any{map[string]any{"key": "a", "type": "html", "label": map[string]any{"zh-CN": "x"}}}, "content_type"},
		"no label":      {[]any{map[string]any{"key": "a", "type": "text"}}, "i18n_required"},
		"nested list":   {[]any{list(list(text("a")))}, "content_nesting"},
		"empty list":    {[]any{list()}, "content_schema"},
		"dup in list":   {[]any{list(text("a"), text("a"))}, "content_key_duplicate"},
		"fields on txt": {[]any{map[string]any{"key": "a", "type": "text", "label": map[string]any{"zh-CN": "x"}, "fields": []any{text("b")}}}, "content_fields"},
		"len on image":  {[]any{map[string]any{"key": "a", "type": "image", "label": map[string]any{"zh-CN": "x"}, "max_length": 3}}, "content_max_length"},
		"neg len":       {[]any{map[string]any{"key": "a", "type": "text", "label": map[string]any{"zh-CN": "x"}, "max_length": -1}}, "content_max_length"},
		"items on text": {[]any{map[string]any{"key": "a", "type": "text", "label": map[string]any{"zh-CN": "x"}, "max_items": 3}}, "content_max_items"},
		"unknown":       {[]any{map[string]any{"key": "a", "type": "text", "label": map[string]any{"zh-CN": "x"}, "html": true}}, "package_json"},
	}
	for name, c := range cases {
		pkg := fixtureV2()
		pkg["content_schema"] = c.schema
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, name, err, c.code)
	}
	tooMany := []any{}
	for i := 0; i <= ContentSchemaMaxFields; i++ {
		tooMany = append(tooMany, text("k"+strings.Repeat("a", i)))
	}
	pkg := fixtureV2()
	pkg["content_schema"] = tooMany
	_, err := Parse(encode(t, pkg), thirdParty())
	expectCode(t, "too many", err, "content_schema")
	// Every type, list one level deep, passes.
	pkg = fixtureV2()
	pkg["content_schema"] = []any{text("a_1"), list(text("t"), map[string]any{"key": "u", "type": "link", "label": map[string]any{"zh-CN": "x"}})}
	if _, err := Parse(encode(t, pkg), thirdParty()); err != nil {
		t.Fatalf("valid schema: %v", err)
	}
}

func TestBase64Strict(t *testing.T) {
	pkg := fixtureV2()
	f := bundleFiles(pkg)[1].(map[string]any)
	f["data_base64"] = base64.RawStdEncoding.EncodeToString([]byte("ab"))
	f["sha256"] = sum("ab")
	_, err := Parse(encode(t, pkg), thirdParty())
	expectCode(t, "unpadded base64", err, "bundle_data")
}

// fix-sitepricing: a plan block takes its packages from the catalog ("" or
// "packages") or keeps its hand-edited items ("manual"); nothing else.
func TestSectionSource(t *testing.T) {
	content := func(source string) map[string]LayoutContent {
		return map[string]LayoutContent{"xmf": {Pages: []Page{{Key: "home", Path: "/", Title: "首页",
			Sections: []Section{{Type: "plans", Source: source}}}}}}
	}
	for _, source := range []string{"", "packages", "manual"} {
		if _, ok := ValidateContent(Brand{Name: "x"}, Contact{}, content(source)); !ok {
			t.Fatalf("source %q rejected", source)
		}
	}
	if _, ok := ValidateContent(Brand{Name: "x"}, Contact{}, content("remote")); ok {
		t.Fatal("unknown source accepted")
	}
	raw, _ := json.Marshal(Section{Type: "plans"})
	if strings.Contains(string(raw), "source") {
		t.Fatalf("empty source serialised: %s", raw)
	}
}
