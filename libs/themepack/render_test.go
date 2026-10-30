package themepack

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
	"strings"
	"testing"
)

func validationCode(t *testing.T, err error) string {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) || !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("error %v is not a theme validation error", err)
	}
	return validation.Code
}

func TestBuiltinThemesRender(t *testing.T) {
	for _, entry := range BuiltinCatalog() {
		rendered, err := Render(entry.Raw)
		if err != nil {
			t.Fatalf("%s: %v", entry.ID, err)
		}
		if rendered.Package.ID != entry.ID || entry.RequiresFeature != "" {
			t.Fatalf("%s: id %q feature %q", entry.ID, rendered.Package.ID, entry.RequiresFeature)
		}
		if len(rendered.ErrorPages) != len(DefaultErrorPages) {
			t.Fatalf("%s: %d error pages", entry.ID, len(rendered.ErrorPages))
		}
		for _, page := range rendered.ErrorPages {
			if err := ValidateThemedHTML(page.Body); err != nil {
				t.Fatalf("%s %s/%d: %v", entry.ID, page.Category, page.Status, err)
			}
			// The node's style-src for the page: the hash of exactly its one <style>.
			hash := ThemeStyleHash(page.Body)
			start, end := bytes.Index(page.Body, []byte("<style>")), bytes.Index(page.Body, []byte("</style>"))
			if start < 0 || end < start || hash != errorpagestyle.SourceHash(string(page.Body[start+len("<style>"):end])) {
				t.Fatalf("%s %s/%d: style hash %q", entry.ID, page.Category, page.Status, hash)
			}
		}
		if bytes.Contains(rendered.CSS, []byte("url(")) || bytes.Contains(rendered.CSS, []byte("@import")) {
			t.Fatalf("%s css loads external resources:\n%s", entry.ID, rendered.CSS)
		}
	}
}

// The default theme must reproduce today's hard-coded look (main.tsx:54-75,
// styles.css :root) so installing it changes nothing on screen.
func TestDefaultThemeMatchesHardCodedLook(t *testing.T) {
	rendered := DefaultRendered()
	var document struct {
		AntdTokens   map[string]any    `json:"antd_tokens"`
		CSSVariables map[string]string `json:"css_variables"`
		Layout       struct {
			LoginLayout string `json:"login_layout"`
			Sidebar     string `json:"sidebar"`
		} `json:"layout"`
	}
	if err := json.Unmarshal(rendered.JSON, &document); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"colorPrimary": "#2d8cf0", "colorLink": "#2d8cf0", "colorLinkHover": "#57a3f3", "colorText": "#515a6e",
		"colorTextSecondary": "#808695", "colorBorder": "#dcdee2", "colorBgLayout": "#f5f7f9",
		"borderRadius": 4.0, "controlHeight": 32.0, "fontSize": 14.0, "lineHeight": 1.5,
	}
	for name, value := range want {
		if document.AntdTokens[name] != value {
			t.Errorf("antd %s = %v, want %v", name, document.AntdTokens[name], value)
		}
	}
	for name, value := range map[string]string{
		"--setting-bg": "#ffffff", "--setting-border": "#e8eaec", "--setting-border-strong": "#dcdee2",
		"--setting-primary": "#2d8cf0", "--cdnca-sidebar-width": "256px",
	} {
		if document.CSSVariables[name] != value {
			t.Errorf("css %s = %q, want %q", name, document.CSSVariables[name], value)
		}
	}
	if document.Layout.LoginLayout != "split" || document.Layout.Sidebar != "light" {
		t.Errorf("layout = %+v", document.Layout)
	}
	if !strings.HasPrefix(string(rendered.CSS), ":root[data-cdnca-theme] {\n") {
		t.Fatalf("css = %s", rendered.CSS)
	}
}

func customPackage(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(BuiltinCatalog()[0].Raw, &document); err != nil {
		t.Fatal(err)
	}
	document["id"] = "custom.brand"
	if _, ok := document["tokens"]; !ok {
		document["tokens"] = map[string]any{}
	}
	if mutate != nil {
		mutate(document)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func templates(document map[string]any) map[string]any { return document["templates"].(map[string]any) }

func firstStyle(document map[string]any) map[string]any {
	return templates(document)["styles"].([]any)[0].(map[string]any)["declarations"].(map[string]any)
}

// Acceptance (PA-17): a package with url(), an external link or an
// undeclared class is refused.
func TestRejectsUnsafePackages(t *testing.T) {
	if _, err := Render(customPackage(t, nil)); err != nil {
		t.Fatalf("baseline custom package rejected: %v", err)
	}
	cases := map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"url in style": {func(d map[string]any) {
			firstStyle(d)["background-color"] = "url(https://evil.example/x.png)"
		}, "external_reference"},
		"import in token": {func(d map[string]any) {
			d["tokens"].(map[string]any)["fontFamily"] = "@import x"
		}, "external_reference"},
		"external image in template": {func(d map[string]any) {
			templates(d)["error_page"] = strings.Replace(templates(d)["error_page"].(string), "<h1", "<img src=\"https://evil.example/x.png\"><h1", 1)
		}, "external_reference"},
		"external link in template": {func(d map[string]any) {
			templates(d)["error_page"] = strings.Replace(templates(d)["error_page"].(string), "{{title}}</h1>", "<a href=\"https://evil.example\">x</a></h1>", 1)
		}, "external_reference"},
		"external link in footer": {func(d map[string]any) {
			d["layout_slots"].(map[string]any)["footer_text"] = map[string]any{"zh-CN": "访问 https://evil.example"}
		}, "external_reference"},
		"undeclared class": {func(d map[string]any) {
			templates(d)["error_page"] = strings.Replace(templates(d)["error_page"].(string), "cf-title", "cf-unknown", 1)
		}, "class_undeclared"},
		"template style": {func(d map[string]any) {
			templates(d)["error_page"] = strings.Replace(templates(d)["error_page"].(string), "</head>", "<style>body { color: #000000; }\n</style></head>", 1)
		}, "template_head"},
		"script": {func(d map[string]any) {
			templates(d)["error_page"] = strings.Replace(templates(d)["error_page"].(string), "</main>", "<script>alert(1)</script></main>", 1)
		}, "external_reference"},
		"unknown template variable": {func(d map[string]any) {
			templates(d)["error_page"] = strings.Replace(templates(d)["error_page"].(string), "{{message}}", "{{request_uri}}", 1)
		}, "template_variable"},
		"http header link": {func(d map[string]any) {
			d["layout_slots"].(map[string]any)["header_links"] = []any{map[string]any{"label": map[string]any{"zh-CN": "帮助"}, "url": "http://docs.example"}}
		}, "header_link_url"},
		"javascript header link": {func(d map[string]any) {
			d["layout_slots"].(map[string]any)["header_links"] = []any{map[string]any{"label": map[string]any{"zh-CN": "帮助"}, "url": "javascript:alert(1)"}}
		}, "header_link_url"},
		"unknown token":       {func(d map[string]any) { d["tokens"].(map[string]any)["colorDanger"] = "#ff0000" }, "token_unknown"},
		"bad color":           {func(d map[string]any) { d["tokens"].(map[string]any)["colorPrimary"] = "red" }, "token_value"},
		"radius out of range": {func(d map[string]any) { d["tokens"].(map[string]any)["borderRadius"] = 40 }, "token_value"},
		"bad layout":          {func(d map[string]any) { d["layout_slots"].(map[string]any)["sidebar"] = "purple" }, "layout_value"},
		"unknown field":       {func(d map[string]any) { d["scripts"] = []any{"x"} }, "package_json"},
		"bad id":              {func(d map[string]any) { d["id"] = "Custom/x" }, "id"},
		"svg brand slot": {func(d map[string]any) {
			d["brand_slots"] = map[string]any{"logo": map[string]any{"mime_type": "image/svg+xml", "body_base64": base64.StdEncoding.EncodeToString([]byte("<svg/>"))}}
		}, "brand_asset_media"},
		"png slot not png": {func(d map[string]any) {
			d["brand_slots"] = map[string]any{"logo_dark": map[string]any{"mime_type": "image/png", "body_base64": base64.StdEncoding.EncodeToString([]byte("GIF89a"))}}
		}, "brand_asset_media"},
	}
	for name, test := range cases {
		_, err := Render(customPackage(t, test.mutate))
		if err == nil {
			t.Errorf("%s: unsafe package accepted", name)
			continue
		}
		if test.code != "" {
			if code := validationCode(t, err); code != test.code {
				t.Errorf("%s: code %q, want %q (%v)", name, code, test.code, err)
			}
		}
	}
}

func TestRejectsJSONEscapedURL(t *testing.T) {
	raw := customPackage(t, func(d map[string]any) { firstStyle(d)["background-color"] = "MARKER" })
	raw = bytes.Replace(raw, []byte(`"MARKER"`), []byte(`"\u0075rl(https://evil.example/x.png)"`), 1)
	if _, err := Render(raw); err == nil || validationCode(t, err) != "external_reference" {
		t.Fatalf("escaped url accepted: %v", err)
	}
}

func TestBrandSlotsRender(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 32)...)
	jpeg := append([]byte{0xff, 0xd8, 0xff}, make([]byte, 32)...)
	raw := customPackage(t, func(d map[string]any) {
		d["brand_slots"] = map[string]any{
			"logo_dark":        map[string]any{"mime_type": "image/png", "body_base64": base64.StdEncoding.EncodeToString(png)},
			"login_background": map[string]any{"mime_type": "image/jpeg", "body_base64": base64.StdEncoding.EncodeToString(jpeg)},
			"app_icon":         map[string]any{"mime_type": "image/png", "body_base64": base64.StdEncoding.EncodeToString(png)},
		}
	})
	rendered, err := Render(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rendered.Assets) != 3 {
		t.Fatalf("assets = %d", len(rendered.Assets))
	}
	var document struct {
		Brand map[string]struct {
			URL string `json:"url"`
		} `json:"brand"`
	}
	if err := json.Unmarshal(rendered.JSON, &document); err != nil {
		t.Fatal(err)
	}
	for _, asset := range rendered.Assets {
		if document.Brand[asset.Slot].URL != AssetPath(asset.SHA256) {
			t.Fatalf("%s url = %q", asset.Slot, document.Brand[asset.Slot].URL)
		}
	}
}

func TestTemplateEscapesAndRendersEmail(t *testing.T) {
	rendered := DefaultRendered()
	body, err := rendered.RenderEmail("账单 <提醒>", []string{"金额 & 时间", "第二行"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "账单 &lt;提醒&gt;") || !strings.Contains(text, "金额 &amp; 时间") ||
		strings.Count(text, `class="cf-line"`) != 2 {
		t.Fatalf("email = %s", text)
	}
	if _, err := rendered.RenderEmail("x", []string{"{{oops}}"}); err == nil {
		t.Fatal("rendered email with a template marker passed the page validator")
	}
}

func TestTemplateSyntax(t *testing.T) {
	variables := templateVariables{"a": false, "items": true}
	for _, source := range []string{"{{{a}}}", "{{&a}}", "{{>a}}", "{{!x}}", "{{#a}}x", "x{{/a}}", "{{=<% %>=}}", "{{b}}", "{{.}}", "{{items}}", "a}}b"} {
		if _, err := compileTemplate(source, variables); err == nil {
			t.Errorf("template %q accepted", source)
		}
	}
	compiled, err := compileTemplate("<p>{{a}}</p>{{#items}}<i>{{.}}</i>{{/items}}{{^a}}none{{/a}}", variables)
	if err != nil {
		t.Fatal(err)
	}
	if got := compiled.render(TemplateContext{"a": "<x>", "items": []string{"1", "&"}}); got != "<p>&lt;x&gt;</p><i>1</i><i>&amp;</i>" {
		t.Fatalf("render = %q", got)
	}
	if got := compiled.render(TemplateContext{}); got != "<p></p>none" {
		t.Fatalf("render = %q", got)
	}
}

func TestThemeStyleHashRejectsUnthemed(t *testing.T) {
	for _, body := range []string{"", "<!doctype html><html><head><title>x</title></head><body><p>x</p></body></html>",
		"<html><head><style>@import url(x)</style></head><body></body></html>"} {
		if hash := ThemeStyleHash([]byte(body)); hash != "" {
			t.Fatalf("%q: %q", body, hash)
		}
	}
}
