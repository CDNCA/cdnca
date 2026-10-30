package sitetheme

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

const pngBody = "\x89PNG\r\n\x1a\nrest"

var svgBody = `<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sum(s string) string {
	digest := sha256.Sum256([]byte(s))
	return hex.EncodeToString(digest[:])
}

func file(path, body string) map[string]any {
	return map[string]any{"path": path, "sha256": sum(body), "data_base64": b64(body)}
}

const indexHTML = `<!doctype html><html><head><link rel="stylesheet" href="assets/app.css">` +
	`<script type="module" src="assets/app.js"></script></head><body><div id="app"></div></body></html>`

const appJS = `fetch("/v1/control-site/content").then(r => r.json()).then(c => {` +
	` document.querySelector("img").src = "/v1/control-site/assets/" + c.brand.logo.slice(6) })`

// v1Package is a minimal valid cdnca.site-theme/v1 package.
func v1Package() map[string]any {
	return map[string]any{
		"schema": SchemaV1, "id": "custom.orange", "version": "1.0.0",
		"name": map[string]any{"zh-CN": "橙", "en-US": "Orange"}, "layout": "xmf",
		"tokens": map[string]any{"colorPrimary": "#f6821f", "borderRadius": "6px"},
		"images": map[string]any{"logo": map[string]any{"mime_type": "image/svg+xml", "body_base64": b64(svgBody)}},
		"seed": map[string]any{
			"brand":   map[string]any{"name": "你的品牌", "logo": "theme:logo"},
			"contact": map[string]any{"enabled": false, "items": []any{}},
			"nav":     []any{map[string]any{"label": "首页", "href": "/", "children": []any{}}},
			"actions": []any{map[string]any{"label": "登录", "href": "#login"}},
			"footer":  map[string]any{"columns": []any{}, "links": []any{}, "records": []any{}},
			"pages": []any{map[string]any{"key": "home", "path": "/", "title": "首页",
				"sections": []any{map[string]any{"type": "hero", "title": "欢迎"}}}},
		},
	}
}

func consoleTheme() map[string]any {
	return map[string]any{"schema": ConsoleSchema, "id": "market.acme.blue", "version": "1.0.0",
		"name": map[string]any{"zh-CN": "蓝"}, "layout_slots": map[string]any{"login_layout": "centered", "sidebar": "dark"},
		"tokens_by_role": map[string]any{"user": map[string]any{"colorPrimary": "#123456"}}}
}

// v2Package is a valid third-party user+site package with every block.
func fixtureV2() map[string]any {
	return map[string]any{
		"schema": SchemaV2, "id": "market.acme.blue", "version": "1.2.3",
		"name":          map[string]any{"zh-CN": "蓝色官网", "en-US": "Blue"},
		"applies_to":    []any{"user", "site"},
		"console_theme": consoleTheme(),
		"site_bundle": map[string]any{"files": []any{
			file("index.html", indexHTML), file("assets/app.js", appJS), file("assets/app.css", "body{color:#333}"),
			file("assets/logo.png", pngBody),
		}},
		"auth_style": map[string]any{"css": `.auth-card{background:url("img/bg.png") no-repeat;border-radius:8px}` +
			`.auth-logo{background-image:url(data:image/png;base64,AAAA)}`, "images": map[string]any{"logo": b64(pngBody)}},
		"content_schema": []any{
			map[string]any{"key": "hero_title", "type": "text", "label": map[string]any{"zh-CN": "主标题"}, "max_length": 80},
			map[string]any{"key": "hero_body", "type": "textarea", "label": map[string]any{"zh-CN": "简介"}},
			map[string]any{"key": "about", "type": "richtext", "label": map[string]any{"zh-CN": "关于"}},
			map[string]any{"key": "banner", "type": "image", "label": map[string]any{"zh-CN": "横幅"}},
			map[string]any{"key": "cta", "type": "link", "label": map[string]any{"zh-CN": "按钮"}},
			map[string]any{"key": "features", "type": "list", "label": map[string]any{"zh-CN": "特性"}, "max_items": 12,
				"fields": []any{
					map[string]any{"key": "title", "type": "text", "label": map[string]any{"zh-CN": "标题"}},
					map[string]any{"key": "icon", "type": "image", "label": map[string]any{"zh-CN": "图标"}},
				}},
		},
	}
}

func encode(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func thirdParty() ParseOptions { return ParseOptions{Publisher: PublisherThirdParty} }
func official() ParseOptions   { return ParseOptions{Publisher: PublisherOfficial} }

// expectCode fails unless err is an *Error with the given code (prefixed).
func expectCode(t *testing.T, name string, err error, code string) {
	t.Helper()
	var invalid *Error
	if !errors.As(err, &invalid) {
		t.Errorf("%s: err %v, want %s", name, err, code)
		return
	}
	if invalid.Code != ErrorPrefix+code {
		t.Errorf("%s: code %s field %s, want %s", name, invalid.Code, invalid.Field, ErrorPrefix+code)
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("%s: does not unwrap to ErrInvalid", name)
	}
}

func bundleFiles(pkg map[string]any) []any {
	return pkg["site_bundle"].(map[string]any)["files"].([]any)
}

// withFile replaces (or appends) one bundle file.
func withFile(path, body string) func(map[string]any) {
	return func(pkg map[string]any) {
		bundle := pkg["site_bundle"].(map[string]any)
		files := bundleFiles(pkg)
		for index, entry := range files {
			if entry.(map[string]any)["path"] == path {
				files[index] = file(path, body)
				return
			}
		}
		bundle["files"] = append(files, file(path, body))
	}
}
