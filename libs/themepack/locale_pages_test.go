package themepack

import (
	"bytes"
	"html"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// a default error page carries
// one language, the site's (none known: zh-CN), never "429 请求过于频繁 / Too
// many requests" with the message repeated in English.

// hasHan reports Han characters in the page's visible text: <style> blocks (a theme's font stack names
// 微软雅黑) and tag attributes are not text a visitor reads.
var (
	styleBlock = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	markupTag  = regexp.MustCompile(`(?s)<[^>]*>`)
)

func hasHan(body []byte) bool {
	text := styleBlock.ReplaceAll(body, nil)
	text = markupTag.ReplaceAll(text, nil)
	for _, r := range string(text) {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func pageOf(t *testing.T, pages []ErrorPage, category string, status int) []byte {
	t.Helper()
	for _, page := range pages {
		if page.Category == category && page.Status == status {
			return page.Body
		}
	}
	t.Fatalf("no %s %d page", category, status)
	return nil
}

func TestDefaultErrorPagesRenderOneLanguage(t *testing.T) {
	for _, entry := range BuiltinCatalog() {
		rendered, err := Render(entry.Raw)
		if err != nil {
			t.Fatalf("%s: %v", entry.ID, err)
		}
		english, err := rendered.ErrorPagesIn("en-US")
		if err != nil {
			t.Fatalf("%s en-US: %v", entry.ID, err)
		}
		if len(english) != len(DefaultErrorPages) {
			t.Fatalf("%s: %d en-US pages", entry.ID, len(english))
		}
		for _, page := range DefaultErrorPages {
			chinese := pageOf(t, rendered.ErrorPages, page.Category, page.Status)
			for _, word := range []string{page.Title["zh-CN"], page.Message["zh-CN"]} {
				if !bytes.Contains(chinese, []byte(html.EscapeString(word))) {
					t.Fatalf("%s zh-CN %d: %q missing:\n%s", entry.ID, page.Status, word, chinese)
				}
			}
			for _, word := range []string{page.Title["en-US"], page.Message["en-US"]} {
				if bytes.Contains(chinese, []byte(html.EscapeString(word))) {
					t.Fatalf("%s zh-CN %d carries the English %q:\n%s", entry.ID, page.Status, word, chinese)
				}
			}
			body := pageOf(t, english, page.Category, page.Status)
			if hasHan(body) || !bytes.Contains(body, []byte(html.EscapeString(page.Title["en-US"]))) || !bytes.Contains(body, []byte(html.EscapeString(page.Message["en-US"]))) {
				t.Fatalf("%s en-US %d is not English only:\n%s", entry.ID, page.Status, body)
			}
			if ValidateThemedHTML(body) != nil {
				t.Fatalf("%s en-US %d is not a valid themed page", entry.ID, page.Status)
			}
		}
		// The 429 title says it once: no "/" joining two languages.
		if title := DefaultErrorPages[4]; title.Status != 429 || strings.Contains(title.Title["zh-CN"], "/") || strings.Contains(title.Title["zh-CN"], "Too many") {
			t.Fatalf("429 title %+v", title)
		}
	}
}

// A custom theme still decides the page: its template, style and footer, in
// the page's language only.
func TestCustomThemeErrorPagesKeepTheThemeInEitherLanguage(t *testing.T) {
	raw := customPackage(t, func(document map[string]any) {
		templates(document)["error_page"] = strings.Replace(templates(document)["error_page"].(string),
			`<main class="cf-page">`, `<main class="cf-page"><p class="cf-status">ACME Edge</p>`, 1)
		document["layout_slots"].(map[string]any)["footer_text"] = map[string]any{"zh-CN": "中文页脚", "en-US": "English footer"}
	})
	rendered, err := Render(raw)
	if err != nil {
		t.Fatal(err)
	}
	english, err := rendered.ErrorPagesIn("en-US")
	if err != nil {
		t.Fatal(err)
	}
	chinese := pageOf(t, rendered.ErrorPages, CategoryEdgeRoute, 429)
	body := pageOf(t, english, CategoryEdgeRoute, 429)
	for _, page := range [][]byte{chinese, body} {
		if !bytes.Contains(page, []byte("ACME Edge")) || !bytes.Contains(page, []byte("#0f766e")) {
			t.Fatalf("custom template or style lost:\n%s", page)
		}
	}
	if !bytes.Contains(chinese, []byte("429 请求过于频繁")) || !bytes.Contains(chinese, []byte("中文页脚")) ||
		bytes.Contains(chinese, []byte("Too many requests")) || bytes.Contains(chinese, []byte("English footer")) {
		t.Fatalf("zh-CN 429:\n%s", chinese)
	}
	if !bytes.Contains(body, []byte("429 Too many requests")) || !bytes.Contains(body, []byte("English footer")) || hasHan(body) {
		t.Fatalf("en-US 429:\n%s", body)
	}
	// A locale the theme does not carry falls back to zh-CN.
	traditional, err := rendered.ErrorPagesIn("zh-TW")
	if err != nil || !bytes.Equal(pageOf(t, traditional, CategoryEdgeRoute, 429), chinese) {
		t.Fatalf("zh-TW fallback: %v", err)
	}
}
