package themepack

import (
	"bytes"
	"testing"
)

// sec-followup P13: every theme renders the node's own block pages
// (edge_route 403 / 429), in Chinese and English.
func TestBuiltinThemesRenderBlockPages(t *testing.T) {
	for _, entry := range BuiltinCatalog() {
		rendered, err := Render(entry.Raw)
		if err != nil {
			t.Fatalf("%s: %v", entry.ID, err)
		}
		found := map[int][]byte{}
		for _, page := range rendered.ErrorPages {
			if page.Category == CategoryEdgeRoute {
				found[page.Status] = page.Body
			}
		}
		for status, words := range map[int][]string{
			403: {"访问被拦截", "Access blocked"},
			429: {"请求过于频繁", "Too many requests"},
		} {
			body := found[status]
			if body == nil {
				t.Fatalf("%s: no edge_route %d page", entry.ID, status)
			}
			for _, word := range words {
				if !bytes.Contains(body, []byte(word)) {
					t.Fatalf("%s edge_route %d: %q missing:\n%s", entry.ID, status, word, body)
				}
			}
		}
		if len(found) != 2 {
			t.Fatalf("%s: edge_route pages %d", entry.ID, len(found))
		}
	}
}
