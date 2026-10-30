package errorpagecontrol

import (
	"bytes"
	"testing"

	"github.com/cdnca/cdnca/libs/themepack"
)

// sec-followup P13: without any theme the node block pages are the built-in
// theme's, as global edge_route rules a node accepts.
func TestBuiltinBlockSnapshot(t *testing.T) {
	document, err := BuiltinBlockSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if document.Schema != ProductionSnapshotSchema || len(document.Sites) != 0 || len(document.Global.Rules) != 2 {
		t.Fatalf("document %+v", document)
	}
	for index, want := range []string{"theme.edge_route.403", "theme.edge_route.429"} {
		rule := document.Global.Rules[index]
		if rule.ID != want || rule.Category != CategoryEdgeRoute || rule.Resource.MIMEType != "text/html" ||
			rule.Resource.SHA256 != digestBytes(rule.Resource.Body) || ValidateThemedHTML(rule.Resource.Body) != nil {
			t.Fatalf("rule %d = %+v", index, rule)
		}
	}
}

// A theme package stored before 471 has no block pages: they are rendered
// from the package itself (its brand), the stored pages stay.
func TestCompleteBlockPagesFromPackage(t *testing.T) {
	var slate themepack.CatalogEntry
	for _, entry := range themepack.BuiltinCatalog() {
		if entry.ID != themepack.DefaultRendered().Package.ID {
			slate = entry
		}
	}
	stored := []ThemeDefaultPage{{Category: CategoryNoHost, Status: 400, Body: []byte("stored 400")},
		{Category: CategoryEdgeConnect, Status: 502, Body: []byte("stored 502")}}
	pages := completeBlockPages(stored, slate.Raw)
	if len(pages) != 4 || pages[0].Category != CategoryEdgeConnect || pages[1].Category != CategoryEdgeRoute ||
		pages[1].Status != 403 || pages[2].Status != 429 || !bytes.Equal(pages[3].Body, []byte("stored 400")) {
		t.Fatalf("pages %+v", pages)
	}
	own, _ := themepack.Render(slate.Raw)
	for _, page := range own.ErrorPages {
		if page.Category == CategoryEdgeRoute && page.Status == 403 && !bytes.Equal(page.Body, pages[1].Body) {
			t.Fatal("block page is not the package's own")
		}
	}
	if !hasBlockPages(pages) || hasBlockPages(stored) {
		t.Fatal("hasBlockPages")
	}
	// A package that no longer renders falls back to the built-in pages.
	if broken := completeBlockPages(stored, []byte("{")); len(broken) != 4 {
		t.Fatalf("broken package %+v", broken)
	}
}
