package edgeskeleton

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/contentrewrite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// configure loads cdnca_rewrite only when a site has rules;
// the plain fetch variables are declared only on a node with RUM or content
// rewrite (the module reads them as "" when absent).
func TestRenderContentRewrite(t *testing.T) {
	off := render(t, testInput())
	if strings.Contains(off, "content_rewrite") {
		t.Fatal("content_rewrite rendered while off")
	}
	plain := []string{`set $cdnca_plain_ae "";`, `set $cdnca_plain_want "";`}
	for _, name := range plain {
		if strings.Contains(off, name) {
			t.Fatalf("%q rendered with RUM and content rewrite off", name)
		}
	}
	input := testInput()
	input.ContentRewrite = true
	rewriteOn := render(t, input)
	if !strings.Contains(rewriteOn, "      content_rewrite = true,\n") {
		t.Fatal("configure lacks content_rewrite")
	}
	rum := testInput()
	rum.SiteRUM = true
	for name, got := range map[string]string{"content rewrite": rewriteOn, "rum": render(t, rum)} {
		for _, want := range plain {
			if !strings.Contains(got, want) {
				t.Fatalf("%s on: missing %q", name, want)
			}
		}
	}
	sites := []edgesite.Site{{}, {ContentRewrite: &contentrewrite.Node{}}}
	if !ContentRewriteFromSites(sites) || ContentRewriteFromSites(sites[:1]) {
		t.Fatal("ContentRewriteFromSites")
	}
}
