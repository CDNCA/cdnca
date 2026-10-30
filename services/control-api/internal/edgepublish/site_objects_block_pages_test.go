package edgepublish

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

// sec-followup P13: a scope that never published error pages (no theme, no
// rule; 73) still gives every site the built-in block pages, edge_route 403
// and 429 under the theme rule IDs cdnca_filters keeps out of the
// intercepted set (an origin 403/429 is not replaced).
func TestDynamicRoutingBuiltinBlockPages(t *testing.T) {
	v8 := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	builtin, err := errorpagecontrol.BuiltinBlockSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	facts, err := dynamicRoutingFacts(v8, &builtin, nil)
	if err != nil {
		t.Fatal(err)
	}
	publication, _, err := buildDynamicRoutingPublication(v8, goldenTenant, facts, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, object := range publication.Objects {
		objects[object.SHA256] = object.Plaintext
	}
	sites := 0
	for _, raw := range objects {
		site, err := edgesite.Decode(raw)
		if err != nil {
			continue
		}
		sites++
		if len(site.Errors) != 2 {
			t.Fatalf("site %s error pages %+v", site.SiteID, site.Errors)
		}
		for index, status := range []int{403, 429} {
			page := site.Errors[index]
			if page.Category != edgesite.ErrorEdgeRoute || page.Status != status || !strings.HasPrefix(page.RuleID, "theme.edge_route.") ||
				page.MIMEType != "text/html" || page.StyleHash == "" || !bytes.Contains(objects[page.Asset.SHA256], []byte("<style>")) {
				t.Fatalf("site %s page %d = %+v", site.SiteID, index, page)
			}
		}
	}
	if sites != 2 {
		t.Fatalf("%d site objects", sites)
	}
}
