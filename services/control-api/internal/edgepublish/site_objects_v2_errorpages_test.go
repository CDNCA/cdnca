package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

func snapshotRule(id, category string, codes []int, ranges [][2]int, mime string, body []byte) errorpagecontrol.ProductionSnapshotRule {
	sum := sha256.Sum256(body)
	match := errorpagecontrol.SnapshotMatch{Codes: codes}
	for _, span := range ranges {
		match.Ranges = append(match.Ranges, errorpagecontrol.SnapshotRange{From: span[0], To: span[1]})
	}
	return errorpagecontrol.ProductionSnapshotRule{ID: id, Category: category, Match: match,
		Resource: errorpagecontrol.ProductionSnapshotResource{MIMEType: mime, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Body: body}}
}

// A tenant scope's error page snapshot (platform global rules, the active
// theme's default pages, the sites' rules) as site object error pages.
func TestSiteErrorPageFactsFromSnapshot(t *testing.T) {
	style := "body { background-color: #f5f7f9; color: #515a6e; }\n"
	theme := []byte("<!doctype html><html><head><title>502</title><style>" + style + "</style></head><body><main><h1>502</h1></main></body></html>")
	unknown := []byte("<!doctype html><html><head><title>404</title><style>" + style + "</style></head><body><main>unknown</main></body></html>")
	globalPage := []byte("global 5xx\n")
	sitePage := []byte("{\"error\":\"site 404\"}")
	siteA, siteB := "0d9a0000-0000-4000-8000-000000000201", "0d9a0000-0000-4000-8000-000000000202"
	snapshot := errorpagecontrol.ProductionSnapshotDocument{Schema: errorpagecontrol.ProductionSnapshotSchema,
		Global: errorpagecontrol.ProductionSnapshotScope{Rules: []errorpagecontrol.ProductionSnapshotRule{
			snapshotRule("11111111-1111-4111-8111-111111111111", "origin_response", nil, [][2]int{{500, 599}}, "text/plain", globalPage),
			snapshotRule("theme.edge_connect.502", "edge_connect", []int{502}, nil, "text/html", theme),
			snapshotRule("theme.unknown_site.404", "unknown_site", []int{404}, nil, "text/html", unknown),
		}},
		Sites: []errorpagecontrol.ProductionSnapshotSite{{SiteKey: siteA, Rules: []errorpagecontrol.ProductionSnapshotRule{
			snapshotRule("22222222-2222-4222-8222-222222222222", "origin_response", []int{404, 503}, nil, "application/json", sitePage),
		}}},
	}
	referenced := map[string][]byte{}
	facts, _, err := siteErrorPageFacts(snapshot, []string{siteA, siteB}, referenced)
	if err != nil {
		t.Fatal(err)
	}
	pagesA, pagesB := facts[siteA], facts[siteB]
	if len(pagesA) != 1+100+1 || len(pagesB) != 1+100 { // edge_connect 502 + origin 500-599 (+ site 404)
		t.Fatalf("%d / %d pages", len(pagesA), len(pagesB))
	}
	find := func(pages []edgesite.ErrorPage, category string, status int) edgesite.ErrorPage {
		for _, page := range pages {
			if page.Category == category && page.Status == status {
				return page
			}
		}
		t.Fatalf("no %s %d", category, status)
		return edgesite.ErrorPage{}
	}
	if page := find(pagesA, "origin_response", 503); page.RuleID != "22222222-2222-4222-8222-222222222222" || page.MIMEType != "application/json" {
		t.Fatalf("site rule must replace the global range: %+v", page)
	}
	if page := find(pagesB, "origin_response", 503); page.RuleID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("a site without own rules gets the global page: %+v", page)
	}
	themed := find(pagesB, "edge_connect", 502)
	if themed.StyleHash != errorpagestyle.SourceHash(style) || themed.RuleID != "theme.edge_connect.502" {
		t.Fatalf("theme page style hash: %+v", themed)
	}
	if find(pagesB, "origin_response", 500).StyleHash != "" {
		t.Fatal("a plain page has a style hash")
	}
	for _, pages := range [][]edgesite.ErrorPage{pagesA, pagesB} {
		for _, page := range pages {
			if page.Status == 404 && page.Category != "origin_response" {
				t.Fatalf("node page leaked into a site: %+v", page)
			}
			if !bytes.Equal(referenced[page.Asset.SHA256], map[string][]byte{"text/plain": globalPage, "text/html": theme, "application/json": sitePage}[page.MIMEType]) {
				t.Fatalf("asset of %s %d is not its body", page.Category, page.Status)
			}
		}
	}
	if len(referenced) != 3 {
		t.Fatalf("%d referenced bodies, want 3 (unknown_site stays out)", len(referenced))
	}
	if find(pagesA, "origin_response", 500).Asset != find(pagesB, "origin_response", 500).Asset {
		t.Fatal("one body must be one asset identity")
	}
	if _, err := uuid.Parse(themed.Asset.ID); err != nil {
		t.Fatal(err)
	}

	tampered := snapshot
	tampered.Global.Rules = append([]errorpagecontrol.ProductionSnapshotRule(nil), snapshot.Global.Rules...)
	tampered.Global.Rules[0].Resource.Body = []byte("other\n")
	if _, _, err := siteErrorPageFacts(tampered, []string{siteA}, map[string][]byte{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a body that is not its digest: %v", err)
	}
	clash := snapshot
	clash.Sites = []errorpagecontrol.ProductionSnapshotSite{{SiteKey: siteA, Rules: []errorpagecontrol.ProductionSnapshotRule{
		snapshotRule("a", "origin_response", []int{404}, nil, "text/plain", globalPage),
		snapshotRule("b", "origin_response", []int{404}, nil, "text/plain", globalPage),
	}}}
	if _, _, err := siteErrorPageFacts(clash, []string{siteA}, map[string][]byte{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("equal precedence: %v", err)
	}
}

func snapshotSlot(key string, status int, region, nodeID string, body []byte) errorpagecontrol.ProductionSnapshotSlot {
	sum := sha256.Sum256(body)
	return errorpagecontrol.ProductionSnapshotSlot{Key: key, Category: "edge_connect", Status: status, Region: region, NodeID: nodeID,
		Resource: errorpagecontrol.ProductionSnapshotResource{MIMEType: "text/html", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Body: body}}
}

// errpage-ovr: the region / node overrides of http_502 / http_504 ride in
// every site object as error page variants (sorted, bodies referenced); a
// site with its own edge_connect rule for a status keeps it (no variant of
// that status); they are not node pages.
func TestSiteErrorPageVariantsFromSlots(t *testing.T) {
	theme := []byte("<!doctype html><html><head><style>body { color: #515a6e; }\n</style></head><body>502</body></html>")
	regionBody, nodeBody := []byte("<p>region 502</p>"), []byte("<p>node 504</p>")
	siteA, siteB := "0d9a0000-0000-4000-8000-000000000301", "0d9a0000-0000-4000-8000-000000000302"
	nodeID := "0d9a0000-0000-4000-8000-0000000003a1"
	snapshot := errorpagecontrol.ProductionSnapshotDocument{Schema: errorpagecontrol.ProductionSnapshotSchema,
		Global: errorpagecontrol.ProductionSnapshotScope{Rules: []errorpagecontrol.ProductionSnapshotRule{
			snapshotRule("theme.edge_connect.502", "edge_connect", []int{502}, nil, "text/html", theme),
		}},
		Sites: []errorpagecontrol.ProductionSnapshotSite{{SiteKey: siteB, Rules: []errorpagecontrol.ProductionSnapshotRule{
			snapshotRule("33333333-3333-4333-8333-333333333333", "edge_connect", []int{502}, nil, "text/plain", []byte("site own 502")),
		}}},
		Slots: []errorpagecontrol.ProductionSnapshotSlot{
			snapshotSlot("http_504", 504, "", nodeID, nodeBody),
			snapshotSlot("http_502", 502, "cn-east", "", regionBody),
			{Key: "node_ip_access", Category: "node_ip_access", Status: 403, Region: "cn-east",
				Resource: snapshotSlot("x", 403, "", "", regionBody).Resource},
		},
	}
	referenced := map[string][]byte{}
	_, variants, err := siteErrorPageFacts(snapshot, []string{siteA, siteB}, referenced)
	if err != nil {
		t.Fatal(err)
	}
	a := variants[siteA]
	if len(a) != 2 || a[0].Status != 502 || a[0].Region != "cn-east" || a[0].RuleID != "slot.http_502.region.cn-east" ||
		a[1].Status != 504 || a[1].NodeID != nodeID || a[1].Asset.SHA256 != digestBytesForTest(nodeBody) ||
		a[0].StyleHash != "" || !bytes.Equal(referenced[a[0].Asset.SHA256], regionBody) {
		t.Fatalf("site A variants %+v", a)
	}
	if b := variants[siteB]; len(b) != 1 || b[0].Status != 504 {
		t.Fatalf("site B keeps its own 502: %+v", b)
	}
	site := edgesite.Site{ErrorVariants: a}
	if digests := site.ReferencedDigests(); len(digests) != 2 {
		t.Fatalf("variant assets not referenced: %v", digests)
	}
	pages, err := nodePageFacts(snapshot, map[string][]byte{})
	if err != nil || len(pages) != 1 || pages[0].Category != "node_ip_access" {
		t.Fatalf("edge_connect slots must not be node pages: %+v %v", pages, err)
	}
	global := snapshot
	global.Slots = []errorpagecontrol.ProductionSnapshotSlot{snapshotSlot("http_502", 502, "", "", regionBody)}
	if _, _, err := siteErrorPageFacts(global, []string{siteA}, map[string][]byte{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("an edge_connect slot without a selector: %v", err)
	}
	twice := snapshot
	twice.Slots = []errorpagecontrol.ProductionSnapshotSlot{snapshotSlot("http_502", 502, "cn-east", "", regionBody),
		snapshotSlot("http_502", 502, "cn-east", "", nodeBody)}
	if _, _, err := siteErrorPageFacts(twice, []string{siteA}, map[string][]byte{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("two variants for one target: %v", err)
	}
}

func digestBytesForTest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
