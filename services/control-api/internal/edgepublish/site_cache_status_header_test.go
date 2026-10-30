package edgepublish

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
)

// The site object carries the published switch
// (cache_status_header), only that site's object changes, and the encoding
// round-trips through the node's strict decoder.
func TestSiteObjectsV2CarryCacheStatusHeader(t *testing.T) {
	publication := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	plain, err := buildSiteObjectsV2(publication, goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain.Sites[0].Plaintext), "cache_status_header") {
		t.Fatal("a site with the header off encodes cache_status_header")
	}
	siteID := plain.Sites[0].SiteID
	built, err := buildSiteObjectsV2(publication, goldenTenant, map[string]siteObjectV2Facts{siteID: {CacheStatusHeader: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(built.Sites[0].Plaintext), `"cache_status_header":true`) {
		t.Fatalf("site object = %s", built.Sites[0].Plaintext)
	}
	decoded, err := edgesite.Decode(built.Sites[0].Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.CacheStatusHeader {
		t.Fatal("decoded site lost cache_status_header")
	}
	if built.Sites[0].SHA256 == plain.Sites[0].SHA256 || built.Sites[1].SHA256 != plain.Sites[1].SHA256 {
		t.Fatal("only the site whose switch changed may change digest")
	}
}

// Levels as escalate_site_states holds them: "" (no row or no lock) is A.
func TestSiteCacheStatusHeaderFollowsEscalation(t *testing.T) {
	for _, item := range []struct {
		name                   string
		enabled                bool
		level, applied, locked string
		want                   bool
	}{
		{"no state row", true, "", "", "", true},
		{"level A", true, "A", "A", "", true},
		{"switch off", false, "A", "A", "", false},
		{"A to B target", true, "B", "A", "", false},
		{"B applied", true, "B", "B", "", false},
		{"C", true, "C", "C", "", false},
		{"D", true, "D", "D", "", false},
		{"B back to A target, DNS not moved yet", true, "A", "B", "", false},
		{"B back to A", true, "A", "A", "", true},
		{"locked at B before the worker moves", true, "A", "A", "B", false},
		{"locked at A", true, "A", "A", "A", true},
	} {
		if got := SiteCacheStatusHeader(item.enabled, item.level, item.applied, item.locked); got != item.want {
			t.Errorf("%s: got %v, want %v", item.name, got, item.want)
		}
	}
}
