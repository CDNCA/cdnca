package edgepublish

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
)

// the site fact ServerTiming reaches the site
// object as server_timing; off it is absent and the object is unchanged.
func TestSiteObjectsV2CarryServerTiming(t *testing.T) {
	publication := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	plain, err := buildSiteObjectsV2(publication, goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	siteID := plain.Sites[0].SiteID
	off, err := buildSiteObjectsV2(publication, goldenTenant, map[string]siteObjectV2Facts{siteID: {ServerTiming: false}})
	if err != nil || off.Sites[0].SHA256 != plain.Sites[0].SHA256 || strings.Contains(string(off.Sites[0].Plaintext), "server_timing") {
		t.Fatalf("server_timing off changed the object: %v", err)
	}
	built, err := buildSiteObjectsV2(publication, goldenTenant, map[string]siteObjectV2Facts{siteID: {ServerTiming: true}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := edgesite.Decode(built.Sites[0].Plaintext)
	if err != nil || !decoded.ServerTiming {
		t.Fatalf("decoded server_timing %v %v", decoded.ServerTiming, err)
	}
	if built.Sites[0].SHA256 == plain.Sites[0].SHA256 || built.Sites[1].SHA256 != plain.Sites[1].SHA256 {
		t.Fatal("only the site whose switch changed may change digest")
	}
}

// the site fact StringSets becomes
// security.string_sets, which must be exactly what the rules reference: a
// set no rule references is refused rather than published.
func TestSiteObjectsV2StringSetsMustBeReferenced(t *testing.T) {
	publication := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	plain, err := buildSiteObjectsV2(publication, goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	set := edgesite.StringSet{ID: "0190a000-0000-7000-8000-0000000000c7", Revision: 1, Mode: edgeconfig.StringSetExact,
		CaseSensitive: true, Members: []string{"x"}}
	_, err = buildSiteObjectsV2(publication, goldenTenant, map[string]siteObjectV2Facts{plain.Sites[0].SiteID: {StringSets: []edgesite.StringSet{set}}})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "string set") {
		t.Fatalf("unreferenced string set: %v", err)
	}
}
