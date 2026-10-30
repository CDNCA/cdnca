package edgepublish

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
)

// F1: published mounts reach security.mounts of that site only; a site
// without mounts encodes neither field (its digest is unchanged).
func TestSiteObjectsV2CarryRuleMounts(t *testing.T) {
	publication := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	plain, err := buildSiteObjectsV2(publication, goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain.Sites[0].Plaintext), "mounts") {
		t.Fatal("a site without mounts encodes mounts")
	}
	var mounts siteRuleMounts
	if err := json.Unmarshal([]byte(`{"mounts":[{"layer":"developer","pack_id":"dev/acme/bots","version":"1.0.0",
		"sha256":"`+strings.Repeat("a", 64)+`","engine":"waf_v2","priority":10,"params":{}}],
		"resolved_sha256":"`+strings.Repeat("b", 64)+`"}`), &mounts); err != nil {
		t.Fatal(err)
	}
	siteID := plain.Sites[0].SiteID
	built, err := buildSiteObjectsV2(publication, goldenTenant, map[string]siteObjectV2Facts{siteID: {Mounts: &mounts}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := edgesite.Decode(built.Sites[0].Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Security.Mounts) != 1 || decoded.Security.Mounts[0].PackID != "dev/acme/bots" ||
		decoded.Security.ResolvedSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("security = %+v", decoded.Security)
	}
	if built.Sites[1].SHA256 != plain.Sites[1].SHA256 {
		t.Fatal("another site's digest changed")
	}
}
