package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
)

// The v2 document's site.access.hsts becomes the site
// object's own hsts (D9 dynfilters sends it); access keeps the rest and is
// dropped when HSTS was all it held. An object carrying access.hsts is refused.
func TestSiteObjectV2AccessHSTSMovesToObjectField(t *testing.T) {
	publication := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e11"), 1, 0)
	entry := publication.Sites[0]
	runtime := entry.Runtime
	if !siteRuntimeHasTLS(runtime) {
		t.Skip("golden site has no TLS listener")
	}
	convert := func(access *edgeconfig.SiteAccess) edgesite.Site {
		t.Helper()
		runtime.Access = access
		site := entry
		site.Runtime = runtime
		converted, err := convertSiteObjectV2(site, publication.ScopeID, goldenTenant.String(), publication.Files,
			publication.fileObjects(), siteObjectV2Facts{}, map[string][]byte{})
		if err != nil {
			t.Fatal(err)
		}
		if err := edgesite.Validate(converted); err != nil {
			t.Fatalf("converted object invalid: %v", err)
		}
		return converted
	}
	hsts := &edgeconfig.SiteHSTS{MaxAgeSeconds: 31536000, IncludeSubdomains: true, Preload: true}
	only := convert(&edgeconfig.SiteAccess{HSTS: hsts})
	if only.HSTS == nil || *only.HSTS != (edgesite.HSTS{MaxAgeSeconds: 31536000, IncludeSubdomains: true, Preload: true}) || only.Access != nil {
		t.Fatalf("hsts only: hsts %+v access %+v", only.HSTS, only.Access)
	}
	limits := &edgeconfig.SiteRequestLimits{ConnectionsPerIP: 8}
	mixed := convert(&edgeconfig.SiteAccess{HSTS: hsts, Limits: limits})
	if mixed.HSTS == nil || mixed.Access == nil || mixed.Access.HSTS != nil || mixed.Access.Limits == nil {
		t.Fatalf("hsts + limits: hsts %+v access %+v", mixed.HSTS, mixed.Access)
	}
	if none := convert(nil); none.HSTS != nil || none.Access != nil {
		t.Fatalf("no access: hsts %+v access %+v", none.HSTS, none.Access)
	}
	mixed.Access.HSTS = hsts
	if err := edgesite.Validate(mixed); err == nil {
		t.Fatal("site object with access.hsts accepted")
	}
}

func siteRuntimeHasTLS(runtime siteRuntimeV2Site) bool {
	for _, listener := range runtime.Listeners {
		if listener.TLS != nil {
			return true
		}
	}
	return false
}
