package edgeskeleton

import (
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// a key rotation's site object may arrive before the new
// version's artifact; the node keeps serving the newest installed version
// down to the control plane's floor, and without a floor (a revocation)
// serves nothing of the older versions.
func TestURLAuthFromSitesFallsBackToInstalledVersion(t *testing.T) {
	site := func(revision, floor int64) edgesite.Site {
		return edgesite.Site{Security: edgesite.Security{
			URLAuth:              &edgesite.Ref{Kind: edgesite.RefURLAuth, ID: "p1", Revision: revision},
			URLAuthFallbackFloor: floor,
		}}
	}
	has := func(versions ...int64) func(edgesite.Ref) bool {
		return func(ref edgesite.Ref) bool {
			for _, version := range versions {
				if ref.Revision == version {
					return true
				}
			}
			return false
		}
	}
	revisions := func(auth *URLAuth) []int64 {
		out := []int64{}
		for _, ref := range auth.Policies {
			out = append(out, ref.Revision)
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		site      edgesite.Site
		installed func(edgesite.Ref) bool
		want      []int64
	}{
		{"own version installed wins", site(5, 3), has(3, 4, 5), []int64{5}},
		{"rotation in flight falls back to newest older", site(5, 3), has(3, 4), []int64{4}},
		{"floor bounds the fallback", site(5, 4), has(3), []int64{}},
		{"revocation has no fallback", site(5, 0), has(4), []int64{}},
		{"nothing installed", site(5, 3), has(), []int64{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := URLAuthFromSites([]edgesite.Site{tc.site}, "/root", tc.installed)
			if auth == nil || !reflect.DeepEqual(revisions(auth), tc.want) {
				t.Fatalf("got %+v, want revisions %v", auth, tc.want)
			}
		})
	}
}
