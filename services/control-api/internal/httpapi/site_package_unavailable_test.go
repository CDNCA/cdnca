package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// fix-nopkgpub2 ①: the detail says why a site is not served for lack of a
// valid package; null while the package is valid. Kept out of basic (PATCH
// echoes basic and refuses unknown fields).
func TestSiteDetailPackageUnavailableReason(t *testing.T) {
	reason := site.PackageUnavailableDeleted
	for _, test := range []struct {
		name   string
		reason *string
		want   any
	}{{"valid", nil, nil}, {"deleted", &reason, reason}} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(siteDetail(site.Site{Revision: 1, PackageUnavailableReason: test.reason}))
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			value, present := body["package_unavailable_reason"]
			if !present || value != test.want {
				t.Fatalf("package_unavailable_reason=%v (present %v), want %v", value, present, test.want)
			}
			if _, inBasic := body["basic"].(map[string]any)["package_unavailable_reason"]; inBasic {
				t.Fatal("the reason must stay out of basic")
			}
		})
	}
}
