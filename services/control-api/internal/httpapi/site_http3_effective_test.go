package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// basic.http3_enabled stays the user's
// choice; http3_effective and http3_unavailable_reason say whether the
// site's current package lets it go out. A write echoing them is accepted
// and they do not reach the stored fields.
func TestSiteBasicHTTP3Effective(t *testing.T) {
	for _, test := range []struct {
		name          string
		item          site.Site
		want, without []string
	}{
		{"allowed on", site.Site{HTTP3Enabled: true},
			[]string{`"http3_enabled":true`, `"http3_effective":true`}, []string{`http3_unavailable_reason`}},
		{"allowed off", site.Site{},
			[]string{`"http3_enabled":false`, `"http3_effective":false`}, []string{`http3_unavailable_reason`}},
		{"package excludes", site.Site{HTTP3Enabled: true, HTTP3PackageDenied: true},
			[]string{`"http3_enabled":true`, `"http3_effective":false`, `"http3_unavailable_reason":"package_feature_denied"`}, nil},
	} {
		encoded, err := json.Marshal(siteDetail(test.item))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range test.want {
			if !strings.Contains(string(encoded), want) {
				t.Fatalf("%s: response lacks %s: %s", test.name, want, encoded)
			}
		}
		for _, absent := range test.without {
			if strings.Contains(string(encoded), absent) {
				t.Fatalf("%s: response carries %s: %s", test.name, absent, encoded)
			}
		}
	}

	payload := siteBasicPayload{}
	if err := json.Unmarshal([]byte(`{"domains":["h3.example"],"http_enabled":true,"ipv6_enabled":false,`+
		`"http3_enabled":true,"http3_effective":false,"http3_unavailable_reason":"package_feature_denied"}`), &payload); err != nil {
		t.Fatalf("write echoing the read-only HTTP/3 facts: %v", err)
	}
	fields, err := fieldsFromBasic(payload)
	if err != nil || fields.HTTP3Enabled == nil || !*fields.HTTP3Enabled {
		t.Fatalf("fields = (%+v, %v), want http3_enabled true kept", fields.HTTP3Enabled, err)
	}
}
