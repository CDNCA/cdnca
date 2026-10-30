package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// basic.cache_shared_across_domains (所有域名共用缓存)
// round-trips; omitted keeps the stored value (nil), the detail always shows it.
func TestSiteBasicCacheSharedAcrossDomainsPayloadAndResponse(t *testing.T) {
	for _, test := range []struct {
		encoded string
		want    *bool
	}{
		{encoded: `{"domains":["a.example"],"http_enabled":true,"ipv6_enabled":false}`},
		{encoded: `{"domains":["a.example"],"http_enabled":true,"ipv6_enabled":false,"cache_shared_across_domains":true}`, want: boolRef(true)},
		{encoded: `{"domains":["a.example"],"http_enabled":true,"ipv6_enabled":false,"cache_shared_across_domains":false}`, want: boolRef(false)},
	} {
		var payload siteBasicPayload
		if err := decodeSiteJSON([]byte(test.encoded), &payload); err != nil {
			t.Fatalf("%s: decode: %v", test.encoded, err)
		}
		fields, err := fieldsFromBasic(payload)
		if err != nil {
			t.Fatalf("%s: fieldsFromBasic: %v", test.encoded, err)
		}
		if (fields.CacheSharedAcrossDomains == nil) != (test.want == nil) ||
			test.want != nil && *fields.CacheSharedAcrossDomains != *test.want {
			t.Fatalf("%s: CacheSharedAcrossDomains = %v, want %v", test.encoded, fields.CacheSharedAcrossDomains, test.want)
		}
	}
	for _, shared := range []bool{false, true} {
		encoded, err := json.Marshal(siteDetail(site.Site{CacheSharedAcrossDomains: shared}))
		if err != nil {
			t.Fatal(err)
		}
		want := `"cache_shared_across_domains":false`
		if shared {
			want = `"cache_shared_across_domains":true`
		}
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("detail %s missing %s", encoded, want)
		}
	}
}

func boolRef(value bool) *bool { return &value }
