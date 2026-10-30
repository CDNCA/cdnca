package edgecache

import (
	"strings"
	"testing"
)

// 响应头显示缓存状态: X-CDN-Cache and
// X-CDN-Cache-Reason read gate variables that are empty unless the cache
// module set $cdnca_cache_show ("1": the site object's cache_status_header,
// or an agent prewarm); nginx adds no header for an empty value. The
// origin's own headers of those names are hidden in every case.
func TestCacheStatusHeadersFollowShow(t *testing.T) {
	pool, err := PlanPool(PoolInput{MaxBytes: 256 << 20})
	if err != nil {
		t.Fatal(err)
	}
	http := HTTP(pool, "/var/lib/cdnca-edge/shared", "", 1)
	for _, want := range []string{
		// on (site switch) and prewarm both set $cdnca_cache_show to 1
		"map $cdnca_cache_show $cdnca_cache_status_header { volatile; 1 $cdnca_cache_status; default \"\"; }",
		"map $cdnca_cache_show $cdnca_cache_reason_shown { volatile; 1 $cdnca_cache_reason_header; default \"\"; }",
	} {
		if !strings.Contains(http, want) {
			t.Fatalf("http block lacks %q", want)
		}
	}
	if !contains(Variables, "cdnca_cache_show") {
		t.Fatal("cdnca_cache_show is not a declared cache variable")
	}
	for name, location := range map[string]string{"public": PublicLocation("    "), "variants": Variants("  ", "      proxy_pass http://o;\n"),
		"follow": FollowLocationBlock("  ", "    proxy_pass http://o;\n", true)} {
		for _, want := range []string{
			"proxy_hide_header X-CDN-Cache;", "proxy_hide_header X-CDN-Cache-Reason;",
			"add_header X-CDN-Cache $cdnca_cache_status_header always;",
			"add_header X-CDN-Cache-Reason $cdnca_cache_reason_shown always;",
		} {
			if !strings.Contains(location, want) {
				t.Fatalf("%s lacks %q", name, want)
			}
		}
		// off: no ungated header anywhere
		for _, ungated := range []string{"add_header X-CDN-Cache $cdnca_cache_status ", "add_header X-CDN-Cache-Reason $cdnca_cache_reason_header "} {
			if strings.Contains(location, ungated) {
				t.Fatalf("%s answers the cache status ungated: %q", name, ungated)
			}
		}
	}
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
