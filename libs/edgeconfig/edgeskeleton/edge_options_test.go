package edgeskeleton

import (
	"strings"
	"testing"
)

// site-backend6: every shared server has the unbuffered locations (only
// they turn buffering off) and, with the ACME overlay, sends a token the
// node does not hold to @cdnca_acme_origin instead of 404.
func TestRenderSiteEdgeOptionLocations(t *testing.T) {
	input := testInput()
	input.ACMEOverlayRoot = "/var/lib/cdnca-edge/state"
	block := server(t, render(t, input), 80)
	for _, want := range []string{
		"    location @cdnca_unbuffered_response {\n",
		"    location @cdnca_unbuffered_request {\n",
		"    location @cdnca_unbuffered_both {\n",
		"try_files /$host/$cdnca_acme_token @cdnca_acme_origin;\n",
		"    location @cdnca_acme_origin {\n      rewrite_by_lua_block { return }\n      access_by_lua_block { return require(\"dynroute.cdnca_dynroute\").acme_origin() }\n",
	} {
		if !strings.Contains(block, want) {
			t.Fatalf("server 80 lacks %q", want)
		}
	}
	if strings.Contains(block, "=404;\n") {
		t.Fatal("the ACME location still ends in =404")
	}
	// buffering is off only in the unbuffered locations, never in location /
	root := block[strings.Index(block, "    location / {\n"):]
	root = root[:strings.Index(root, "    }\n")]
	if strings.Contains(root, "proxy_buffering off") || strings.Contains(root, "proxy_request_buffering off") {
		t.Fatal("location / must keep buffering (the cache needs it)")
	}
	both := block[strings.Index(block, "    location @cdnca_unbuffered_both {\n"):]
	both = both[:strings.Index(both, "    }\n")]
	if !strings.Contains(both, "proxy_buffering off;\n") || !strings.Contains(both, "proxy_request_buffering off;\n") ||
		!strings.Contains(both, "proxy_pass $cdnca_origin_scheme://") {
		t.Fatalf("@cdnca_unbuffered_both: %s", both)
	}
}
