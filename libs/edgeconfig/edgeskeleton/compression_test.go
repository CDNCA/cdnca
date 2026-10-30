package edgeskeleton

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Brotli and the level variables only when a site uses
// them (they need EDGE_BROTLI), on every server; WebP renders its thread
// pool (main context), dictionary and nothing else.
func TestRenderSiteBrotliAndWebP(t *testing.T) {
	off := render(t, testInput())
	for _, unwanted := range []string{"brotli", "cdnca_compress_", "thread_pool", "cdnca_webp"} {
		if strings.Contains(off, unwanted) {
			t.Fatalf("%q rendered while off", unwanted)
		}
	}
	input := testInput()
	input.SiteGzip, input.SiteBrotli, input.SiteWebP = true, true, true
	config := render(t, input)
	for _, port := range []int{80, 443, 8443} {
		if !strings.Contains(server(t, config, port), siteGzipServer+siteBrotliServer) {
			t.Fatalf("server %d lacks the Brotli directives", port)
		}
	}
	for _, want := range []string{
		"site_brotli = true,\n",
		`set $cdnca_compress_gzip_level "";`, `set $cdnca_compress_brotli_level "";`,
		"lua_shared_dict cdnca_webp 256m;\n",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("missing %q", want)
		}
	}
	// thread_pool is a main-context directive: before http{}
	pool := strings.Index(config, "thread_pool cdnca_webp threads=2 max_queue=64;\n")
	if pool < 0 || pool > strings.Index(config, "http {") {
		t.Fatal("thread pool not in the main context")
	}
}

func TestSiteBrotliAndWebPFromSites(t *testing.T) {
	gzipOnly := edgesite.Site{Access: &edgeconfig.SiteAccess{Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/css"}}}}
	brotli := edgesite.Site{Access: &edgeconfig.SiteAccess{Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/css"},
		Encodings: []string{"br", "gzip"}}}}
	level := edgesite.Site{Access: &edgeconfig.SiteAccess{Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/css"},
		Encodings: []string{"gzip"}, GzipLevel: 6}}}
	webp := edgesite.Site{Access: &edgeconfig.SiteAccess{WebP: &edgeconfig.SiteWebP{Enabled: true}}}
	if SiteBrotliFromSites([]edgesite.Site{{}, gzipOnly, webp}) || !SiteBrotliFromSites([]edgesite.Site{gzipOnly, brotli}) ||
		!SiteBrotliFromSites([]edgesite.Site{level}) {
		t.Fatal("SiteBrotliFromSites")
	}
	if SiteWebPFromSites([]edgesite.Site{{}, brotli}) || !SiteWebPFromSites([]edgesite.Site{gzipOnly, webp}) {
		t.Fatal("SiteWebPFromSites")
	}
}
