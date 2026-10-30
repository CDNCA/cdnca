package edgeconfig

import (
	"strings"
	"testing"
)

// The platform's website gzip default reaches http{}
// (before, gzip was always on for text/html only and the setting was never
// read), and invalid type lists are refused.
func TestSiteRuntimeSystemGzipDefault(t *testing.T) {
	settings := testSystemNginx()
	settings.GzipTypes = []string{"application/json", "text/css", "text/html"}
	value, err := NewSiteRuntimeSystem(testPlatformScope, 1, strings.Repeat("a", 64), settings)
	if err != nil {
		t.Fatal(err)
	}
	http := SiteRuntimeSystemHTTP(&value)
	if !strings.Contains(http, "  gzip on;\n  gzip_types application/json text/css;\n") {
		t.Fatalf("gzip default not rendered:\n%s", http)
	}
	settings.GzipDisabled, settings.GzipTypes = true, nil
	if value, err = NewSiteRuntimeSystem(testPlatformScope, 1, strings.Repeat("a", 64), settings); err != nil ||
		!strings.Contains(SiteRuntimeSystemHTTP(&value), "  gzip off;\n") || strings.Contains(SiteRuntimeSystemHTTP(&value), "gzip_types") {
		t.Fatalf("gzip off not rendered: %v\n%s", err, SiteRuntimeSystemHTTP(&value))
	}
	for name, types := range map[string][]string{
		"unsorted":  {"text/css", "application/json"},
		"duplicate": {"text/css", "text/css"},
		"not MIME":  {"css"},
		"injection": {"text/css; gzip off"},
	} {
		settings := testSystemNginx()
		settings.GzipTypes = types
		if _, err := NewSiteRuntimeSystem(testPlatformScope, 1, strings.Repeat("a", 64), settings); err == nil {
			t.Errorf("%s gzip types accepted", name)
		}
	}
}

func TestSiteAccessServerRendering(t *testing.T) {
	access := &SiteAccess{
		Compression: &SiteCompression{Enabled: false, Types: []string{}},
		HSTS:        &SiteHSTS{MaxAgeSeconds: 0},
	}
	if got := SiteAccessServer("s", access, false); got != "    gzip off;\n" {
		t.Fatalf("plain listener = %q (HSTS must not be sent over HTTP)", got)
	}
	if got := SiteAccessServer("s", access, true); !strings.Contains(got, `more_set_headers "Strict-Transport-Security: max-age=0";`) {
		t.Fatalf("max-age=0 (the way to clear HSTS) not rendered: %q", got)
	}
	if SiteAccessServer("s", nil, true) != "" || SiteAccessHTTP(false) != "" {
		t.Fatal("no access settings render something")
	}
}

// encodings, levels and WebP are validated with the rest.
func TestValidateSiteAccessBrotliAndWebP(t *testing.T) {
	on := func(change func(*SiteCompression)) SiteAccess {
		value := &SiteCompression{Enabled: true, Types: []string{"text/css"}, MinLengthBytes: 256}
		change(value)
		return SiteAccess{Compression: value}
	}
	for name, access := range map[string]SiteAccess{
		"gzip only (absent)": on(func(*SiteCompression) {}),
		"brotli and gzip":    on(func(c *SiteCompression) { c.Encodings = []string{"br", "gzip"}; c.GzipLevel, c.BrotliLevel = 9, 11 }),
		"brotli only":        on(func(c *SiteCompression) { c.Encodings = []string{"br"}; c.BrotliLevel = 0 }),
		"gzip level only":    on(func(c *SiteCompression) { c.GzipLevel = 5 }),
		"webp":               {WebP: &SiteWebP{Enabled: true, Quality: 75}},
	} {
		if err := ValidateSiteAccess(access, []string{"example.com"}, false); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, access := range map[string]SiteAccess{
		"unknown encoding":       on(func(c *SiteCompression) { c.Encodings = []string{"zstd"} }),
		"unsorted":               on(func(c *SiteCompression) { c.Encodings = []string{"gzip", "br"} }),
		"empty encodings":        on(func(c *SiteCompression) { c.Encodings = []string{} }),
		"gzip level 10":          on(func(c *SiteCompression) { c.GzipLevel = 10 }),
		"brotli level 12":        on(func(c *SiteCompression) { c.Encodings = []string{"br"}; c.BrotliLevel = 12 }),
		"brotli level, no br":    on(func(c *SiteCompression) { c.BrotliLevel = 4 }),
		"gzip level, br only":    on(func(c *SiteCompression) { c.Encodings = []string{"br"}; c.GzipLevel = 4 }),
		"negative":               on(func(c *SiteCompression) { c.GzipLevel = -1 }),
		"off with encodings":     {Compression: &SiteCompression{Enabled: false, Types: []string{}, Encodings: []string{"br"}}},
		"webp off (use absence)": {WebP: &SiteWebP{}},
		"webp quality 101":       {WebP: &SiteWebP{Enabled: true, Quality: 101}},
	} {
		if ValidateSiteAccess(access, []string{"example.com"}, false) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	gzip := &SiteCompression{Enabled: true, Types: []string{"text/css"}}
	if gzip.NeedsEdgeBrotli() || (*SiteCompression)(nil).NeedsEdgeBrotli() ||
		!(&SiteCompression{Enabled: true, Types: []string{"a/b"}, Encodings: []string{"gzip"}, GzipLevel: 3}).NeedsEdgeBrotli() ||
		!(&SiteCompression{Enabled: true, Types: []string{"a/b"}, Encodings: []string{"br"}}).NeedsEdgeBrotli() {
		t.Fatal("NeedsEdgeBrotli")
	}
}
