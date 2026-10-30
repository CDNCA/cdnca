package edgeskeleton

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
)

// NODE_STORAGE: the cache zones live under Paths.CacheRoot when set, under
// SharedRoot/cache otherwise (an unset root renders the bytes it always did).
func TestCacheRootMovesZones(t *testing.T) {
	plain := render(t, testInput())
	for _, want := range []string{`proxy_cache_path "/var/lib/cdnca-edge/shared/cache/cdnca-0" `, `proxy_cache_path "/var/lib/cdnca-edge/shared/cache/cdnca-1" `} {
		if !strings.Contains(plain, want) {
			t.Fatalf("default cache root: missing %s", want)
		}
	}
	input := testInput()
	input.Paths.CacheRoot = "/data/cdnca-cache"
	moved := render(t, input)
	if !strings.Contains(moved, `proxy_cache_path "/data/cdnca-cache/cdnca-0" `) || strings.Contains(moved, "shared/cache/") {
		t.Fatalf("cache root not applied:\n%s", moved)
	}
	// a moved root renames the zones (nginx refuses a reload that keeps a
	// zone name on another path) and tells the cache module the suffix
	suffix := edgecache.ZoneSuffix("/data/cdnca-cache", "")
	for _, want := range []string{"keys_zone=cdnca_cache_0" + suffix + ":", "keys_zone=cdnca_cache_1" + suffix + ":",
		`cache_zone_suffix = "` + suffix + `",`, `"~^1\|cdnca_cache_[0-9]+` + suffix + `\|0000\|HIT$" HIT;`} {
		if !strings.Contains(moved, want) {
			t.Fatalf("moved cache root: missing %s", want)
		}
	}
	if strings.Contains(plain, "cache_zone_suffix") {
		t.Fatal("default cache root: zone suffix rendered")
	}
	restored := strings.ReplaceAll(moved, "/data/cdnca-cache", "/var/lib/cdnca-edge/shared/cache")
	restored = strings.ReplaceAll(strings.ReplaceAll(restored, `      cache_zone_suffix = "`+suffix+`",`+"\n", ""), suffix, "")
	if restored != plain {
		t.Fatal("cache root changed more than the zone paths and names")
	}
	logs := testInput()
	logs.Telemetry = true
	logs.Paths.LogRoot = "/data/cdnca-logs"
	logged := render(t, logs)
	for _, want := range []string{`error_log "/data/cdnca-logs/error.log" notice;`, "/data/cdnca-logs/telemetry/dynroute/"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log root: missing %s", want)
		}
	}
	if strings.Contains(logged, "/var/lib/cdnca-edge/shared/error.log") || strings.Contains(logged, "shared/telemetry/") {
		t.Fatal("log root: a log stayed under the shared root")
	}
	input.Paths.CacheRoot = "relative/cache"
	if _, err := Render(input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative cache root: err = %v", err)
	}
}
