package dynroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// N16: a node with a cache budget renders the zone pool and the X-CDN-Cache
// status maps; a budget of 0 renders neither. The cache directory under the
// shared root is the workers' (0750, worker group: dynroute.New).
func TestRenderCachePoolFollowsTheBudget(t *testing.T) {
	sites := []edgesite.Site{testSite(testScopeA, testSiteA, 80)}
	for _, test := range []struct {
		budget int64
		cached bool
	}{{10 << 30, true}, {0, false}} {
		// short root: the control socket path has a length limit
		root, err := os.MkdirTemp("/tmp", "n16")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(root) })
		runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
			LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1, CacheMaxBytes: test.budget})
		if err != nil {
			t.Fatal(err)
		}
		conf, err := runtime.render(sites, dynwaf.Result{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("budget %d: %v", test.budget, err)
		}
		text := string(conf)
		for _, want := range []string{
			"proxy_cache_path " + `"` + filepath.Join(runtime.config.SharedRoot, "cache", "cdnca-0") + `"`,
			"map $cdnca_cache_show $cdnca_cache_status_header",
			"map \"$cdnca_cache_enabled|$cdnca_cache_zone|",
			"add_header X-CDN-Cache $cdnca_cache_status_header always;",
		} {
			if strings.Contains(text, want) != test.cached {
				t.Fatalf("budget %d: %q present=%v, want %v", test.budget, want, !test.cached, test.cached)
			}
		}
		if test.cached && strings.Count(text, "proxy_cache_path ") != 4 {
			t.Fatalf("budget %d: %d zones, want the 4 zone tier", test.budget, strings.Count(text, "proxy_cache_path "))
		}
		info, err := os.Stat(runtime.cacheRoot())
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
			t.Fatalf("cache root %v %v, want a 0750 worker directory", info, err)
		}
	}
}
