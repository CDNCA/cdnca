package dynroute

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// With PurgeIndex the runtime's purges go through the
// zone's index once it is built (scan before), the layout the indexes
// follow is the pool and the sites' key prefixes, and with PurgeIndex off
// the index files of an earlier run are removed.
func TestRuntimePurgeThroughIndex(t *testing.T) {
	const prefix = "aaaaaaaa0000000000000000000000a1"
	root := t.TempDir()
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1, CacheMaxBytes: 4 << 30, PurgeIndex: true,
		PurgeIndexSettings: dyncache.IndexSettings{ShadowRuns: 1,
			Local: func(string) (bool, string, error) { return true, "test", nil },
			Free:  func(string) (int64, error) { return 1 << 40, nil }}})
	if err != nil || runtime.indexes == nil {
		t.Fatalf("new: %v", err)
	}
	runtime.sites = []edgesite.Site{{SiteID: "s", TenantID: "t", Hosts: edgesite.Hosts{Primary: "a.test"},
		Listeners: []edgesite.Listener{{Port: 80}},
		Cache: &edgesite.Cache{KeyPrefix: prefix, Generation: "1111111111111111", Domain: "a.test", KeyByHost: true,
			Policy: edgeconfig.CachePolicyDocument{Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve}}}}
	runtime.zones = dyncache.Zones{Root: filepath.Join(root, "cache"), Count: 1}
	runtime.generations = &dyncache.Generations{Path: filepath.Join(root, "generations.json"), Control: okControl{}}
	layout := runtime.indexLayout()
	if layout.Root != runtime.zones.Root || layout.Zones != 1 || layout.ZoneBytes != 4<<30 || layout.Prefixes["s"] != prefix {
		t.Fatalf("layout %+v", layout)
	}
	zone, _ := runtime.zones.ZoneOf(prefix)
	write := func(path string) string {
		key := prefix + "|1111111111111111|0|a.test|80|" + path
		object := dyncache.FilePath(zone, key)
		if err := os.MkdirAll(filepath.Dir(object), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(object, append(make([]byte, 64), "\nKEY: "+key+"\n"...), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Minute)
		_ = os.Chtimes(object, old, old)
		return object
	}
	status := func() dyncache.ZoneIndexStatus {
		zones := runtime.indexes.Status().Zones
		if len(zones) != 1 {
			t.Fatalf("zones %+v", zones)
		}
		return zones[0]
	}
	purge := func() string {
		object := write("/dir/a.css")
		if _, err := runtime.Purge(context.Background(), "t", "s", []string{"http://a.test/dir/"}, true); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(object); !os.IsNotExist(err) {
			t.Fatalf("object kept: %v", err)
		}
		return status().LastPurge.Path
	}
	runtime.indexes.Configure(layout.Root, layout.Zones, layout.ZoneBytes, layout.Prefixes)
	if path := purge(); path != "scan" {
		t.Fatalf("before the build: %s", path)
	}
	runtime.indexes.Maintain(context.Background())
	if first, second := purge(), purge(); first != "shadow" || second != "index" {
		t.Fatalf("after the build: %s, %s (%+v)", first, second, status())
	}
	if _, _, err := runtime.PurgeSite(context.Background(), "t", "s"); err != nil || status().LastPurge.Path != "index" {
		t.Fatalf("site purge: %v %+v", err, status())
	}
	runtime.indexes.Close()
	if _, err := os.Stat(filepath.Join(runtime.indexDir(), "cdnca-0.db")); err != nil {
		t.Fatalf("index file: %v", err)
	}
	// purge_index false on the next start: the files go, status.json says off
	off, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1})
	if err != nil || off.indexes != nil {
		t.Fatalf("off: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(off.indexDir(), "status.json"))
	var value dyncache.IndexesStatus
	if _, err := os.Stat(filepath.Join(off.indexDir(), "cdnca-0.db")); !os.IsNotExist(err) || json.Unmarshal(raw, &value) != nil ||
		value.Enabled || value.Reason != "configured_off" {
		t.Fatalf("off: %v %s", err, raw)
	}
}
