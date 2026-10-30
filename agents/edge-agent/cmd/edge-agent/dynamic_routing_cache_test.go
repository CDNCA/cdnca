package main

import (
	"encoding/json"
	"testing"
)

// N16: install-node.sh writes dynamic_routing without cache_max_bytes, so
// every fresh node ran without cache zones. Unset now means the default
// budget; an explicit 0 still means no cache zones.
func TestDynamicRoutingCacheBudgetDefaultsWhenUnset(t *testing.T) {
	shared := t.TempDir() + "/dynroute/shared" // not created yet, as on a fresh node
	for name, test := range map[string]struct {
		json string
		want func(int64) bool
	}{
		"installer config, unset": {`{"enabled":true,"worker_group":"cdnca-runtime"}`, func(v int64) bool {
			return v >= defaultCacheMinBytes && v <= defaultCacheMaxBytes && v%(1<<20) == 0
		}},
		"explicit 0 = no cache": {`{"enabled":true,"cache_max_bytes":0}`, func(v int64) bool { return v == 0 }},
		"explicit size":         {`{"enabled":true,"cache_max_bytes":1073741824}`, func(v int64) bool { return v == 1<<30 }},
	} {
		var settings dynamicRoutingSettings
		if err := json.Unmarshal([]byte(test.json), &settings); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		config := fileConfig{DynamicRouting: settings}
		if err := config.validateDynamicRouting(); err != nil {
			t.Fatalf("%s: validate %v", name, err)
		}
		got, err := dynamicRoutingCacheMaxBytes(settings, shared)
		if err != nil || !test.want(got) {
			t.Fatalf("%s: cache budget %d (%v)", name, got, err)
		}
	}
}

func TestDefaultCacheBytesIsBoundedShareOfTheFileSystem(t *testing.T) {
	for _, test := range []struct{ fileSystem, want int64 }{
		{100 << 20, 0},                  // a quarter is under the 64 MiB pool floor
		{256 << 20, 64 << 20},           // floor
		{40 << 30, 10 << 30},            // 40 GB system disk: 10 GiB
		{1 << 40, defaultCacheMaxBytes}, // capped at the 4 zone tier (64 GiB)
		{(40 << 30) + 12345, 10 << 30},  // whole MiB
	} {
		if got := defaultCacheBytes(test.fileSystem); got != test.want {
			t.Fatalf("defaultCacheBytes(%d) = %d, want %d", test.fileSystem, got, test.want)
		}
	}
}
