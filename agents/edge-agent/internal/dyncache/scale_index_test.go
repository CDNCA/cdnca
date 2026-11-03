//go:build scale

package dyncache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Index scenarios (index file <root>/index/cdnca-0.db, outside the zone):
// ibuild builds it from nothing, isync syncs it as it is, i<scan scenario>
// purges through it (its catch-up Sync included; reported apart).
func init() {
	scaleIndexScenarios = func(t *testing.T, zones Zones, root string) map[string]func(context.Context) (Result, error) {
		dir, _ := zones.ZoneOf(scalePrefix(0))
		path := filepath.Join(root, "index", "cdnca-0.db")
		open := func(fresh bool) *ZoneIndex {
			if fresh {
				_ = os.Remove(path)
			}
			index, err := OpenZoneIndex(dir, path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				index.Close()
				if info, err := os.Stat(path); err == nil {
					scaleNotes["index_mb"] = float64(info.Size()) / (1 << 20)
				}
			})
			return index
		}
		sync := func(fresh bool) func(context.Context) (Result, error) {
			return func(ctx context.Context) (Result, error) {
				stats, err := open(fresh).Sync(ctx)
				scaleNotes["sync"] = stats
				return Result{Affected: stats.Added}, err
			}
		}
		site := scaleSite()
		projected := site
		projected.Projected = true
		purge := func(use Site, raw string, prefix bool) func(context.Context) (Result, error) {
			target, err := ParseTarget(use, raw, prefix)
			if err != nil {
				t.Fatal(err)
			}
			return func(ctx context.Context) (Result, error) {
				index := open(false)
				return index.Purge(ctx, use, []Target{target}, prefix)
			}
		}
		return map[string]func(context.Context) (Result, error){
			"ibuild":     sync(true),
			"isync":      sync(false),
			"idir10":     purge(site, "http://www.s0.test/d0/", true),
			"idir1":      purge(site, "http://www.s0.test/d0/e0/", true),
			"iwild10":    purge(site, "http://*.img.s0.test/", true),
			"iwild1":     purge(site, "http://*.img.s0.test/d9/e0/", true),
			"iwildexact": purge(site, "http://*.img.s0.test/d9/e0/f9.css", false),
			"iexactscan": purge(projected, "http://www.s0.test/d1/e2/f21.css", false),
			"isite": func(ctx context.Context) (Result, error) {
				return open(false).PurgeSite(ctx, site, 1)
			},
		}
	}
}
