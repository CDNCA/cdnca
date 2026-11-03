package dyncache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

// indexCorpus writes the same objects into a zone root: two sites in one
// zone, hosts under and outside wildcards, two ports, generations, queries,
// slices, a v7 key and a tampered file.
func indexCorpus(t *testing.T, zones Zones) {
	t.Helper()
	now := time.Now()
	hosts := []string{"a.test", "www.a.test", "img.a.test", "x.y.a.test", "a.testx", "*.a.test"}
	paths := []string{"/", "/a.css", "/dir", "/dir/", "/dir/b.css", "/dir/sub/c.css", "/dirx/d.css", "/dir%2f/e"}
	count := 0
	for _, host := range hosts {
		for _, port := range []int{80, 443} {
			for _, path := range paths {
				for generation := uint64(0); generation < 2; generation++ {
					// whole objects, query variants, policy slices and chunk files
					// of both chunk generations (ADR 0021 §8: <key>|slice=…[|e=n])
					for _, suffix := range []string{"", "?v=1", "|slice=bytes=0-1", "|slice=bytes=4194304-8388607",
						"|slice=bytes=0-4194303|e=1730000000", "?v=1|slice=bytes=0-4194303|e=1730000000"} {
						writeObject(t, zones, prefixA, key(siteA(), generation, host, port, path+suffix), 1, now)
						count++
					}
				}
			}
		}
	}
	for _, path := range paths {
		writeObject(t, zones, prefixB, key(siteB(), 0, "b.test", 80, path), 1, now)
	}
	// a v7 key and a file whose name is not md5(key): never removed
	writeObject(t, zones, prefixA, "v2|0a1b9999-0000-4000-8000-000000000001|site|config|a.test|80|/a", 1, now)
	path := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/tampered"), 1, now)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "0123456789abcdef0123456789abcdef"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func remaining(t *testing.T, root string) []string {
	t.Helper()
	var names []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			rel, _ := filepath.Rel(root, path)
			names = append(names, rel)
		}
		return nil
	})
	slices.Sort(names)
	return names
}

func openIndex(t *testing.T, zones Zones, prefix string) *ZoneIndex {
	t.Helper()
	dir, _ := zones.ZoneOf(prefix)
	index, err := OpenZoneIndex(dir, filepath.Join(t.TempDir(), "zone.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { index.Close() })
	return index
}

// The index removes exactly what the zone scan removes, target by target;
// purges run in steps of removeBatch candidates (3 here: many steps, each
// resuming after keys it did not accept).
func TestIndexPurgeEqualsScan(t *testing.T) {
	saved := removeBatch
	removeBatch = 3
	t.Cleanup(func() { removeBatch = saved })
	ctx := context.Background()
	byDomain := siteA()
	byDomain.KeyByHost, byDomain.Domain = false, "*.a.test"
	projected := siteA()
	projected.Projected = true
	cases := []struct {
		site   Site
		url    string
		prefix bool
	}{
		{siteA(), "http://a.test/dir/", true}, {siteA(), "http://a.test/dir", true}, {siteA(), "http://a.test/", true},
		{siteA(), "https://www.a.test/dir/sub/", true}, {siteA(), "http://*.a.test/", true}, {siteA(), "http://*.a.test/dir/", true},
		{siteA(), "http://*.y.a.test/", true}, {siteA(), "http://*.a.test/a.css", false}, {siteA(), "http://a.test/a.css?v=1", false},
		{projected, "http://www.a.test/a.css", false},
		{byDomain, "http://*.a.test/dir/", true}, {byDomain, "http://*.a.test/a.css", false}, {siteB(), "http://b.test/dir/", true},
	}
	for _, item := range cases {
		target, err := ParseTarget(item.site, item.url, item.prefix)
		if err != nil {
			t.Fatalf("%s: %v", item.url, err)
		}
		scanned, indexed := Zones{Root: t.TempDir(), Count: 4}, Zones{Root: t.TempDir(), Count: 4}
		indexCorpus(t, scanned)
		indexCorpus(t, indexed)
		index := openIndex(t, indexed, prefixA)
		if _, err := index.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		want, err := scanned.Purge(ctx, item.site, []Target{target}, item.prefix, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := index.Purge(ctx, item.site, []Target{target}, item.prefix)
		if err != nil || got.Affected != want.Affected || want.Affected == 0 {
			t.Fatalf("%s: index %+v %v, scan %+v", item.url, got, err, want)
		}
		if left, right := remaining(t, indexed.Root), remaining(t, scanned.Root); !slices.Equal(left, right) {
			t.Fatalf("%s: index leaves %d files, scan %d", item.url, len(left), len(right))
		}
	}
	// whole site: older generations only
	scanned, indexed := Zones{Root: t.TempDir(), Count: 4}, Zones{Root: t.TempDir(), Count: 4}
	indexCorpus(t, scanned)
	indexCorpus(t, indexed)
	index := openIndex(t, indexed, prefixA)
	if _, err := index.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	generation, want, err := scanned.PurgeSite(ctx, &Generations{Path: filepath.Join(t.TempDir(), "g"), Control: &fakeControl{}}, siteA())
	if err != nil {
		t.Fatal(err)
	}
	got, err := index.PurgeSite(ctx, siteA(), generation)
	if err != nil || got.Affected != want.Affected || !slices.Equal(remaining(t, indexed.Root), remaining(t, scanned.Root)) {
		t.Fatalf("site: index %+v %v, scan %+v", got, err, want)
	}
}

// Objects filled or evicted after the index was built are seen by the next
// purge (it syncs first); the index is complete only after a full Sync.
func TestIndexFollowsTheDisk(t *testing.T) {
	ctx := context.Background()
	zones := Zones{Root: t.TempDir(), Count: 1}
	now := time.Now()
	old := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/dir/old.css"), 1, now)
	index := openIndex(t, zones, prefixA)
	target, _ := ParseTarget(siteA(), "http://a.test/dir/", true)
	if _, err := index.Purge(ctx, siteA(), []Target{target}, true); !errors.Is(err, ErrIndexUnavailable) {
		t.Fatalf("an index never synced answered: %v", err)
	}
	// purgeIndexed falls back to the zone scan
	if result, err := zones.purgeIndexed(ctx, index, siteA(), []Target{target}, true, nil); err != nil || result.Affected != 1 || exists(old) {
		t.Fatalf("fallback: %+v %v", result, err)
	}
	if stats, err := index.Sync(ctx); err != nil || !index.Complete() || stats.Added != 0 {
		t.Fatalf("sync: %+v %v", stats, err)
	}
	// filled after the sync, in a directory already listed and in a new one
	var filled []string
	for i := range 50 {
		filled = append(filled, writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/dir/n"+strconv.Itoa(i)), 1, now))
	}
	evicted := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/dir/evicted"), 1, now)
	if _, err := index.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(evicted); err != nil { // the cache manager evicts it
		t.Fatal(err)
	}
	result, err := zones.purgeIndexed(ctx, index, siteA(), []Target{target}, true, nil)
	if err != nil || result.Affected != 50 {
		t.Fatalf("purge: %+v %v", result, err)
	}
	for _, path := range filled {
		if exists(path) {
			t.Fatalf("left %s", path)
		}
	}
	if stats, err := index.Sync(ctx); err != nil || stats.Removed != 0 || stats.Added != 0 {
		t.Fatalf("index after purge: %+v %v", stats, err)
	}
}

// A directory listed within Settle of its mtime is listed again: a file
// created in the same mtime tick as the listing is not missed.
func TestIndexRelistsRacyDirectories(t *testing.T) {
	ctx := context.Background()
	zones := Zones{Root: t.TempDir(), Count: 1}
	first := key(siteA(), 0, "a.test", 80, "/dir/a")
	path := writeObject(t, zones, prefixA, first, 1, time.Now())
	index := openIndex(t, zones, prefixA)
	if _, err := index.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// a second file in the same directory with the mtime put back: only the
	// racy mark makes the next Sync list the directory again
	dir := filepath.Dir(path)
	info, _ := os.Stat(dir)
	second := "/dir/" + sameDir(t, first)
	late := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, second), 1, time.Now())
	if err := os.Chtimes(dir, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if stats, err := index.Sync(ctx); err != nil || stats.Added != 1 {
		t.Fatalf("racy directory not listed again: %+v %v", stats, err)
	}
	// settled: not listed any more
	index.Now = func() time.Time { return time.Now().Add(time.Minute) }
	if _, err := index.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if stats, err := index.Sync(ctx); err != nil || stats.Listed != 0 {
		t.Fatalf("settled directory listed: %+v %v", stats, err)
	}
	// control: the same change to a settled directory with its mtime put
	// back is invisible to Sync, which is why the racy mark exists
	if err := os.Remove(late); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(dir)
	if _, err := index.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	again := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, second), 1, time.Now())
	if err := os.Chtimes(dir, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if stats, err := index.Sync(ctx); err != nil || stats.Listed != 0 || !exists(again) {
		t.Fatalf("control: %+v %v", stats, err)
	}
}

// sameDir finds a path whose key lands in the same level directory as key.
func sameDir(t *testing.T, key string) string {
	t.Helper()
	want := filepath.Dir(FilePath("", key))
	for i := range 1 << 20 {
		name := "s" + strconv.Itoa(i)
		candidate := key[:len(key)-len("/dir/a")] + "/dir/" + name
		if filepath.Dir(FilePath("", candidate)) == want {
			return name
		}
	}
	t.Fatal("no path in the same directory")
	return ""
}

func TestIndexFileOutsideTheZone(t *testing.T) {
	zones := Zones{Root: t.TempDir(), Count: 1}
	dir, _ := zones.ZoneOf(prefixA)
	if _, err := OpenZoneIndex(dir, filepath.Join(dir, "index.db")); err == nil {
		t.Fatal("index file inside the zone accepted")
	}
	// a corrupt index file is rebuilt
	path := filepath.Join(t.TempDir(), "zone.db")
	if err := os.WriteFile(path, []byte("not a bbolt file"), 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := OpenZoneIndex(dir, path)
	if err != nil || index.Complete() {
		t.Fatalf("corrupt index: %v", err)
	}
	index.Close()
}

// ADR 0021: a chunk file's key parses to its URL's path and
// policy key, so a directory or wildcard purge through the index removes
// the URL's whole object and every chunk file (both chunk generations);
// an exact purge on a chunking node keeps the chunk path fast path.
func TestIndexPurgesChunkFilesWithTheirURL(t *testing.T) {
	ctx := context.Background()
	zones := Zones{Root: t.TempDir(), Count: 4}
	site := siteA()
	site.ChunkBytes = testChunk
	now := time.Now()
	whole := key(site, 0, "img.a.test", 443, "/v/a.mp4")
	files := []string{writeObject(t, zones, prefixA, whole, 1, now)}
	for _, epoch := range []int64{0, 1730000000} {
		for _, index := range []int64{0, 5} {
			files = append(files, writeChunk(t, zones, whole, index, epoch, 6*testChunk))
		}
	}
	keep := writeChunk(t, zones, key(site, 0, "img.a.test", 443, "/w/b.mp4"), 0, 0, testChunk)
	index := openIndex(t, zones, prefixA)
	if _, err := index.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://img.a.test/v/", "https://*.a.test/v/"} {
		target, err := ParseTarget(site, raw, true)
		if err != nil {
			t.Fatal(err)
		}
		result, err := zones.purgeIndexed(ctx, index, site, []Target{target}, true, nil)
		if err != nil || result.Affected != len(files) {
			t.Fatalf("%s: %+v %v", raw, result, err)
		}
		for _, path := range files {
			if exists(path) {
				t.Fatalf("%s: left %s", raw, path)
			}
		}
		if !exists(keep) {
			t.Fatalf("%s: another URL's chunk removed", raw)
		}
		// written again for the wildcard round
		files = []string{writeObject(t, zones, prefixA, whole, 1, now)}
		for _, epoch := range []int64{0, 1730000000} {
			for _, index := range []int64{0, 5} {
				files = append(files, writeChunk(t, zones, whole, index, epoch, 6*testChunk))
			}
		}
	}
	// exact on a chunking node: the chunk path fast path, not the index
	// (the cache module's forget is asked; a scan or the index would not)
	control := &chunkControl{states: map[string]chunkState{whole: {Epoch: 1730000000, Total: 6 * testChunk, Kind: "c"}}}
	generations := &Generations{Path: filepath.Join(t.TempDir(), "g.json"), Control: control, values: map[string]uint64{prefixA: 0}}
	target, _ := ParseTarget(site, "https://img.a.test/v/a.mp4", false)
	result, err := zones.purgeIndexed(ctx, index, site, []Target{target}, false, generations)
	if err != nil || result.Affected != len(files) || len(control.asked) != 1 {
		t.Fatalf("exact: %+v %v asked %v", result, err, control.asked)
	}
	// the control socket down: the exact purge falls back to the index
	files = []string{writeObject(t, zones, prefixA, whole, 1, now), writeChunk(t, zones, whole, 1, 0, 6*testChunk)}
	control.fail = true
	if result, err := zones.purgeIndexed(ctx, index, site, []Target{target}, false, generations); err != nil || result.Affected != 2 {
		t.Fatalf("exact fallback: %+v %v", result, err)
	}
	if !exists(keep) {
		t.Fatal("another URL's chunk removed")
	}
}

// purgeIndexed (test helper): Zones.Purge with one zone index, without
// Indexes' states: the exact fast path, else the index, else the scan.
// : the exact fast path as Purge
// takes it (chunk files by path on a chunking node), else the index (whole
// objects and chunk files: a chunk's key parses to its URL's path and
// policy key), else (index unavailable) the zone scan.
func (zones Zones) purgeIndexed(ctx context.Context, index *ZoneIndex, site Site, targets []Target, prefix bool,
	generations *Generations) (Result, error) {
	if result, done, err := zones.exactFast(ctx, site, targets, prefix, generations); done || err != nil {
		return result, err
	}
	if index != nil {
		dir, err := zones.ZoneOf(site.Prefix)
		if err == nil && dir == index.Dir {
			result, err := index.Purge(ctx, site, targets, prefix)
			if !errors.Is(err, ErrIndexUnavailable) {
				return result, err
			}
		}
	}
	return zones.Purge(ctx, site, targets, prefix, nil)
}
