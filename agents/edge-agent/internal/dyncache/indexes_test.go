package dyncache

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// indexFixture: siteA and siteB in zone 2 of a 4 zone pool, objects under
// /d/ of siteA, and a manager whose file system checks the test controls.
type indexFixture struct {
	t       *testing.T
	ctx     context.Context
	zones   Zones
	indexes *Indexes
	local   bool
	free    int64
	objects []string
}

func newIndexFixture(t *testing.T, settings IndexSettings) *indexFixture {
	fixture := &indexFixture{t: t, ctx: context.Background(), zones: Zones{Root: t.TempDir(), Count: 4}, local: true, free: 1 << 40}
	settings.Local = func(string) (bool, string, error) { return fixture.local, "test", nil }
	settings.Free = func(string) (int64, error) { return fixture.free, nil }
	fixture.indexes = NewIndexes(t.TempDir(), settings)
	t.Cleanup(fixture.indexes.Close)
	fixture.write()
	writeObject(t, fixture.zones, prefixB, key(siteB(), 0, "b.test", 80, "/d/1.css"), 1, time.Now().Add(-time.Minute))
	return fixture
}

// write (re)writes siteA's four objects a minute old, their level
// directories too: a later sync of an index lists those directories once
// and then trusts them (not racy).
func (fixture *indexFixture) write() {
	fixture.t.Helper()
	old := time.Now().Add(-time.Minute)
	fixture.objects = nil
	for _, path := range []string{"/d/1.css", "/d/2.css", "/d/sub/3.css", "/e/4.css"} {
		object := writeObject(fixture.t, fixture.zones, prefixA, key(siteA(), 0, "a.test", 80, path), 1, old)
		fixture.objects = append(fixture.objects, object)
		if err := os.Chtimes(filepath.Dir(object), old, old); err != nil {
			fixture.t.Fatal(err)
		}
	}
}

func (fixture *indexFixture) configure() {
	fixture.indexes.Configure(fixture.zones.Root, fixture.zones.Count, 1<<30, map[string]string{"a": prefixA, "b": prefixB})
	fixture.indexes.Maintain(fixture.ctx)
}

func (fixture *indexFixture) zone() ZoneIndexStatus {
	for _, zone := range fixture.indexes.Status().Zones {
		if zone.Zone == 2 {
			return zone
		}
	}
	fixture.t.Fatal("zone 2 missing")
	return ZoneIndexStatus{}
}

// purge rewrites the objects and purges /d/ of siteA; it returns the path
// the purge took.
func (fixture *indexFixture) purge() (Result, string) {
	fixture.t.Helper()
	fixture.write()
	return fixture.purgeOnly()
}

func (fixture *indexFixture) purgeOnly() (Result, string) {
	fixture.t.Helper()
	target, _ := ParseTarget(siteA(), "http://a.test/d/", true)
	result, err := fixture.indexes.Purge(fixture.ctx, fixture.zones, siteA(), []Target{target}, true, nil)
	if err != nil {
		fixture.t.Fatal(err)
	}
	for _, path := range fixture.objects[:3] {
		if exists(path) {
			fixture.t.Fatalf("%s left by the purge", path)
		}
	}
	if !exists(fixture.objects[3]) {
		fixture.t.Fatal("an object outside the directory removed")
	}
	zone := fixture.zone()
	return result, zone.LastPurge.Path
}

// unindex drops a file from zone 2's index without touching the disk: the
// index no longer knows a file that is there (what a shadow check exists
// to catch).
func (fixture *indexFixture) unindex(path string) {
	fixture.t.Helper()
	entry := fixture.indexes.zones[2]
	id, _ := fileIDOf(path)
	if err := entry.index.db.Update(func(tx *bolt.Tx) error {
		_, err := entry.index.drop(tx.Bucket(bucketFiles), tx.Bucket(bucketSites), id[:])
		return err
	}); err != nil {
		fixture.t.Fatal(err)
	}
}

// A built zone is checked in shadow: ShadowRuns consistent purges (the scan
// removes, the index is compared) turn it active; then purges go through
// the index, and every RecheckPurges one runs as in shadow again.
func TestIndexesShadowThenActive(t *testing.T) {
	fixture := newIndexFixture(t, IndexSettings{ShadowRuns: 2, RecheckPurges: 3})
	// configured, not built yet: the scan
	fixture.indexes.Configure(fixture.zones.Root, fixture.zones.Count, 1<<30, map[string]string{"a": prefixA, "b": prefixB})
	if result, path := fixture.purgeOnly(); result.Affected != 3 || path != "scan" || fixture.zone().LastPurge.Reason != string(IndexBuilding) {
		t.Fatalf("unbuilt: %+v %s %+v", result, path, fixture.zone())
	}
	fixture.configure()
	if zone := fixture.zone(); zone.State != IndexShadow || zone.ShadowLeft != 2 || zone.Objects != 2 {
		t.Fatalf("built: %+v", zone)
	}
	var paths []string
	for range 6 {
		result, path := fixture.purge()
		if result.Affected != 3 {
			t.Fatalf("purge %d removed %d", len(paths), result.Affected)
		}
		paths = append(paths, path)
	}
	want := []string{"shadow", "shadow", "index", "index", "shadow", "index"}
	if !equalStrings(paths, want) || fixture.zone().State != IndexActive || fixture.zone().Mismatches != 0 {
		t.Fatalf("paths %v (want %v), zone %+v", paths, want, fixture.zone())
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// A shadow purge that finds a file the index does not know drops the
// index and rebuilds it; past MaxRebuilds the zone is disabled until the
// agent restarts, and purges scan. The scan decided every time: nothing
// was left behind.
func TestIndexesShadowMismatchRebuildsThenDisables(t *testing.T) {
	fixture := newIndexFixture(t, IndexSettings{ShadowRuns: 3, MaxRebuilds: 1})
	fixture.configure()
	for round := range 2 {
		fixture.write()
		if _, err := fixture.indexes.zones[2].index.Sync(fixture.ctx); err != nil {
			t.Fatal(err)
		}
		fixture.unindex(fixture.objects[0])
		if result, path := fixture.purgeOnly(); path != "shadow" || result.Affected != 3 {
			t.Fatalf("round %d: %s %+v", round, path, result)
		}
		zone := fixture.zone()
		if zone.Mismatches != round+1 || zone.Missed != 1 {
			t.Fatalf("round %d: %+v", round, zone)
		}
		if round == 0 {
			if zone.State != IndexBuilding || zone.Reason != ReasonShadowMismatch {
				t.Fatalf("not rebuilding: %+v", zone)
			}
			if _, err := os.Stat(fixture.indexes.zones[2].file); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("index file kept: %v", err)
			}
			fixture.configure()
			if zone := fixture.zone(); zone.State != IndexShadow {
				t.Fatalf("not rebuilt: %+v", zone)
			}
		}
	}
	zone := fixture.zone()
	if zone.State != IndexDisabled || zone.Reason != ReasonShadowMismatch || zone.Rebuilds != 2 {
		t.Fatalf("not disabled: %+v", zone)
	}
	fixture.configure() // sticky: no rebuild
	if _, path := fixture.purge(); path != "scan" || fixture.zone().State != IndexDisabled {
		t.Fatalf("disabled zone: %s %+v", path, fixture.zone())
	}
}

// A different zone count or cache root drops every index (the files of a
// site are in another zone now) and builds new ones; a site whose key
// prefix changed rebuilds the zones of its old and new prefix.
func TestIndexesRebuildOnLayoutChange(t *testing.T) {
	fixture := newIndexFixture(t, IndexSettings{})
	fixture.configure()
	old := fixture.indexes.zones[2].file
	if !exists(old) || fixture.zone().State != IndexShadow {
		t.Fatalf("not built: %+v", fixture.zone())
	}
	// zone count 4 -> 8: siteA's prefix aaaaaaaa maps to zone 2 of 8 too,
	// but the index (built for 4 zones) is dropped
	fixture.zones.Count = 8
	fixture.indexes.Configure(fixture.zones.Root, 8, 1<<30, map[string]string{"a": prefixA, "b": prefixB})
	if zone := fixture.zone(); zone.State != IndexBuilding || zone.Reason != ReasonLayoutChanged {
		t.Fatalf("layout change: %+v", zone)
	}
	if result, path := fixture.purgeOnly(); result.Affected != 3 || path != "scan" {
		t.Fatalf("purge during rebuild: %+v %s %+v", result, path, fixture.zone())
	}
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexShadow || len(fixture.indexes.Status().Zones) != 8 {
		t.Fatalf("not rebuilt: %+v (%d zones)", zone, len(fixture.indexes.Status().Zones))
	}
	// a purge with the old layout (a stale caller) scans that layout
	stale := Zones{Root: fixture.zones.Root, Count: 4}
	target, _ := ParseTarget(siteA(), "http://a.test/d/", true)
	if _, err := fixture.indexes.Purge(fixture.ctx, stale, siteA(), []Target{target}, true, nil); err != nil {
		t.Fatal(err)
	}
	// key prefix of siteB changes (zone 2 -> zone 3 of 8)
	const moved = "bbbbbbbb0000000000000000000000b3"
	fixture.indexes.Configure(fixture.zones.Root, 8, 1<<30, map[string]string{"a": prefixA, "b": moved})
	for _, number := range []int{2, 3} {
		if zone := fixture.indexes.Status().Zones[number]; zone.State != IndexBuilding || zone.Reason != ReasonPrefixChanged {
			t.Fatalf("zone %d after prefix change: %+v", number, zone)
		}
	}
	if zone := fixture.indexes.Status().Zones[0]; zone.State != IndexShadow {
		t.Fatalf("an unrelated zone rebuilt: %+v", zone)
	}
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexShadow || zone.Reason != "" {
		t.Fatalf("not rebuilt after prefix change: %+v", zone)
	}
	// a new site (no earlier prefix) rebuilds nothing
	fixture.indexes.Configure(fixture.zones.Root, 8, 1<<30, map[string]string{"a": prefixA, "b": moved, "c": "cccccccc0000000000000000000000c1"})
	if zone := fixture.zone(); zone.State != IndexShadow {
		t.Fatalf("a new site rebuilt zone 2: %+v", zone)
	}
}

// The cache or index directory not on a local file system, or too little
// free space for the index: the zone is disabled (purges scan) and comes
// back once the condition is gone; a low disk also removes the index file.
func TestIndexesFallBackOnFilesystemAndDisk(t *testing.T) {
	fixture := newIndexFixture(t, IndexSettings{ReserveBytes: 1 << 20})
	fixture.local = false
	fixture.configure()
	if zone := fixture.zone(); zone.State != IndexDisabled || zone.Reason != ReasonNotLocal || exists(fixture.indexes.zones[2].file) {
		t.Fatalf("not local: %+v", zone)
	}
	if _, path := fixture.purge(); path != "scan" || fixture.zone().LastPurge.Reason != ReasonNotLocal {
		t.Fatalf("not local purge: %s %+v", path, fixture.zone())
	}
	fixture.local = true
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexShadow {
		t.Fatalf("local again: %+v", zone)
	}
	// the estimate for a 1 GiB zone (32768 planned objects x 1 KiB + 1 MiB)
	// no longer fits once built: the built index needs its growth room
	fixture.free = 2 << 20
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexShadow {
		t.Fatalf("built index with room: %+v", zone)
	}
	fixture.free = 512 << 10
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexDisabled || zone.Reason != ReasonDiskLow || exists(fixture.indexes.zones[2].file) {
		t.Fatalf("disk low: %+v", zone)
	}
	if _, path := fixture.purge(); path != "scan" {
		t.Fatalf("disk low purge: %s", path)
	}
	// not enough for a new index of the planned size
	fixture.free = 8 << 20
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexDisabled || zone.Reason != ReasonDiskLow {
		t.Fatalf("rebuilt below the estimate: %+v", zone)
	}
	fixture.free = 1 << 40
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexShadow || zone.Rebuilds != 0 {
		t.Fatalf("space back: %+v", zone)
	}
}

// The index failing during a purge (bbolt closed under it): that purge
// scans and still removes everything, the index is rebuilt.
func TestIndexesIndexErrorScansAndRebuilds(t *testing.T) {
	fixture := newIndexFixture(t, IndexSettings{ShadowRuns: 1})
	fixture.configure()
	if _, path := fixture.purge(); path != "shadow" || fixture.zone().State != IndexActive {
		t.Fatalf("not active: %s %+v", path, fixture.zone())
	}
	_ = fixture.indexes.zones[2].index.db.Close()
	result, path := fixture.purge()
	zone := fixture.zone()
	if path != "scan" || zone.LastPurge.Reason != ReasonIndexError || result.Affected != 3 || zone.State != IndexBuilding ||
		zone.Reason != ReasonIndexError || zone.Rebuilds != 1 {
		t.Fatalf("index error: %s %+v %+v", path, result, zone)
	}
	fixture.indexes.Maintain(fixture.ctx)
	if zone := fixture.zone(); zone.State != IndexShadow {
		t.Fatalf("not rebuilt: %+v", zone)
	}
}

// A site purge scans while the zone is in shadow (it is never a shadow
// check) and goes through the index once active; status.json reports the
// zone, its last purge and the index's size.
func TestIndexesSitePurgeAndStatus(t *testing.T) {
	fixture := newIndexFixture(t, IndexSettings{ShadowRuns: 1})
	fixture.configure()
	site := func() (Result, string) {
		result, err := fixture.indexes.PurgeSite(fixture.ctx, fixture.zones, siteA(), 1)
		if err != nil {
			t.Fatal(err)
		}
		return result, fixture.zone().LastPurge.Path
	}
	if result, path := site(); path != "scan" || fixture.zone().LastPurge.Reason != string(IndexShadow) || result.Affected != 4 {
		t.Fatalf("site in shadow: %s %+v", path, result)
	}
	if _, path := fixture.purge(); path != "shadow" || fixture.zone().State != IndexActive {
		t.Fatalf("not active: %s", path)
	}
	writeObject(t, fixture.zones, prefixA, key(siteA(), 0, "a.test", 80, "/x.css"), 1, time.Now().Add(-time.Minute))
	keep := writeObject(t, fixture.zones, prefixA, key(siteA(), 1, "a.test", 80, "/y.css"), 1, time.Now().Add(-time.Minute))
	b := FilePath(fixture.indexes.zones[2].dir, key(siteB(), 0, "b.test", 80, "/d/1.css"))
	// left after the directory purge: /e/4.css and /x.css of generation 0
	if result, path := site(); path != "index" || result.Affected != 2 || !exists(keep) || !exists(b) {
		t.Fatalf("site active: %s %+v (gen 1 kept %v, site B kept %v)", path, result, exists(keep), exists(b))
	}
	raw, err := os.ReadFile(filepath.Join(fixture.indexes.Dir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status IndexesStatus
	if err := json.Unmarshal(raw, &status); err != nil || !status.Enabled || len(status.Zones) != 4 {
		t.Fatalf("status.json %s %v", raw, err)
	}
	zone := status.Zones[2]
	if zone.State != IndexActive || zone.Objects < 2 || zone.IndexBytes == 0 || zone.LastPurge == nil || zone.LastPurge.Path != "index" ||
		zone.BuiltAt.IsZero() || zone.CheckedAt.IsZero() {
		t.Fatalf("status zone %+v", zone)
	}
}

// purge_index false: index files of an earlier run are removed and
// status.json says the node has none.
func TestDisableIndexesRemovesFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"cdnca-0.db", "cdnca-1.db"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	DisableIndexes(dir, "configured_off")
	raw, _ := os.ReadFile(filepath.Join(dir, "status.json"))
	var status IndexesStatus
	if exists(filepath.Join(dir, "cdnca-0.db")) || json.Unmarshal(raw, &status) != nil || status.Enabled || status.Reason != "configured_off" {
		t.Fatalf("status %s", raw)
	}
}

// Purges, background passes and layout changes at once (-race): every
// purge removes what it targets, whatever path it takes.
func TestIndexesConcurrentPurgeAndMaintain(t *testing.T) {
	fixture := newIndexFixture(t, IndexSettings{ShadowRuns: 1, RecheckPurges: 2})
	fixture.configure()
	ctx, cancel := context.WithCancel(fixture.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			fixture.indexes.Maintain(ctx)
		}
	}()
	target, _ := ParseTarget(siteA(), "http://a.test/e/", true)
	for round := range 40 {
		path := writeObject(t, fixture.zones, prefixA, key(siteA(), 0, "a.test", 80, "/e/"+string(rune('a'+round%26))+".css"), 1,
			time.Now().Add(-time.Minute))
		if round == 20 {
			fixture.indexes.Configure(fixture.zones.Root, fixture.zones.Count, 1<<30, map[string]string{"a": prefixA, "b": "bbbbbbbb0000000000000000000000b9"})
		}
		if _, err := fixture.indexes.Purge(fixture.ctx, fixture.zones, siteA(), []Target{target}, true, nil); err != nil {
			t.Fatal(err)
		}
		if exists(path) {
			t.Fatalf("round %d: %s left (%+v)", round, path, fixture.zone())
		}
	}
	cancel()
	<-done
}
