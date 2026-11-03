package dyncache

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const testChunk = 4 << 20

// chunkControl answers the cache module's chunk forget with states (by
// key), or fails.
type chunkControl struct {
	states map[string]chunkState
	fail   bool
	asked  [][]string
}

func (control *chunkControl) Post(_ context.Context, path string, body []byte) ([]byte, error) {
	if path != ChunkForgetPath {
		return []byte("{}"), nil
	}
	if control.fail {
		return nil, errors.New("control socket down")
	}
	var request struct {
		Keys []string `json:"keys"`
	}
	_ = json.Unmarshal(body, &request)
	control.asked = append(control.asked, request.Keys)
	states := map[string]chunkState{}
	for _, key := range request.Keys {
		states[key] = control.states[key]
	}
	return json.Marshal(map[string]any{"chunk_bytes": testChunk, "states": states})
}

// writeChunk writes chunk index of key (generation epoch) as nginx stores a
// 206 chunk: the KEY line, then the upstream header with its Content-Range.
func writeChunk(t *testing.T, zones Zones, key string, index, epoch, total int64) string {
	t.Helper()
	dir, _ := zones.ZoneOf(prefixA)
	name := chunkKey(key, testChunk, index, epoch)
	path := FilePath(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	end := min((index+1)*testChunk, total) - 1
	header := "\nKEY: " + name + "\nHTTP/1.1 206 Partial Content\r\nContent-Range: bytes " +
		itoa(index*testChunk) + "-" + itoa(end) + "/" + itoa(total) + "\r\n\r\n"
	if err := os.WriteFile(path, append(make([]byte, 64), header...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }

// chunkSetup: site A on a chunking node, generation 3, one URL with chunks
// and a decoy (another URL's chunks, and the same URL's file of an earlier
// purge generation that only a zone scan would remove).
func chunkSetup(t *testing.T) (Zones, Site, *Generations, string, string, string) {
	zones := Zones{Root: t.TempDir(), Count: 4}
	site := siteA()
	site.ChunkBytes = testChunk
	generations := &Generations{Path: filepath.Join(t.TempDir(), "g.json"), values: map[string]uint64{prefixA: 3}}
	whole := key(site, 3, "www.a.test", 443, "/v.mp4")
	other := key(site, 3, "www.a.test", 443, "/other.mp4")
	stale := writeObject(t, zones, prefixA, key(site, 2, "www.a.test", 443, "/v.mp4"), 10, time.Now())
	return zones, site, generations, whole, other, stale
}

var target = []Target{{Host: "www.a.test", Port: 443, URI: "/v.mp4", Path: "/v.mp4"}}

// ADR 0021: a known length (the cache module's state) names
// every chunk file of both reachable generations ("" and the current one)
// plus the whole object file; nothing else is touched and no zone is scanned.
func TestExactPurgeFindsChunksByPath(t *testing.T) {
	zones, site, generations, whole, other, stale := chunkSetup(t)
	const total = 10*testChunk + 5 // 11 chunks
	var paths []string
	for _, index := range []int64{0, 3, 10} {
		paths = append(paths, writeChunk(t, zones, whole, index, 0, total))
	}
	for _, index := range []int64{1, 7} {
		paths = append(paths, writeChunk(t, zones, whole, index, 1730000000, total))
	}
	paths = append(paths, writeObject(t, zones, prefixA, whole, 10, time.Now()))
	decoy := writeChunk(t, zones, other, 0, 0, total)
	control := &chunkControl{states: map[string]chunkState{whole: {Epoch: 1730000000, Total: total, Kind: "c"}}}
	generations.Control = control
	result, err := zones.Purge(context.Background(), site, target, false, generations)
	if err != nil || result.Affected != 6 {
		t.Fatalf("result %+v err %v", result, err)
	}
	for _, path := range paths {
		if exists(path) {
			t.Fatalf("%s left", path)
		}
	}
	if !exists(decoy) || !exists(stale) {
		t.Fatal("another URL's chunk or an earlier generation's file removed (a zone scan ran)")
	}
	if len(control.asked) != 1 || len(control.asked[0]) != 1 || control.asked[0][0] != whole {
		t.Fatalf("forget asked %v", control.asked)
	}
}

// Unknown length (the cache module restarted or forgot): the first chunks
// are probed; the first one found gives the length, every chunk after the
// probe window is then found too.
func TestExactPurgeProbesChunksWithoutState(t *testing.T) {
	zones, site, generations, whole, _, stale := chunkSetup(t)
	const total = 100 * testChunk // past the 64 chunk probe
	paths := []string{writeChunk(t, zones, whole, 2, 0, total), writeChunk(t, zones, whole, 90, 0, total)}
	generations.Control = &chunkControl{}
	result, err := zones.Purge(context.Background(), site, target, false, generations)
	if err != nil || result.Affected != 2 || exists(paths[0]) || exists(paths[1]) || !exists(stale) {
		t.Fatalf("result %+v err %v left %v %v stale %v", result, err, exists(paths[0]), exists(paths[1]), exists(stale))
	}
}

// An uncached URL: nothing found, no zone scan (default on: every exact
// purge of a URL the node never cached must stay cheap).
func TestExactPurgeOfUncachedURLDoesNotScan(t *testing.T) {
	zones, site, generations, _, _, stale := chunkSetup(t)
	generations.Control = &chunkControl{}
	result, err := zones.Purge(context.Background(), site, target, false, generations)
	if err != nil || result.Affected != 0 || !exists(stale) {
		t.Fatalf("result %+v err %v stale left %v", result, err, exists(stale))
	}
}

// The control socket down: the cache module may still serve the chunks,
// the zone scan removes everything of the URL (as before chunks).
func TestExactPurgeScansWhenTheCacheModuleIsUnreachable(t *testing.T) {
	zones, site, generations, whole, _, stale := chunkSetup(t)
	chunk := writeChunk(t, zones, whole, 0, 0, 2*testChunk)
	generations.Control = &chunkControl{fail: true}
	result, err := zones.Purge(context.Background(), site, target, false, generations)
	if err != nil || result.Affected != 2 || exists(chunk) || exists(stale) {
		t.Fatalf("result %+v err %v chunk %v stale %v", result, err, exists(chunk), exists(stale))
	}
}

// A file at a chunk's path whose key is not that chunk's: the fast path
// cannot vouch for it, the zone scan decides.
func TestExactPurgeScansOnAForeignChunkFile(t *testing.T) {
	zones, site, generations, whole, _, stale := chunkSetup(t)
	dir, _ := zones.ZoneOf(prefixA)
	path := FilePath(dir, chunkKey(whole, testChunk, 0, 0))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(make([]byte, 64), "\nKEY: something else\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	generations.Control = &chunkControl{}
	if _, err := zones.Purge(context.Background(), site, target, false, generations); err != nil || exists(stale) {
		t.Fatalf("err %v: no zone scan (stale left %v)", err, exists(stale))
	}
}

// Prefix and whole-site purges are unchanged on a chunking node: the scan
// matches chunk files by path, the site's purge generation hides them.
func TestPrefixAndSitePurgeCoverChunks(t *testing.T) {
	zones, site, generations, whole, other, _ := chunkSetup(t)
	chunk := writeChunk(t, zones, whole, 4, 1730000000, 8*testChunk)
	decoy := writeChunk(t, zones, other, 0, 0, 8*testChunk)
	result, err := zones.Purge(context.Background(), site, []Target{{Host: "www.a.test", Port: 443, URI: "/v.mp4", Path: "/v.mp4"}}, true, nil)
	if err != nil || result.Affected != 2 || exists(chunk) || !exists(decoy) {
		t.Fatalf("prefix %+v err %v chunk %v decoy %v", result, err, exists(chunk), exists(decoy))
	}
	generations.Control = &chunkControl{}
	generation, site2, err := zones.PurgeSite(context.Background(), generations, site)
	if err != nil || generation != 4 || site2.Affected != 1 || exists(decoy) {
		t.Fatalf("site generation %d %+v err %v decoy %v", generation, site2, err, exists(decoy))
	}
}

func TestChunkKeyFormat(t *testing.T) {
	if got := chunkKey("K", testChunk, 2, 0); got != "K|slice=bytes=8388608-12582911" {
		t.Fatal(got)
	}
	if got := chunkKey("K", testChunk, 0, 7); got != "K|slice=bytes=0-4194303|e=7" {
		t.Fatal(got)
	}
	parsed, ok := ParseKey(chunkKey(key(siteA(), 3, "www.a.test", 443, "/v.mp4?x=1"), testChunk, 1, 9))
	if !ok || parsed.PolicyKey != "/v.mp4?x=1" || parsed.Path != "/v.mp4" || parsed.Slice != "bytes=4194304-8388607|e=9" {
		t.Fatalf("%+v %v", parsed, ok)
	}
}
