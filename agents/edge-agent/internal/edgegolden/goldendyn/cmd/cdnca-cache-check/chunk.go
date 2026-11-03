package main

// chunk: the chunked range cache (ADR 0021) on the real node. A node with
// edgecache.Pool.ChunkBytes caches a large object in fixed chunks fetched
// aligned and only where missing; ADR 0021 goals 1-7 are checked here, the
// rangebase scenarios run again on a chunking node (CHUNK-METRIC) and the
// chunk size candidates are measured (chunksizes).

import (
	"context"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const mib = 1 << 20

func startChunkNode(sites []edgesite.Site, chunkBytes int64) (*node, error) {
	pool, err := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 4 << 30, Chunked: true})
	if err != nil {
		return nil, err
	}
	pool.ChunkBytes = chunkBytes
	n, err := startNode(sites, pool)
	if err != nil {
		return nil, err
	}
	if err := n.startCache(); err != nil {
		n.stop()
		return nil, err
	}
	return n, nil
}

// objectKeys: the cache file keys of a site's object (path), sorted by fill.
func objectKeys(n *node, site edgesite.Site, path string) []string {
	var keys []string
	_ = n.zones().Walk(context.Background(), site.Cache.KeyPrefix, func(entry dyncache.Entry) error {
		if entry.Key.Path == path {
			keys = append(keys, entry.Key.PolicyKey[len(entry.Key.Path):]+"|"+entry.Key.Slice)
		}
		return nil
	})
	return keys
}

// delta: what the origin served for path since before.
func delta(o *rangeOrigin, path string, before rangeStats) (int, int64) {
	now := o.of(path)
	return now.Requests - before.Requests, now.Bytes - before.Bytes
}

// whole: a 200 of the object's size, version v.
func (a rangeAnswer) whole(size int64, version int) bool {
	return a.err == nil && a.status == 200 && int64(len(a.body)) == size && patternMatches(a.body, 0, version)
}

// part: a 206 of [start, start+length).
func (a rangeAnswer) part(start, length int64, version int, total int64) bool {
	return a.err == nil && a.status == 206 && int64(len(a.body)) == length && patternMatches(a.body, start, version) &&
		a.contentRange == fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, total)
}

func rangeHeader(start, end int64) map[string]string {
	return map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", start, end)}
}

// chunkRun: ADR 0021 goals on a 4 MiB chunk node.
func chunkRun(o *rangeOrigin) {
	const c = 4 * mib
	plain := policy(nil, 4<<30)
	short := policy([]edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".bin"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 1}}, 4<<30)
	short.StaleIfError = true
	bounded := policy(nil, 4<<30)
	bounded.MaxObjectBytes = 16 * mib
	sliced := policy(nil, 4<<30)
	sliced.SliceBytes = 1 * mib
	sites := []edgesite.Site{
		rangeSite(51, "chunk.range.test", plain),
		rangeSite(52, "short.range.test", short),
		rangeSite(53, "bounded.range.test", bounded),
		rangeSite(54, "sliced.range.test", sliced),
	}
	n, err := startChunkNode(sites, c)
	if err != nil {
		check("chunk-start", false, "%v", err)
		return
	}
	defer n.stop()
	host := "chunk.range.test"

	// the Lua plan names the same chunk variant as edgecache
	for _, site := range sites {
		plan, _ := edgecache.Build(site)
		raw, _ := edgesite.Encode(site)
		body, err := adminGet(n, "/cache/plan?digest="+edgesite.Digest(raw)+"&signatures=1")
		want := fmt.Sprintf(`"chunk_variant":%q`, edgecache.ChunkVariant(plan.Variant()))
		check("CHUNK-PLAN-LUA-EQUALS-GO-"+site.Hosts.Primary, err == nil && strings.Contains(string(body), want) &&
			strings.Contains(string(body), fmt.Sprintf(`"chunk_bytes":%d`, c)), "want %s in %s err %v", want, body, err)
	}

	chunkGoals(o, n, sites, host, c)
	chunkCorrectness(o, n, sites[0], c)
	chunkCompat(o, n, sites, c)
	for _, line := range n.errors() {
		fmt.Println("LOG", line)
	}
}
