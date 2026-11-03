package main

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// chunkCompat: ADR 0021 goal 6 on chunks: purge (exact, prefix, whole
// site), prewarm, stale-if-error and revalidation, object size bounds, a
// policy's slice_bytes replaced by the chunks.
func chunkCompat(o *rangeOrigin, n *node, sites []edgesite.Site, c int64) {
	site, host := sites[0], sites[0].Hosts.Primary
	// the first whole download of a new large object learns it is chunks
	// (not stored); the second stores every chunk
	full := func(path string, size int64) rangeAnswer {
		rangeGet(host, fmt.Sprintf("%s?size=%d", path, size), nil)
		answer := rangeGet(host, fmt.Sprintf("%s?size=%d", path, size), nil)
		o.quiet(30 * time.Second)
		return answer
	}
	// exact URL: every chunk of the URL, found by path (the agent gives a
	// chunking node's sites ChunkBytes; the whole object key alone finds
	// nothing); the cache module forgets the object's chunk state
	path := "/purge/a.bin"
	full(path, 16*mib)
	keys := objectKeys(n, site, path)
	target := []dyncache.Target{{Host: host, Port: edge, URI: path + "?size=16777216", Path: path}}
	unchunked, err1 := n.zones().Purge(context.Background(), cacheSite(site), target, false, n.generations)
	value := cacheSite(site)
	value.ChunkBytes = c
	purged, err2 := n.zones().Purge(context.Background(), value, target, false, n.generations)
	before := o.of(path)
	after := rangeGet(host, path+"?size=16777216", rangeHeader(0, 9))
	again := rangeGet(host, path+"?size=16777216", rangeHeader(10, 19))
	refetched, _ := delta(o, path, before)
	check("CHUNK-PURGE-URL", len(keys) == 4 && err1 == nil && unchunked.Affected == 0 && err2 == nil && purged.Affected == 4 &&
		len(objectKeys(n, site, path)) <= 1 && after.cache == "MISS" && after.part(0, 10, 0, 16*mib) && again.cache == "HIT" && refetched == 1,
		"keys %v / unchunked %+v / chunked %+v err %v %v / %v / %v origin %d", keys, unchunked, purged, err1, err2, after, again, refetched)
	// an uncached URL: nothing, at once
	start := time.Now()
	none, err3 := n.zones().Purge(context.Background(), value, []dyncache.Target{{Host: host, Port: edge, URI: "/never.bin", Path: "/never.bin"}}, false, n.generations)
	check("CHUNK-PURGE-URL-UNCACHED", err3 == nil && none.Affected == 0, "%+v err %v in %v", none, err3, time.Since(start))
	// prefix
	path = "/purgedir/b.bin"
	full(path, 16*mib)
	value.Sliced = true // prefix: the zone scan, as before
	prefixed, err := n.zones().Purge(context.Background(), value, []dyncache.Target{{Host: host, Port: edge, URI: "/purgedir/", Path: "/purgedir/"}}, true, nil)
	after = rangeGet(host, path+"?size=16777216", rangeHeader(0, 9))
	check("CHUNK-PURGE-PREFIX", err == nil && prefixed.Affected == 4 && after.cache == "MISS", "%+v err %v / %v", prefixed, err, after)
	// whole site (generation)
	path = "/purgesite/c.bin"
	full(path, 16*mib)
	_, _, err = n.zones().PurgeSite(context.Background(), n.generations, cacheSite(site))
	after = rangeGet(host, path+"?size=16777216", rangeHeader(0, 9))
	check("CHUNK-PURGE-SITE", err == nil && after.cache == "MISS" && after.part(0, 10, 0, 16*mib), "err %v / %v", err, after)
	o.quiet(30 * time.Second)

	// prewarm of a new large object: stored whole at once, Range hits it
	path = "/warm/a.bin"
	outcome := n.prewarmer.Prewarm(context.Background(), cacheSite(site), dyncache.Target{Host: host, Port: edge, URI: path + "?size=33554432", Path: path}, "http")
	hit := rangeGet(host, path+"?size=33554432", rangeHeader(20*mib, 20*mib+9))
	requests, _ := delta(o, path, rangeStats{})
	check("CHUNK-PREWARM", outcome.Code == "PREWARMED" && hit.part(20*mib, 10, 0, 32*mib) && hit.cache == "HIT" && requests == 1,
		"%+v / %v origin %d", outcome, hit, requests)

	// stale-if-error and revalidation of a chunk (1 s rule TTL)
	host2 := sites[1].Hosts.Primary
	path = "/stale/a.bin"
	uri := path + "?size=16777216"
	a := rangeGet(host2, uri, rangeHeader(5*mib, 5*mib+9))
	o.quiet(30 * time.Second)
	time.Sleep(2200 * time.Millisecond)
	o.fail.Store(true)
	b := rangeGet(host2, uri, rangeHeader(5*mib+10, 5*mib+19))
	o.fail.Store(false)
	d := rangeGet(host2, uri, rangeHeader(5*mib+20, 5*mib+29))
	check("CHUNK-STALE-IF-ERROR-REVALIDATE", a.part(5*mib, 10, 0, 16*mib) && a.cache == "MISS" && b.part(5*mib+10, 10, 0, 16*mib) && b.cache == "STALE" &&
		d.part(5*mib+20, 10, 0, 16*mib) && d.cache == "REVALIDATED", "%v / %v / %v", a, b, d)

	// object size bounds: the object's total length, as before
	host3 := sites[2].Hosts.Primary
	a = rangeGet(host3, "/size/big.bin?size=33554432", rangeHeader(0, 9))
	b = rangeGet(host3, "/size/big.bin?size=33554432", rangeHeader(10, 19))
	d = rangeGet(host3, "/size/ok.bin?size=8388608", rangeHeader(0, 9))
	e := rangeGet(host3, "/size/ok.bin?size=8388608", rangeHeader(10, 19))
	check("CHUNK-MAX-OBJECT-BYTES", a.cache == "BYPASS" && a.part(0, 10, 0, 32*mib) && b.cache == "BYPASS" && o.of("/size/big.bin").Requests == 2 &&
		d.cache == "MISS" && e.cache == "HIT", "%v / %v / %v / %v", a, b, d, e)

	// a policy's slice_bytes runs as chunks (the chunk size, not the slice)
	host4 := sites[3].Hosts.Primary
	path = "/sliced/a.bin"
	a = rangeGet(host4, path+"?size=16777216", rangeHeader(5*mib, 5*mib+9))
	o.quiet(30 * time.Second)
	ranges := o.of(path).Ranges
	check("CHUNK-REPLACES-SLICE", a.part(5*mib, 10, 0, 16*mib) && len(ranges) == 1 && ranges[0] == fmt.Sprintf("bytes=%d-%d", c, 2*c-1),
		"%v %v keys %v", a, ranges, objectKeys(n, sites[3], path))
}
