package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// chunkGoals: ADR 0021 goals 1-4 and 7 (aligned fetch, bounded over-fetch,
// shared fills, partial objects, small objects unchanged).
func chunkGoals(o *rangeOrigin, n *node, sites []edgesite.Site, host string, c int64) {
	site := sites[0]
	// goal 1/2: one aligned chunk for a small Range, the client gets its bytes
	path := "/g/small.bin"
	a := rangeGet(host, path+"?size=67108864", rangeHeader(10*mib, 10*mib+1023))
	o.quiet(30 * time.Second)
	requests, bytes := delta(o, path, rangeStats{})
	ranges := o.of(path).Ranges
	check("CHUNK-SMALL-RANGE-ONE-CHUNK", a.part(10*mib, 1024, 0, 64*mib) && a.cache == "MISS" && requests == 1 && bytes == c &&
		len(ranges) == 1 && ranges[0] == fmt.Sprintf("bytes=%d-%d", 8*mib, 12*mib-1),
		"%v origin %d/%d %v keys %v", a, requests, bytes, ranges, objectKeys(n, site, path))
	b := rangeGet(host, path+"?size=67108864", rangeHeader(10*mib+1024, 10*mib+2047))
	requests, _ = delta(o, path, rangeStats{})
	check("CHUNK-SMALL-RANGE-HIT", b.part(10*mib+1024, 1024, 0, 64*mib) && b.cache == "HIT" && requests == 1, "%v origin %d", b, requests)

	// over-fetch bound: a Range across a chunk boundary is two chunks
	path = "/g/cross.bin"
	a = rangeGet(host, path+"?size=67108864", rangeHeader(16*mib-512, 16*mib+511))
	o.quiet(30 * time.Second)
	requests, bytes = delta(o, path, rangeStats{})
	check("CHUNK-CROSS-TWO-CHUNKS", a.part(16*mib-512, 1024, 0, 64*mib) && requests == 2 && bytes == 2*c, "%v origin %d/%d %v", a, requests, bytes, o.of(path).Ranges)

	// goal 3: concurrent misses of one chunk share one fill (a slow origin:
	// 4 MiB at 512 KiB/s = 8 s, above the 5 s whole object lock)
	path = "/g/same.bin"
	uri := path + "?size=33554432&rate=524288"
	// unknown object: one prober fetches chunk 5, the others wait for it
	before := o.of(path)
	answers := parallel(20, func(int) rangeAnswer { return rangeGet(host, uri, rangeHeader(20*mib, 20*mib+65535)) })
	o.quiet(60 * time.Second)
	requests, bytes = delta(o, path, before)
	good := 0
	for _, answer := range answers {
		if answer.part(20*mib, 65536, 0, 32*mib) {
			good++
		}
	}
	check("CHUNK-CONCURRENT-SAME-CHUNK-ONE-FILL", good == 20 && requests == 1 && bytes == c, "%d/20 good, origin %d/%d first %v", good, requests, bytes, answers[0])

	// a burst of whole-object downloads of a new hot file: the prober streams
	// it, the others take chunks (shared fills): at most twice the object
	path = "/g/hot.bin"
	answers = parallel(20, func(int) rangeAnswer { return rangeGet(host, path+"?size=33554432&rate=8388608", nil) })
	o.quiet(60 * time.Second)
	requests, bytes = delta(o, path, rangeStats{})
	good = 0
	for _, answer := range answers {
		if answer.whole(32*mib, 0) {
			good++
		}
	}
	check("CHUNK-HOT-BURST-SHARED", good == 20 && bytes <= 2*32*mib && requests <= 1+8+8, "%d/20 good, origin %d/%d first %v", good, requests, bytes, answers[0])
	metric("chunk4m", "hot_burst_new_object", "clients", 20, "origin_requests", requests, "origin_bytes", bytes)

	// goal 4: a partly cached object: cached chunks from disk, the missing
	// ones from the origin, one 200
	path = "/g/partial.bin"
	rangeGet(host, path+"?size=33554432", rangeHeader(5*mib, 5*mib+9))   // chunk 1
	rangeGet(host, path+"?size=33554432", rangeHeader(25*mib, 25*mib+9)) // chunk 6
	o.quiet(30 * time.Second)
	before = o.of(path)
	a = rangeGet(host, path+"?size=33554432", nil)
	o.quiet(30 * time.Second)
	requests, bytes = delta(o, path, before)
	check("CHUNK-PARTIAL-OBJECT", a.whole(32*mib, 0) && requests == 6 && bytes == 6*c, "%v origin %d/%d keys %d", a, requests, bytes, len(objectKeys(n, site, path)))
	before = o.of(path)
	a = rangeGet(host, path+"?size=33554432", rangeHeader(3*mib, 29*mib))
	requests, _ = delta(o, path, before)
	check("CHUNK-PARTIAL-THEN-HIT", a.part(3*mib, 26*mib+1, 0, 32*mib) && a.cache == "HIT" && requests == 0, "%v origin %d", a, requests)

	// HEAD of a new large object: headers only, the right length
	path = "/g/head.bin"
	request, _ := http.NewRequest(http.MethodHead, fmt.Sprintf("http://127.0.0.1:%d%s?size=67108864", edge, path), nil)
	request.Host = host
	response, err := bigClient.Do(request)
	o.quiet(30 * time.Second)
	requests, bytes = delta(o, path, rangeStats{})
	if err == nil {
		response.Body.Close()
		check("CHUNK-HEAD-NEW-OBJECT", response.StatusCode == 200 && response.ContentLength == 64*mib, "%d len %d origin %d/%d",
			response.StatusCode, response.ContentLength, requests, bytes)
		metric("chunk4m", "head_new_large_object", "origin_requests", requests, "origin_bytes", bytes)
	} else {
		check("CHUNK-HEAD-NEW-OBJECT", false, "%v", err)
	}

	// goal 7: a small object stays one whole object
	path = "/g/tiny.css"
	a, b = rangeGet(host, path+"?size=65536", nil), rangeGet(host, path+"?size=65536", nil)
	requests, _ = delta(o, path, rangeStats{})
	keys := objectKeys(n, site, path)
	check("CHUNK-SMALL-OBJECT-WHOLE", a.whole(65536, 0) && a.cache == "MISS" && b.cache == "HIT" && requests == 1 && len(keys) == 1 && keys[0] == "?size=65536|",
		"%v / %v origin %d keys %v", a, b, requests, keys)
	path = "/g/tiny-range.css"
	a = rangeGet(host, path+"?size=65536", rangeHeader(100, 199))
	b = rangeGet(host, path+"?size=65536", rangeHeader(200, 299))
	d := rangeGet(host, path+"?size=65536", rangeHeader(300, 399))
	requests, _ = delta(o, path, rangeStats{})
	keys = objectKeys(n, site, path)
	// a small object whose first request has a Range is its one chunk:
	// fetched once (aligned), then served from it with or without Range
	whole := rangeGet(host, path+"?size=65536", nil)
	requests, _ = delta(o, path, rangeStats{})
	check("CHUNK-SMALL-OBJECT-RANGE-ONE-CHUNK", a.part(100, 100, 0, 65536) && b.part(200, 100, 0, 65536) && d.part(300, 100, 0, 65536) &&
		b.cache == "HIT" && d.cache == "HIT" && whole.whole(65536, 0) && whole.cache == "HIT" && requests == 1 && len(keys) == 1 &&
		keys[0] == "?size=65536|bytes=0-4194303" && o.of(path).Ranges[0] == "bytes=0-4194303",
		"%v / %v / %v / %v origin %d %v keys %v", a, b, d, whole, requests, o.of(path).Ranges, keys)
	path = "/g/tiny-burst.css"
	answers = parallel(20, func(int) rangeAnswer { return rangeGet(host, path+"?size=65536&delay=200", nil) })
	requests, _ = delta(o, path, rangeStats{})
	good = 0
	for _, answer := range answers {
		if answer.whole(65536, 0) {
			good++
		}
	}
	check("CHUNK-SMALL-OBJECT-BURST-ONE-FILL", good == 20 && requests == 1, "%d/20 good, origin %d", good, requests)
}

func parallel(count int, run func(int) rangeAnswer) []rangeAnswer {
	answers := make([]rangeAnswer, count)
	var group sync.WaitGroup
	for index := range answers {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			answers[index] = run(index)
		}(index)
	}
	group.Wait()
	return answers
}
