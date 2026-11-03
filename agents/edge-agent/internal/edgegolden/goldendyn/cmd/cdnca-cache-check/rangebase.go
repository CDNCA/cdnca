package main

// rangebase: large object / Range measurements on the real node (the
// chunked range cache baseline, ADR 0021). Every site runs the same scenarios on
// its own paths; METRIC lines carry origin requests and bytes (after the
// origin is quiet: the edge may keep filling after the client is done),
// client bytes, latency and the X-CDN-Cache values.

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

var bigClient = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256, DisableCompression: true}, Timeout: 120 * time.Second}

type rangeAnswer struct {
	status       int
	cache        string
	contentRange string
	etag         string
	body         string
	ttfb, total  time.Duration
	err          error
}

func rangeGet(host, path string, headers map[string]string) rangeAnswer {
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), nil)
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	start := time.Now()
	response, err := bigClient.Do(request)
	if err != nil {
		return rangeAnswer{err: err}
	}
	defer response.Body.Close()
	ttfb := time.Since(start)
	body, err := io.ReadAll(response.Body)
	return rangeAnswer{status: response.StatusCode, cache: response.Header.Get("X-CDN-Cache"), contentRange: response.Header.Get("Content-Range"),
		etag: response.Header.Get("ETag"),
		body: string(body), ttfb: ttfb, total: time.Since(start), err: err}
}

func (a rangeAnswer) String() string {
	if a.err != nil {
		return a.err.Error()
	}
	return fmt.Sprintf("%d %s %q len=%d ttfb=%v total=%v", a.status, a.cache, a.contentRange, len(a.body),
		a.ttfb.Round(time.Millisecond), a.total.Round(time.Millisecond))
}

// rangeSite: a caching site on the range origin.
func rangeSite(number int, host string, document edgeconfig.CachePolicyDocument) edgesite.Site {
	site := makeSite(number, host, true, &document)
	site.Origin.Pools[0].Endpoints[0].Port = 19802
	return site
}

func metric(site, scenario string, values ...any) {
	fmt.Printf("METRIC %s %s", site, scenario)
	for index := 0; index+1 < len(values); index += 2 {
		fmt.Printf(" %v=%v", values[index], values[index+1])
	}
	fmt.Println()
}

func percentile(values []time.Duration, fraction float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[int(float64(len(sorted)-1)*fraction)].Round(time.Millisecond)
}

// rangeScenarios runs the large object scenarios on one site (paths under
// /<label>/ so sites never share objects).
func rangeScenarios(o *rangeOrigin, label, host string) {
	const mib = 1 << 20
	// 1. a small Range of a large object, cache miss
	path := fmt.Sprintf("/%s/small.bin", label)
	a := rangeGet(host, path+"?size=67108864", map[string]string{"Range": "bytes=10485760-10486783"})
	o.quiet(60 * time.Second)
	stats := o.of(path)
	check("RANGE-SMALL-MISS-"+label, a.status == 206 && len(a.body) == 1024 && patternMatches(a.body, 10485760, 0), "%v", a)
	metric(label, "small_range_miss", "object", "64MiB", "range", "1KiB@10MiB", "origin_requests", stats.Requests,
		"origin_bytes", stats.Bytes, "client_bytes", len(a.body), "ttfb", a.ttfb.Round(time.Millisecond), "cache", a.cache)
	b := rangeGet(host, path+"?size=67108864", map[string]string{"Range": "bytes=10486784-10487807"})
	check("RANGE-SMALL-HIT-"+label, b.status == 206 && patternMatches(b.body, 10486784, 0), "%v", b)

	// 2. a Range across a 1 MiB and a 16 MiB boundary
	path = fmt.Sprintf("/%s/cross.bin", label)
	c := rangeGet(host, path+"?size=67108864", map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", 16*mib-512, 16*mib+511)})
	o.quiet(60 * time.Second)
	stats = o.of(path)
	check("RANGE-CROSS-"+label, c.status == 206 && len(c.body) == 1024 && patternMatches(c.body, 16*mib-512, 0), "%v", c)
	metric(label, "cross_boundary", "range", "1KiB@16MiB-512", "origin_requests", stats.Requests, "origin_bytes", stats.Bytes,
		"origin_ranges", strings.Join(stats.Ranges, ";"))

	// 3. N concurrent misses of random 64 KiB ranges (8 MiB/s origin: the
	// whole 64 MiB object takes 8 s, above the 5 s lock)
	concurrent(o, label, host, "concurrent_random_range", fmt.Sprintf("/%s/burst.bin?size=67108864&rate=8388608", label),
		fmt.Sprintf("/%s/burst.bin", label), 64<<20, 20, randomStarts(20))
	// 4. N concurrent misses of the same 64 KiB range at 20 MiB of a slow
	// origin (2 MiB/s: a 16 MiB piece takes 8 s, above the lock)
	same := make([]int64, 20)
	for index := range same {
		same[index] = 20 << 20
	}
	concurrent(o, label, host, "concurrent_same_range_slow", fmt.Sprintf("/%s/same.bin?size=33554432&rate=2097152", label),
		fmt.Sprintf("/%s/same.bin", label), 32<<20, 20, same)
	// 5. N concurrent whole-object downloads of a hot file (32 MiB at 4 MiB/s)
	concurrent(o, label, host, "concurrent_whole", fmt.Sprintf("/%s/hot.bin?size=33554432&rate=4194304", label),
		fmt.Sprintf("/%s/hot.bin", label), 32<<20, 20, nil)
	// 6. one client downloads a 64 MiB object three times; every origin
	// request takes 20 ms more (round trip); unthrottled
	path = fmt.Sprintf("/%s/rtt.bin", label)
	values := []any{"object", "64MiB", "origin_delay", "20ms"}
	for pass := 1; pass <= 3; pass++ {
		before := o.of(path)
		answer := rangeGet(host, path+"?size=67108864&delay=20", nil)
		o.quiet(60 * time.Second)
		requests, bytes := delta(o, path, before)
		check(fmt.Sprintf("RANGE-RTT-PASS%d-%s", pass, label), answer.whole(64<<20, 0), "%v", answer)
		values = append(values, fmt.Sprintf("pass%d", pass), fmt.Sprintf("%s/%v/%d/%d", answer.cache, answer.total.Round(time.Millisecond), requests, bytes))
	}
	metric(label, "whole_download_rtt", values...)
}

// chunkBase: the rangebase scenarios on chunking nodes, one per chunk size.
func chunkBase(o *rangeOrigin, sizes []int64) {
	for _, size := range sizes {
		label := fmt.Sprintf("c%dm", size>>20)
		n, err := startChunkNode([]edgesite.Site{rangeSite(61, "chunkbase.range.test", policy(nil, 4<<30))}, size)
		if err != nil {
			check("chunkbase-start-"+label, false, "%v", err)
			continue
		}
		rangeScenarios(o, label, "chunkbase.range.test")
		for _, line := range n.errors() {
			fmt.Println("LOG", line)
		}
		n.stop()
	}
}

func randomStarts(count int) []int64 {
	random := rand.New(rand.NewSource(7))
	starts := make([]int64, count)
	for index := range starts {
		starts[index] = random.Int63n(64<<20-64<<10) &^ 1023
	}
	return starts
}

// concurrent: clients at once; starts[i] is client i's 64 KiB Range, nil =
// whole object of size bytes.
func concurrent(o *rangeOrigin, label, host, scenario, uri, path string, size int64, clients int, starts []int64) {
	var group sync.WaitGroup
	answers := make([]rangeAnswer, clients)
	ranged := starts != nil
	begin := time.Now()
	for index := 0; index < clients; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			headers := map[string]string{}
			if ranged {
				headers["Range"] = fmt.Sprintf("bytes=%d-%d", starts[index], starts[index]+64<<10-1)
			}
			answers[index] = rangeGet(host, uri, headers)
		}(index)
	}
	group.Wait()
	wall := time.Since(begin)
	o.quiet(90 * time.Second)
	stats := o.of(path)
	failed, statuses := 0, map[string]int{}
	var ttfbs, totals []time.Duration
	for index, answer := range answers {
		statuses[answer.cache]++
		ttfbs, totals = append(ttfbs, answer.ttfb), append(totals, answer.total)
		good := answer.err == nil
		if ranged {
			good = good && answer.status == 206 && len(answer.body) == 64<<10 && patternMatches(answer.body, starts[index], 0)
		} else {
			good = good && answer.status == 200 && int64(len(answer.body)) == size && patternMatches(answer.body, 0, 0)
		}
		if !good {
			failed++
		}
	}
	ok := failed == 0
	check("RANGE-"+strings.ToUpper(scenario)+"-"+label, ok, "first %v statuses %v", answers[0], statuses)
	metric(label, scenario, "clients", clients, "failed", failed, "origin_requests", stats.Requests, "origin_bytes", stats.Bytes,
		"ttfb_p50", percentile(ttfbs, 0.5), "ttfb_max", percentile(ttfbs, 1), "total_p50", percentile(totals, 0.5),
		"total_max", percentile(totals, 1), "wall", wall.Round(time.Millisecond), "cache", fmt.Sprint(statuses))
}

// rangeBase: the baseline sites (whole object, 1 MiB and 16 MiB slices).
func rangeBase(o *rangeOrigin) {
	whole := policy(nil, 4<<30)
	slice1m, slice16m := policy(nil, 4<<30), policy(nil, 4<<30)
	slice1m.SliceBytes, slice16m.SliceBytes = 1<<20, 16<<20
	sites := []edgesite.Site{
		rangeSite(41, "whole.range.test", whole),
		rangeSite(42, "s1m.range.test", slice1m),
		rangeSite(43, "s16m.range.test", slice16m),
	}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 4 << 30})
	n, err := startNode(sites, pool)
	if err != nil {
		check("rangebase-start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("rangebase-sync", false, "%v", err)
		return
	}
	rangeScenarios(o, "whole", "whole.range.test")
	rangeScenarios(o, "s1m", "s1m.range.test")
	rangeScenarios(o, "s16m", "s16m.range.test")
	for _, line := range n.errors() {
		fmt.Println("LOG", line)
	}
}
