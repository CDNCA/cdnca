package main

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// ---------------------------------------------------------------- servertiming

// serverTiming: Server-Timing 响应头 on the real
// node skeleton with a cache. Off: no header, and one site object field is
// the only difference. On: cdn-cache (X-CDN-Cache's value), cdn-hit-layer
// edge on a hit, cdn-connect / cdn-ttfb when the node went upstream; the
// origin's own entries stay first. Then an L1 -> L2 pair (two nodes, the
// L2 trusting 127.0.0.1 as a node network): an L1 miss the L2 serves from
// its cache says cdn-hit-layer;desc=l2, X-Cdnca-L2-Cache never reaches the
// visitor, an origin's forged copy is ignored.
func serverTiming(o *originServer) {
	simple := policy(nil, 64<<20)
	on := makeSite(41, "st-on.d8.test", false, &simple)
	on.ServerTiming = true
	off := makeSite(42, "st-off.d8.test", false, &simple)
	nocache := makeSite(43, "st-nocache.d8.test", false, nil)
	nocache.ServerTiming = true
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	n, err := startNode([]edgesite.Site{on, off, nocache}, pool)
	if err != nil {
		check("start", false, "%v", err)
		return
	}
	if err := n.startCache(); err != nil {
		n.stop()
		check("sync", false, "%v", err)
		return
	}
	upstream := `cdn-connect;dur=[0-9]+, cdn-ttfb;dur=[0-9]+`
	matches := func(a answer, pattern string) bool {
		return a.err == nil && regexp.MustCompile("^"+pattern+"$").MatchString(a.headers.Get("Server-Timing")) &&
			len(a.headers.Values("Server-Timing")) <= 2
	}
	timing := func(a answer) string { return fmt.Sprintf("%d %q", a.status, a.headers.Values("Server-Timing")) }

	a, b := get("st-off.d8.test", "/a.css", nil), get("st-off.d8.test", "/a.css", nil)
	check("server-timing-off", a.status == 200 && b.cache == "HIT" && len(a.headers.Values("Server-Timing")) == 0 &&
		len(b.headers.Values("Server-Timing")) == 0, "%s / %s", timing(a), timing(b))

	miss, hit := get("st-on.d8.test", "/a.css", nil), get("st-on.d8.test", "/a.css", nil)
	bypass := get("st-on.d8.test", "/a.css", map[string]string{"Authorization": "Bearer x"})
	check("server-timing-miss", miss.cache == "MISS" && matches(miss, "cdn-cache;desc=MISS, "+upstream), "%s", timing(miss))
	check("server-timing-hit", hit.cache == "HIT" && matches(hit, "cdn-cache;desc=HIT, cdn-hit-layer;desc=edge"), "%s", timing(hit))
	check("server-timing-bypass", bypass.cache == "BYPASS" && matches(bypass, "cdn-cache;desc=BYPASS, "+upstream), "%s", timing(bypass))
	plain := get("st-nocache.d8.test", "/a.css", nil)
	check("server-timing-no-cache-plan", plain.status == 200 && matches(plain, upstream), "%s", timing(plain))
	// the origin's own entry first (stored with the object: the HIT keeps it)
	own1, own2 := get("st-on.d8.test", "/st-origin/x.css", nil), get("st-on.d8.test", "/st-origin/x.css", nil)
	appended := func(a answer, pattern string) bool {
		values := a.headers.Values("Server-Timing")
		return len(values) == 2 && values[0] == "app;dur=7" && regexp.MustCompile("^"+pattern+"$").MatchString(values[1])
	}
	check("server-timing-origin-appended", appended(own1, "cdn-cache;desc=MISS, "+upstream) &&
		appended(own2, "cdn-cache;desc=HIT, cdn-hit-layer;desc=edge"), "%s / %s", timing(own1), timing(own2))
	// an origin's X-Cdnca-L2-Cache: no l2 layer without an L2 hop, never shown
	forged1, forged2 := get("st-on.d8.test", "/l2forge/x.css", nil), get("st-on.d8.test", "/l2forge/x.css", nil)
	check("server-timing-l2-header-forged", matches(forged1, "cdn-cache;desc=MISS, "+upstream) && forged1.headers.Get("X-Cdnca-L2-Cache") == "" &&
		forged2.headers.Get("X-Cdnca-L2-Cache") == "", "%s %v", timing(forged1), forged2.headers)
	// attack escalation B: the control plane publishes the switch off
	escalated := on
	escalated.Revision, escalated.ServerTiming = 2, false
	if err := n.reactivate([]edgesite.Site{escalated, off, nocache}); err != nil {
		check("server-timing-escalated", false, "%v", err)
	} else {
		hidden := get("st-on.d8.test", "/a.css", nil)
		check("server-timing-escalated", hidden.cache == "HIT" && len(hidden.headers.Values("Server-Timing")) == 0, "%s", timing(hidden))
	}
	n.stop()
	serverTimingL2(o, pool)
}

const l2Edge = 18281

// serverTimingL2: L1 (state root *state, port 18280) -> L2 (its own root,
// port 18281) for the same site; the L2 serves the origin.
func serverTimingL2(o *originServer, pool edgecache.Pool) {
	simple := policy(nil, 64<<20)
	l2Site := makeSite(44, "st-l2.d8.test", false, &simple)
	l2Site.ServerTiming = true
	l2Site.Listeners = []edgesite.Listener{{Port: l2Edge, AddressFamily: edgesite.FamilyIPv4}}
	l1Site := makeSite(44, "st-l2.d8.test", false, &simple)
	l1Site.ServerTiming = true
	direct := l1Site.Origin.Pools[0]
	direct.ID = "direct"
	l1Site.Origin = edgesite.Origin{DefaultPoolID: "l2", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
		L2: &edgesite.L2{DirectFallbackPoolID: "direct", ProbeIntervalMS: 1000, FailureThreshold: 3, RecoveryThreshold: 1},
		Pools: []edgesite.Pool{direct, {ID: "l2", Kind: edgesite.PoolL2, Algorithm: "round_robin",
			Endpoints: []edgesite.Endpoint{{ID: "l2a", Scheme: "http", Host: "127.0.0.1", Port: l2Edge, Weight: 1,
				NodeID: "0d8a0000-0000-4000-8000-0000000000a2", MTLSIdentitySHA256: "sha256:" + strings.Repeat("0", 63) + "1", TopologyRevision: 1}},
			Retry: direct.Retry}}}
	l2, err := startNodeAt(filepath.Join(filepath.Dir(*state), "d8-l2"), []string{"127.0.0.1/32"}, []edgesite.Site{l2Site}, pool, nil)
	if err != nil {
		check("server-timing-l2-start", false, "L2: %v", err)
		return
	}
	defer l2.stop()
	l1, err := startNode([]edgesite.Site{l1Site}, pool)
	if err != nil {
		check("server-timing-l2-start", false, "L1: %v", err)
		return
	}
	defer l1.stop()
	if err := l2.startCache(); err != nil {
		check("server-timing-l2-start", false, "L2 sync: %v", err)
		return
	}
	if err := l1.startCache(); err != nil {
		check("server-timing-l2-start", false, "L1 sync: %v", err)
		return
	}
	upstream := `cdn-connect;dur=[0-9]+, cdn-ttfb;dur=[0-9]+`
	is := func(a answer, pattern string) bool {
		return a.err == nil && len(a.headers.Values("Server-Timing")) == 1 &&
			regexp.MustCompile("^"+pattern+"$").MatchString(a.headers.Get("Server-Timing")) && a.headers.Get("X-Cdnca-L2-Cache") == ""
	}
	timing := func(a answer) string {
		return fmt.Sprintf("%d %s %q l2=%q", a.status, a.cache, a.headers.Values("Server-Timing"), a.headers.Get("X-Cdnca-L2-Cache"))
	}
	// cold: both miss (the L2 fetched from the origin)
	first := get("st-l2.d8.test", "/b.css", nil)
	check("server-timing-l2-cold", first.cache == "MISS" && is(first, "cdn-cache;desc=MISS, "+upstream) &&
		o.count("st-l2.d8.test", "/b.css") == 1, "%s origin %d", timing(first), o.count("st-l2.d8.test", "/b.css"))
	again := get("st-l2.d8.test", "/b.css", nil)
	check("server-timing-l2-edge-hit", is(again, "cdn-cache;desc=HIT, cdn-hit-layer;desc=edge"), "%s", timing(again))
	// warm only the L2 (a visitor's request straight to it), then the L1 misses
	warm := getAt(l2Edge, "st-l2.d8.test", "/c.css", nil)
	viaL2 := get("st-l2.d8.test", "/c.css", nil)
	check("server-timing-l2-hit", warm.cache == "MISS" && is(viaL2, "cdn-cache;desc=MISS, cdn-hit-layer;desc=l2, "+upstream) &&
		o.count("st-l2.d8.test", "/c.css") == 1, "warm %s / via L2 %s origin %d", timing(warm), timing(viaL2), o.count("st-l2.d8.test", "/c.css"))
	// the L2 answering a visitor: its own Server-Timing, no L2 status header
	visitor := getAt(l2Edge, "st-l2.d8.test", "/c.css", nil)
	forgedHop := getAt(l2Edge, "st-l2.d8.test", "/c.css", map[string]string{"X-Cdnca-L2-Hop": "1", "X-Cdnca-L2-Timing": "1"})
	check("server-timing-l2-visitor", is(visitor, "cdn-cache;desc=HIT, cdn-hit-layer;desc=edge") && forgedHop.headers.Get("X-Cdnca-L2-Cache") != "",
		"visitor %s / hop from a node network %s", timing(visitor), timing(forgedHop))
}

func getAt(port int, host, path string, headers map[string]string) answer {
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return answer{err: err}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return answer{status: response.StatusCode, cache: response.Header.Get("X-CDN-Cache"), reason: response.Header.Get("X-CDN-Cache-Reason"),
		body: string(body), headers: response.Header}
}
