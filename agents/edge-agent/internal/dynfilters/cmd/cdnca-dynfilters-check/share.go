package main

import (
	"fmt"
	"math"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// ML-08: the leaf splits a market supply's totals over the pool's serving
// nodes, ceil(total / nodes) (marketsupply.NodeShare, same arithmetic), and
// republishes the site object when the count or the market's hold changes:
// stop = every request 503, a monthly traffic throttle = bandwidth
// throttle_bps / nodes, pause = nodes keep serving. These checks republish
// one site object to the running node (no reload) and measure what it runs.
const (
	shareSite  = "0d9a0000-0000-4000-8000-000000000230"
	shareHost  = "share.market.test"
	shareSub   = "0d9a0000-0000-4000-8000-000000000330"
	shareQPS   = 30        // supply total
	shareBPS   = 1_600_000 // supply total, bit/s
	throttleBP = 800_000   // monthly traffic throttle_bps (total)
)

func ceilShare(total int64, nodes int64) int64 {
	if total <= 0 {
		return 0
	}
	return total/nodes + min(total%nodes, 1)
}

// shareConnections is the site object limits for nodes serving nodes under
// hold (stop / throttle / pause / "").
func shareConnections(nodes int64, hold string) *edgesite.Connections {
	limit := &edgesite.Connections{SubscriptionID: shareSub, Max: -1, QPS: ceilShare(shareQPS, nodes),
		BandwidthBPS: ceilShare(shareBPS, nodes)}
	switch hold {
	case "stop":
		limit.Stopped = true
	case "throttle":
		limit.BandwidthBPS = min(limit.BandwidthBPS, ceilShare(throttleBP, nodes))
	}
	return limit
}

// leaked is how many more requests the qps limiter (resty.limit.req, a burst
// of qps at once then qps a second) admits while a burst takes elapsed: on a
// slow machine 60 new connections spread over a few hundred milliseconds. At
// least 2 (the tolerance of a fast machine).
func leaked(qps int, elapsed time.Duration) int {
	return max(2, int(math.Ceil(float64(qps)*elapsed.Seconds())))
}

func checkShare(n *node) {
	fmt.Println("== market node share and holds (ADR 0012 ML-08): re-split on the node count, stop, throttle")
	revision := int64(10)
	publish := func(nodes int64, hold string) bool {
		revision++
		sites := baseSites(n)
		site := makeSite(shareSite, shareHost, revision)
		site.Limits.Connections = shareConnections(nodes, hold)
		sites = append(sites, site)
		if err := n.activate(sites); err != nil {
			check(fmt.Sprintf("share-activate-%d-%s", nodes, hold), false, "%v", err)
			return false
		}
		time.Sleep(1100 * time.Millisecond) // a fresh QPS second
		return true
	}
	timed := func() time.Duration {
		started := time.Now()
		answer := raw(plain, "GET", shareHost, "/big", nil, "")
		if len(answer.Body) != bigBody {
			return 0
		}
		return time.Since(started)
	}
	// One serving node: the node runs the whole total.
	if !publish(1, "") {
		return
	}
	started := time.Now()
	counts, _ := burst(shareHost, 60)
	most := shareQPS + leaked(shareQPS, time.Since(started))
	check("share-qps-1-node", counts[200] >= shareQPS && counts[200] <= most && counts[503] == 60-counts[200],
		"60 at once, total %d on 1 node (at most %d): %v", shareQPS, most, counts)
	time.Sleep(1100 * time.Millisecond)
	one := timed()
	// 400 KB at 200 000 B/s: 1-3 s
	check("share-bw-1-node", one > 900*time.Millisecond && one < 3500*time.Millisecond, "400 KB at %d bit/s: %s", shareBPS, one)

	// Three serving nodes: ceil(30/3) = 10 QPS, 533 334 bit/s on this node.
	if !publish(3, "") {
		return
	}
	started = time.Now()
	counts, _ = burst(shareHost, 60)
	most = 10 + leaked(10, time.Since(started))
	check("share-qps-3-nodes", counts[200] >= 10 && counts[200] <= most && counts[503] == 60-counts[200],
		"60 at once, share %d (at most %d): %v", ceilShare(shareQPS, 3), most, counts)
	time.Sleep(1100 * time.Millisecond)
	three := timed()
	// 400 KB at 66 667 B/s: 5-7 s, about three times the one node time
	check("share-bw-3-nodes", three > 4500*time.Millisecond && three < 8*time.Second && three > 2*one,
		"share %d bit/s: %s (1 node %s)", ceilShare(shareBPS, 3), three, one)

	// stop hold: every request 503 on h1/h2/h3; release serves again.
	if !publish(3, "stop") {
		return
	}
	stopped, _ := burst(shareHost, 5)
	h2 := probe("h2", shareHost, "/ok")
	h3 := probe("h3", shareHost, "/ok")
	check("share-stop", stopped[503] == 5 && h2.Status == 503 && h3.Status == 503, "h1 %v, h2 %d, h3 %d", stopped, h2.Status, h3.Status)
	// pause: DNS only, the node serves under the same limits.
	if !publish(3, "pause") {
		return
	}
	paused := raw(plain, "GET", shareHost, "/ok", nil, "")
	check("share-pause-serves", paused.Status == 200 && paused.Body == "origin-ok-body\n", "%s", paused)

	// Monthly traffic throttle 1 600 000 bit/s total over 2 nodes: 800 000
	// bit/s here = 100 000 B/s, 400 KB in 3-4 s; released: the bandwidth
	// share of 2 nodes, 800 000 bit/s as well, so the throttle is checked
	// against the stricter 1 node cap below.
	if !publish(1, "throttle") {
		return
	}
	throttled := timed()
	check("share-throttle", throttled > 2500*time.Millisecond && throttled < 6*time.Second,
		"throttle %d bit/s on 1 node (cap %d): %s", ceilShare(throttleBP, 1), shareBPS, throttled)
	if !publish(1, "") {
		return
	}
	released := timed()
	check("share-released", released > 900*time.Millisecond && released < 3500*time.Millisecond && released < throttled*2/3,
		"released, share %d bit/s: %s (throttled %s)", ceilShare(shareBPS, 1), released, throttled)
}
