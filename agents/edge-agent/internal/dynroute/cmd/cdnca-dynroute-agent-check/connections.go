package main

import (
	"time"
)

// Per-site in-flight counts (D13-b2 交接 4): two sites on one port, a
// request held at the origin counts for its site only; read back over the
// control socket (Runtime.SiteConnections) and released after the response.
func checkSiteConnections(h *harness) {
	shopID, blogID := siteID(1), siteID(2)
	done := make(chan answer, 1)
	go func() { done <- get(portPlain, "shop.d13.test", "/hold/connections") }()
	time.Sleep(700 * time.Millisecond)
	counts, evidence, err := h.runtime.SiteConnections(h.ctx)
	got := map[string]uint64{}
	for _, count := range counts {
		if count.Port == portPlain {
			got[count.SiteID] = count.Connections
		}
	}
	check("site-connections-in-flight", err == nil && got[shopID] == 1 && got[blogID] == 0 && evidence != [32]byte{},
		"%v %v", got, err)
	held := <-done
	counts, _, err = h.runtime.SiteConnections(h.ctx)
	left := uint64(0)
	for _, count := range counts {
		if count.SiteID == shopID {
			left += count.Connections
		}
	}
	check("site-connections-released", err == nil && held.status == 200 && left == 0, "%d left %d %v", held.status, left, err)
}
