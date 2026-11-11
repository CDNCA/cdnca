package main

import (
	"fmt"
	"regexp"
)

// Server-Timing 响应头: the cdnca_filters slot 3b on
// h1, h2 and h3, appended after the origin's own entries, kept on a replaced
// error page (the origin's 503 here: connect and first byte are what one
// debugs), absent while the site object does not carry server_timing. This
// node runs no cache module (the cache module's stand-in slot only), so
// cdn-cache / cdn-hit-layer are left out here; tests/dynroute-cache
// ONLY=servertiming covers them on the real skeleton with a cache.
var serverTimingNoCache = regexp.MustCompile(`^cdn-connect;dur=[0-9]+, cdn-ttfb;dur=[0-9]+$`)

func checkServerTiming(n *node) {
	fmt.Println("== server timing")
	on := respSite(n, 1, nil)
	on.ServerTiming = true
	if err := n.activate(append(baseSites(n), on)); err != nil {
		check("activate-server-timing", false, "%v", err)
		return
	}
	plainAnswer := raw(plain, "GET", respHost, "/resp/st", nil, "")
	check("server-timing-h1", plainAnswer.Status == 200 && serverTimingNoCache.MatchString(plainAnswer.Headers["server-timing"]),
		"%d %q", plainAnswer.Status, plainAnswer.Headers["server-timing"])
	for _, proto := range []string{"h2", "h3"} {
		result := probe(proto, respHost, "/resp/st")
		check("server-timing-"+proto, result.Status == 200 && serverTimingNoCache.MatchString(result.Headers["server-timing"]),
			"%s %d %q %s", result.Proto, result.Status, result.Headers["server-timing"], result.Err)
	}
	// the origin's own entry first, the node's after it (two header lines)
	appended := raw(plain, "GET", respHost, "/resp/st-origin?h=Server-Timing:app%3Bdur%3D7", nil, "")
	check("server-timing-appended", regexp.MustCompile(`^app;dur=7, cdn-connect;dur=[0-9]+, cdn-ttfb;dur=[0-9]+$`).
		MatchString(appended.Headers["server-timing"]), "%q", appended.Headers["server-timing"])
	replaced := raw(plain, "GET", respHost, "/resp/st-503?s=503", nil, "")
	check("server-timing-replaced-page", replaced.Status == 503 && replaced.Headers["cache-control"] == "no-store, max-age=0" &&
		serverTimingNoCache.MatchString(replaced.Headers["server-timing"]), "%d %v", replaced.Status, replaced.Headers)

	off := respSite(n, 2, nil)
	if err := n.activate(append(baseSites(n), off)); err != nil {
		check("activate-server-timing-off", false, "%v", err)
		return
	}
	plainAnswer = raw(plain, "GET", respHost, "/resp/st", nil, "")
	h2 := probe("h2", respHost, "/resp/st")
	kept := raw(plain, "GET", respHost, "/resp/st-origin?h=Server-Timing:app%3Bdur%3D7", nil, "")
	check("server-timing-off", plainAnswer.Status == 200 && plainAnswer.Headers["server-timing"] == "" && h2.Status == 200 &&
		h2.Headers["server-timing"] == "" && kept.Headers["server-timing"] == "app;dur=7",
		"h1 %q h2 %q origin's %q", plainAnswer.Headers["server-timing"], h2.Headers["server-timing"], kept.Headers["server-timing"])
}
