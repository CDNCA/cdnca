package main

// slicebg: a policy's slices (slice_bytes) with stale-if-error and
// background update, chunking off (ADR 0021 section 7, fixed).
// nginx's background update subrequest has no
// slice context: $slice_range is empty there, so it would ask the origin
// for the whole object without Range and store it under "<key>|slice=".
// Every origin request of a sliced site must carry its slice's Range and no
// object may be stored under an empty slice.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func sliceBackground(o *rangeOrigin) {
	document := policy([]edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".bin"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 1}}, 4<<30)
	document.StaleIfError, document.BackgroundUpdate, document.SliceBytes = true, true, 256<<10
	site := rangeSite(71, "slicebg.range.test", document)
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 1 << 30}) // chunking off: the policy's slices
	n, err := startNode([]edgesite.Site{site}, pool)
	if err != nil {
		check("slicebg-start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("slicebg-sync", false, "%v", err)
		return
	}
	plan, _ := edgecache.Build(site)
	host, path := site.Hosts.Primary, "/bg/v.bin"
	uri := path + "?size=716800"
	a := rangeGet(host, uri, rangeHeader(300000, 300009))
	o.quiet(10 * time.Second)
	time.Sleep(2200 * time.Millisecond) // the 1 s TTL is over
	b := rangeGet(host, uri, rangeHeader(300010, 300019))
	o.quiet(10 * time.Second)
	time.Sleep(300 * time.Millisecond) // a background update ends after the client's response
	o.quiet(10 * time.Second)
	c := rangeGet(host, uri, rangeHeader(300020, 300029))
	stats := o.of(path)
	unranged := 0
	for _, value := range stats.Ranges {
		if value == "" {
			unranged++
		}
	}
	var emptySlice []string
	_ = n.zones().Walk(context.Background(), site.Cache.KeyPrefix, func(entry dyncache.Entry) error {
		if entry.Key.Path == path && entry.Key.Slice == "" {
			emptySlice = append(emptySlice, fmt.Sprintf("%s (%d bytes)", entry.Key.PolicyKey, entry.Size))
		}
		return nil
	})
	check("SLICE-BACKGROUND-UPDATE-KEEPS-RANGE", strings.HasSuffix(plan.Variant(), "_stalebg_s256") && a.part(300000, 10, 0, 716800) &&
		b.part(300010, 10, 0, 716800) && c.part(300020, 10, 0, 716800) && unranged == 0 && len(emptySlice) == 0 &&
		// refreshed (HIT, or REVALIDATED when the 1 s TTL ran out again):
		// never left STALE as with the whole object stored under "|slice="
		(c.cache == "HIT" || c.cache == "REVALIDATED"),
		"variant %s / %v / %v / %v / origin %d requests %d bytes ranges %q / empty slice objects %v",
		plan.Variant(), a, b, c, stats.Requests, stats.Bytes, stats.Ranges, emptySlice)
	for _, line := range n.errors() {
		fmt.Println("LOG", line)
	}
}
