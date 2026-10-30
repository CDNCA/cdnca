package main

// -only buckets: ADR 0011 RI-15 automatic exclusion lifecycle on the node's
// exclusion buckets (RI-03d, edgeconfig.DynamicWAFBucketSites = 128 sites a
// bucket location per tier). 129 严格防护 sites each with its own exclusion
// of 941380 on its own parameter (p<n>):
//   - suggested (not in force): nothing is excluded, no bucket at all;
//   - in force: sites 0..127 share one bucket location, site 128 is in a
//     second one; every site's exclusion works on its own parameter only
//     (not on a neighbour's in the same bucket);
//   - revoked on one site (the agent re-renders without it and reloads):
//     that site's parameter is challenged again, every other site keeps its
//     exclusion.

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func bucketsRun() {
	strict := profileNamed(profiles(), "system/crs-pl2")
	count := edgeconfig.DynamicWAFBucketSites + 1
	sites := make([]edgesite.Site, 0, count)
	for index := range count {
		sites = append(sites, makeSite(1000+index, fmt.Sprintf("b%d.waf.test", index), &wafSpec{profile: strict}))
	}
	targets := map[string][]edgeconfig.DynamicWAFTarget{}
	for index, site := range sites {
		targets[site.SiteID] = []edgeconfig.DynamicWAFTarget{{Rule: 941380, Location: "args", Name: fmt.Sprintf("p%d", index)}}
	}
	defer func() { siteTargets = nil }()
	browser := map[string]string{"Accept": "text/html"}
	grey := url.QueryEscape(greyValue)
	status := func(index int, param string) int {
		return send(http.MethodGet, fmt.Sprintf("b%d.waf.test", index), "/t?"+param+"="+grey, "", browser).status
	}
	greyChallenge := func() bool {
		entries := make([]any, 0, len(sites))
		for _, site := range sites {
			entries = append(entries, map[string]any{"site_id": site.SiteID, "grey_challenge": true, "typed_params": []any{}})
		}
		code, text := controlPost("/waf-adapt/", map[string]any{"sites": entries})
		check("buckets waf-adapt", code == 204, "POST /waf-adapt/ %d %s", code, text)
		return code == 204
	}
	probed := []int{0, 1, 127, 128}

	// suggested: no exclusion in force
	siteTargets = nil
	node, err := startNode(sites, true)
	if err != nil {
		check("buckets start", false, "%v", err)
		return
	}
	defer stop()
	if !greyChallenge() {
		return
	}
	check("buckets suggested no bucket", len(node.waf.Skeleton.Buckets) == 0, "buckets %d", len(node.waf.Skeleton.Buckets))
	for _, index := range probed {
		got := status(index, fmt.Sprintf("p%d", index))
		check(fmt.Sprintf("buckets suggested b%d", index), got == 503, "own parameter %d (want challenge)", got)
	}

	// in force: 128 sites per bucket location
	siteTargets = targets
	waf, err := prepareWAF(sites)
	if err != nil || rerender(sites) != nil {
		check("buckets activate", false, "%v", err)
		return
	}
	if !greyChallenge() {
		return
	}
	perBucket := map[string]int{}
	for _, location := range waf.Skeleton.SiteBuckets {
		perBucket[location]++
	}
	first, last := waf.Skeleton.SiteBuckets[sites[0].SiteID], waf.Skeleton.SiteBuckets[sites[count-1].SiteID]
	check("buckets layout", len(waf.Skeleton.Buckets) == 2 && len(waf.Skeleton.SiteBuckets) == count &&
		perBucket[first] == edgeconfig.DynamicWAFBucketSites && perBucket[last] == 1 && first != last &&
		waf.Skeleton.SiteBuckets[sites[edgeconfig.DynamicWAFBucketSites-1].SiteID] == first,
		"buckets %d sites %d per bucket %v", len(waf.Skeleton.Buckets), len(waf.Skeleton.SiteBuckets), perBucket)
	for _, index := range probed {
		own := status(index, fmt.Sprintf("p%d", index))
		neighbour := status(index, fmt.Sprintf("p%d", (index+1)%count))
		check(fmt.Sprintf("buckets active b%d", index), own == 200 && neighbour == 503,
			"own parameter %d (want 200), neighbour's parameter %d (want challenge)", own, neighbour)
	}

	// revoked on site 1 (shares the first bucket with 0 and 127)
	revoked := map[string][]edgeconfig.DynamicWAFTarget{}
	for id, list := range targets {
		if id != sites[1].SiteID {
			revoked[id] = list
		}
	}
	siteTargets = revoked
	if err := rerender(sites); err != nil {
		check("buckets revoke reload", false, "%v", err)
		return
	}
	if !greyChallenge() {
		return
	}
	for _, index := range probed {
		want := 200
		if index == 1 {
			want = 503
		}
		got := status(index, fmt.Sprintf("p%d", index))
		check(fmt.Sprintf("buckets revoked b%d", index), got == want, "own parameter %d want %d", got, want)
	}
	for _, line := range errorLines() {
		check("buckets error log", false, "%s", line)
	}
}
