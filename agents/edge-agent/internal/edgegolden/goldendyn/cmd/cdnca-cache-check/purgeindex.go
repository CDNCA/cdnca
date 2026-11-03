package main

// purgeindex: the purge indexes (dyncache.Indexes,
// as the agent runs them) on a real OpenResty that fills and evicts while
// they sync. Four sites on two zones of a small pool (the cache manager
// evicts under max_size), each with a wildcard alias; ROUNDS rounds of
// random traffic with directory and wildcard purges through the indexes in
// flight (shadow checks under live writes and evictions), then, with the
// traffic stopped, purges whose removals are compared with what a zone
// scan finds: every file the scan matches is removed, nothing else.

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	soakDirs    = 16  // directories per host
	soakFiles   = 400 // files per directory
	soakSubs    = 4   // wildcard hosts per site
	soakWorkers = 16
)

// soakSite is a cached site with "*.img.<host>" and the dyncache view of it.
func soakSite(number int, host string) (edgesite.Site, dyncache.Site) {
	document := policy(nil, 1<<30)
	site := makeSite(number, host, false, &document)
	site.Hosts.Aliases = []string{"*.img." + host}
	view := cacheSite(site)
	view.Names = append(view.Names, site.Hosts.Aliases...)
	return site, view
}

// soakURL: request i (0 <= i < soakDirs*soakFiles*4) of a site (host,
// path); the last quarter on the wildcard hosts, in every directory.
func soakURL(host string, i int) (string, string) {
	dir, file, variant := i%soakDirs, i/soakDirs%soakFiles, i/(soakDirs*soakFiles)
	if variant == 3 {
		host = fmt.Sprintf("a%d.img.%s", file%soakSubs, host)
	}
	return host, fmt.Sprintf("/d%02d/f%03d.css?size=2048", dir, file)
}

// soakTarget: directory dir of the site's primary host, or of every host
// under its wildcard alias.
func soakTarget(view dyncache.Site, wildcard bool, dir int) (dyncache.Target, string) {
	host := view.Names[0]
	if wildcard {
		host = "*.img." + host
	}
	raw := fmt.Sprintf("http://%s:%d/d%02d/", host, edge, dir)
	target, err := dyncache.ParseTarget(view, raw, true)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", raw, err))
	}
	return target, raw
}

type soakNode struct {
	n       *node
	zones   dyncache.Zones
	indexes *dyncache.Indexes
	views   []dyncache.Site
	misses  atomic.Int64
	served  atomic.Int64
	failed  atomic.Int64
	purges  atomic.Int64
	purgeMu sync.Mutex // the agent runs one cache task at a time
	// scanOnly: the control run (-purgescan): purges scan, no index
	scanOnly bool
}

func (soak *soakNode) purge(view dyncache.Site, target dyncache.Target) (dyncache.Result, error) {
	soak.purgeMu.Lock()
	defer soak.purgeMu.Unlock()
	if soak.scanOnly {
		return soak.zones.Purge(context.Background(), view, []dyncache.Target{target}, true, nil)
	}
	return soak.indexes.Purge(context.Background(), soak.zones, view, []dyncache.Target{target}, true, nil)
}

// fill sends random requests until stop closes; with purges, a purger
// runs directory and wildcard purges through the indexes meanwhile.
func (soak *soakNode) fill(stop <-chan struct{}, seed int64, purges bool) {
	var wait sync.WaitGroup
	for worker := range soakWorkers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			random := rand.New(rand.NewSource(seed*100 + int64(worker)))
			for {
				select {
				case <-stop:
					return
				default:
				}
				view := soak.views[random.Intn(len(soak.views))]
				host, path := soakURL(view.Names[0], random.Intn(soakDirs*soakFiles*4))
				a := get(host, path, nil)
				soak.served.Add(1)
				switch {
				case a.err != nil || a.status != 200:
					soak.failed.Add(1)
				case a.cache == "MISS":
					soak.misses.Add(1)
				}
			}
		}()
	}
	if purges {
		wait.Add(1)
		go func() {
			defer wait.Done()
			random := rand.New(rand.NewSource(seed))
			for {
				select {
				case <-stop:
					return
				case <-time.After(time.Duration(200+random.Intn(400)) * time.Millisecond):
				}
				view := soak.views[random.Intn(len(soak.views))]
				target, raw := soakTarget(view, random.Intn(2) == 0, random.Intn(soakDirs))
				_, err := soak.purge(view, target)
				soak.purges.Add(1)
				if err != nil {
					check("PURGEINDEX-LIVE", false, "%s: %v", raw, err)
				}
			}
		}()
	}
	wait.Wait()
}

// files is every cache file of the pool: path -> key.
func (soak *soakNode) files() map[string]dyncache.Key {
	found := map[string]dyncache.Key{}
	_ = soak.zones.WalkAll(context.Background(), func(entry dyncache.Entry) error {
		found[entry.Path] = entry.Key
		return nil
	})
	return found
}

// settled waits for the cache manager to stop removing files after the
// traffic stopped (it evicts a backlog in batches): three walks a second
// apart see the same files.
func (soak *soakNode) settled() map[string]dyncache.Key {
	previous, same := soak.files(), 0
	for range 120 {
		time.Sleep(time.Second)
		current := soak.files()
		if len(current) == len(previous) && sameFiles(current, previous) {
			if same++; same == 2 {
				return current
			}
		} else {
			same = 0
		}
		previous = current
	}
	fmt.Println("INFO the cache manager did not settle in 120s")
	return previous
}

func sameFiles(left, right map[string]dyncache.Key) bool {
	for path := range left {
		if _, ok := right[path]; !ok {
			return false
		}
	}
	return true
}

// quiesced: one purge with the traffic stopped. The files a zone scan
// matches (computed from the disk before) are exactly the ones removed.
func (soak *soakNode) quiesced(round int, view dyncache.Site, wildcard bool, dir int) {
	target, raw := soakTarget(view, wildcard, dir)
	before := soak.settled()
	matched := map[string]bool{}
	for path, key := range before {
		if key.Prefix == view.Prefix && target.Matches(view, key, true) {
			matched[path] = true
		}
	}
	result, err := soak.purge(view, target)
	after := soak.files()
	missed, extra := 0, 0
	for path := range before {
		_, kept := after[path]
		switch {
		case matched[path] && kept:
			missed++
		case !matched[path] && !kept:
			extra++
		}
	}
	trace := soak.trace(view)
	check(fmt.Sprintf("PURGEINDEX-QUIESCED-%d-%s", round, map[bool]string{false: "dir", true: "wild"}[wildcard]),
		err == nil && missed == 0 && extra == 0 && result.Affected == len(matched),
		"%s via %s: scan matches %d, removed %d, matched left %d, others removed %d (of %d files) %v",
		raw, trace, len(matched), result.Affected, missed, extra, len(before), err)
}

// trace is the path the site's zone's last purge took.
func (soak *soakNode) trace(view dyncache.Site) string {
	dir, _ := soak.zones.ZoneOf(view.Prefix)
	for _, zone := range soak.indexes.Status().Zones {
		if filepath.Join(soak.zones.Root, fmt.Sprintf("cdnca-%d", zone.Zone)) == dir && zone.LastPurge != nil {
			return zone.LastPurge.Path + "(" + string(zone.State) + ")"
		}
	}
	return "?"
}

func purgeIndexRun(o *originServer) {
	// two sites in each of two zones
	var sites []edgesite.Site
	var views []dyncache.Site
	perZone := map[int]int{}
	for number := 7000; len(sites) < 4; number++ {
		zone, _ := edgecache.ZoneIndex(edgesite.CacheKeyPrefix(tenant, siteID(number)), 2)
		if perZone[zone] == 2 {
			continue
		}
		perZone[zone]++
		site, view := soakSite(number, fmt.Sprintf("p%d.pidx.d8.test", number))
		sites, views = append(sites, site), append(views, view)
	}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 128 << 20})
	// a few thousand 2 KiB objects per zone: the cache manager evicts by
	// max_size (the keys zone holds 64k nodes, so it is never the limit,
	// as edgecache.PlanPool sizes it for a real zone)
	pool.Zones, pool.MaxBytes, pool.KeysZoneBytes = 2, 16<<20, 8<<20
	n, err := startNode(sites, pool)
	if err != nil {
		check("PURGEINDEX-START", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("PURGEINDEX-SYNC", false, "%v", err)
		return
	}
	soak := &soakNode{n: n, zones: n.zones(), views: views, scanOnly: *purgeScan}
	soak.indexes = dyncache.NewIndexes(filepath.Join(*state, "cache-index"), dyncache.IndexSettings{
		SyncInterval: 2 * time.Second, ShadowRuns: 2, RecheckPurges: 5})
	prefixes := map[string]string{}
	for _, site := range sites {
		prefixes[site.SiteID] = site.Cache.KeyPrefix
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		soak.indexes.Run(ctx, func() dyncache.IndexLayout {
			return dyncache.IndexLayout{Root: soak.zones.Root, Zones: pool.Zones, ZoneBytes: pool.MaxBytes, Prefixes: prefixes}
		})
	}()
	defer func() { cancel(); <-done }()
	started := time.Now()
	for round := range *rounds {
		stop := make(chan struct{})
		go func() { time.Sleep(*fillTime); close(stop) }()
		soak.fill(stop, int64(round+1), true)
		for index, view := range views {
			soak.quiesced(round, view, index%2 == 1, (round*3+index)%soakDirs)
		}
		status := soak.indexes.Status()
		fmt.Printf("INFO round %d: served %d (miss %d, failed %d), live purges %d, resident %d; zones %s\n", round,
			soak.served.Load(), soak.misses.Load(), soak.failed.Load(), soak.purges.Load(), len(soak.files()), zoneSummary(status))
	}
	status := soak.indexes.Status()
	resident := len(soak.files())
	healthy := len(status.Zones) == 2 || soak.scanOnly
	for _, zone := range status.Zones {
		healthy = healthy && zone.Mismatches == 0 && zone.Rebuilds == 0 && (zone.State == dyncache.IndexActive || soak.scanOnly)
	}
	check("PURGEINDEX-ZONES", healthy, "%s", zoneSummary(status))
	check("PURGEINDEX-EVICTED", soak.misses.Load() > int64(resident)*3 && soak.failed.Load() == 0,
		"%d fills, %d resident at the end (the cache manager evicted), %d failed requests, %d live purges in %v",
		soak.misses.Load(), resident, soak.failed.Load(), soak.purges.Load(), time.Since(started).Round(time.Second))
	// nginx logs crit "unlink() / stat() ... failed (2: No such file or
	// directory)" for a purged file its cache manager evicts or checks later
	// (its keys zone node stays until a request misses it): the same for a
	// scan or an index purge (PURGESCAN=1 measures it)
	enoent, other := 0, 0
	for _, line := range n.errors() {
		if (strings.Contains(line, "unlink()") || strings.Contains(line, "stat()")) &&
			strings.Contains(line, "(2: No such file or directory)") {
			enoent++
			continue
		}
		other++
		fmt.Println("LOG", line)
	}
	fmt.Printf("INFO error.log: %d unlink/stat ENOENT (purged files the cache manager evicted later), %d other (scan only %v)\n",
		enoent, other, soak.scanOnly)
	check("PURGEINDEX-ERRORLOG", other == 0, "%d error.log lines besides unlink/stat ENOENT", other)
}

func zoneSummary(status dyncache.IndexesStatus) string {
	summary := ""
	for _, zone := range status.Zones {
		summary += fmt.Sprintf("[zone %d %s%s objects %d index %d KiB mismatches %d rebuilds %d] ", zone.Zone, zone.State,
			map[bool]string{true: "/" + zone.Reason}[zone.Reason != ""], zone.Objects, zone.IndexBytes>>10, zone.Mismatches, zone.Rebuilds)
	}
	return summary
}
