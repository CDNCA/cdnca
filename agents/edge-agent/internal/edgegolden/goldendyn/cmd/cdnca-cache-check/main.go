// Command cdnca-cache-check is the dynamic routing D8 acceptance run on a
// real OpenResty (tests/dynroute-cache/run.sh starts it in the node runtime
// image built with patch 24, one --rm --network none container). It starts a
// mock origin, a dynamic routing node with the shared zone pool
// (goldendyn.Config + libs/edgeconfig/edgecache), activates SCALE caching
// sites through the D3 index and checks:
//   - Range under dynamic routing (ge-cache D): a range site answers Range
//     from the cached object (206 HIT, origin asked once, without Range); a
//     range-off site serves the whole object; uncached Range forwarded;
//   - per-rule TTL through patch 24 (two sites, same path, different TTLs);
//   - the cache status header (MISS/HIT/BYPASS + reason, STALE);
//   - every site's plan in Lua equals edgecache.Build (differential);
//   - SCALE sites on the shared pool: hit rate of a Zipf workload;
//   - purge isolation: purging site A (URL, prefix, whole site) never
//     touches site B (same zone, same paths);
//   - soft quota: an over-quota site is trimmed by LRU, others untouched;
//   - a purge generation bump is immediate and survives a restart only
//     through the agent's sync (fail closed until then);
//   - ge-cache policy fields: stale_if_error (stale object on origin 5xx),
//     background_update, min/max_object_bytes (BYPASS object_size), slice
//     variants (origin asked per slice, 206 cached, URL purge removes every
//     slice), Accept-Ranges on every cached site and v7 reason names;
//   - 响应头显示缓存状态 (statusheader): X-CDN-Cache
//     and X-CDN-Cache-Reason only with the site object's cache_status_header
//     (off as published at escalation B and above), always on a prewarm, an
//     origin's forged headers removed either way.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

var (
	luaRoot  = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	state    = flag.String("state", "/tmp/d8", "state directory")
	workers  = flag.Int("workers", 2, "worker_processes")
	scale    = flag.Int("scale", 10000, "sites on the shared pool")
	requests = flag.Int("requests", 100000, "requests of the hit rate workload")
	only     = flag.String("only", "", "comma separated parts: functional,extensions,rulematch,ruleextras,follow,statusheader,scale")
)

const (
	scope  = "0d8a0000-0000-4000-8000-000000000001"
	tenant = "0d8a0000-0000-4000-8000-000000000002"
	edge   = 18280
	origin = "127.0.0.1:19801"
)

var failures int

func check(name string, ok bool, format string, args ...any) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("%s %s %s\n", status, name, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------- origin

// mock origin: GET /<anything> answers 200 with a body of size given by
// ?size= (default 64), Range served by net/http ServeContent; /cc/ adds
// Cache-Control max-age=60; /nostore/ no-store; /e404/ answers 404;
// /slow503/ 503; ?ct= sets the Content-Type; [/x]/r/<code>/<rest> redirects
// with <code> to ?to= (rest "loop...": to itself) (default "/final/<rest>", Cache-Control max-age=60
// and a Set-Cookie: never stored by the edge as such). Every request is
// counted per (host, path) and Range kept.
type originServer struct {
	mu       sync.Mutex
	counts   map[string]int
	ranges   map[string][]string
	total    atomic.Int64
	failNext atomic.Bool
}

func (o *originServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	o.total.Add(1)
	key := request.Host + request.URL.Path
	o.mu.Lock()
	o.counts[key]++
	o.ranges[key] = append(o.ranges[key], request.Header.Get("Range"))
	o.mu.Unlock()
	if o.failNext.Load() {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/slow/") {
		time.Sleep(300 * time.Millisecond)
	}
	size := 64
	if value, err := strconv.Atoi(request.URL.Query().Get("size")); err == nil && value > 0 {
		size = value
	}
	body := []byte(strings.Repeat(string(rune('a'+len(request.URL.Path)%26)), size))
	path := request.URL.Path
	if index := strings.Index(path, "/r/"); index >= 0 {
		code, rest, _ := strings.Cut(path[index+3:], "/")
		status, _ := strconv.Atoi(code)
		target := request.URL.Query().Get("to")
		switch {
		case strings.HasPrefix(rest, "loop"):
			target = request.URL.RequestURI() // to itself, forever
		case target == "":
			target = "/final/" + rest
		}
		writer.Header().Set("Location", target)
		writer.Header().Set("Cache-Control", "max-age=60")
		writer.Header().Set("X-Origin-Redirect", "1")
		writer.WriteHeader(status)
		return
	}
	switch {
	case strings.HasPrefix(path, "/cc/"):
		writer.Header().Set("Cache-Control", "max-age=60")
	case strings.HasPrefix(path, "/nostore/"):
		writer.Header().Set("Cache-Control", "no-store")
	case strings.HasPrefix(path, "/forge/"):
		// an origin answering the edge's own cache headers
		writer.Header().Set("X-CDN-Cache", "HIT-FORGED")
		writer.Header().Set("X-CDN-Cache-Reason", "forged")
	case strings.HasPrefix(path, "/vary/"):
		// a body per X-Device, split by Vary (ruleextras: ignore_vary)
		writer.Header().Set("Vary", "X-Device")
		writer.Header().Set("ETag", `"v-`+request.Header.Get("X-Device")+`"`)
		_, _ = writer.Write([]byte("device=" + request.Header.Get("X-Device")))
		return
	case strings.Contains(path, "/maxage5/"):
		// a short origin lifetime the rule's force_cache overrides
		writer.Header().Set("Cache-Control", "max-age=1")
	case strings.HasPrefix(path, "/e404/"):
		writer.Header().Set("Content-Length", "3")
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte("404"))
		return
	}
	writer.Header().Set("ETag", `"e1"`)
	if value := request.URL.Query().Get("ct"); value != "" {
		writer.Header().Set("Content-Type", value)
	}
	http.ServeContent(writer, request, "", time.Time{}, strings.NewReader(string(body)))
}

func (o *originServer) count(host, path string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.counts[host+path]
}

func (o *originServer) lastRange(host, path string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	values := o.ranges[host+path]
	if len(values) == 0 {
		return "<none>"
	}
	return values[len(values)-1]
}

// ---------------------------------------------------------------- sites

func siteID(number int) string { return fmt.Sprintf("0d8a0000-0000-4000-8000-%012d", number) }

func policy(rules []edgeconfig.CacheRuleDocument, quota int64) edgeconfig.CachePolicyDocument {
	document := edgeconfig.CachePolicyDocument{Revision: 1, Mode: edgeconfig.CacheOverride, Rules: []edgeconfig.CacheRuleDocument{},
		QueryMode: edgeconfig.CacheQueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: quota}
	if len(rules) != 0 {
		document.SchemaVersion, document.Rules = 2, rules
	}
	return document
}

func makeSite(number int, host string, rangeOn bool, document *edgeconfig.CachePolicyDocument) edgesite.Site {
	site := edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID(number), Revision: 1,
		Hosts: edgesite.Hosts{Primary: host, Aliases: []string{}}, Range: rangeOn, CacheStatusHeader: true,
		Listeners: []edgesite.Listener{{Port: edge, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: 19801, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 5000, TotalBudgetMS: 10000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
	}
	if document != nil {
		cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(tenant, site.SiteID), Domain: host, KeyByHost: true, Policy: *document}
		cache.Generation, _ = edgesite.CacheGeneration(*cache)
		site.Cache = cache
	}
	return site
}

func cacheSite(site edgesite.Site) dyncache.Site {
	return dyncache.Site{SiteID: site.SiteID, Prefix: site.Cache.KeyPrefix, Token: site.Cache.Generation, Domain: site.Cache.Domain,
		KeyByHost: site.Cache.KeyByHost, Names: []string{site.Hosts.Primary}, Ports: map[int]string{edge: "http"},
		QuotaBytes: site.Cache.Policy.DiskQuotaBytes}
}

// ---------------------------------------------------------------- node

type node struct {
	root        string
	pool        edgecache.Pool
	activator   *siteindex.Activator
	generations *dyncache.Generations
	control     dyncache.UnixControl
	prewarmer   dyncache.Prewarmer
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func (n *node) openresty(args ...string) error {
	output, err := exec.Command("openresty", append([]string{"-p", n.root + "/", "-c", "nginx.conf"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v %s", args, err, output)
	}
	return nil
}

func startNode(sites []edgesite.Site, pool edgecache.Pool) (*node, error) {
	return startNodeWith(sites, pool, nil)
}

// startNodeWith: referenced objects (error page bodies) are supplied with
// every site object.
func startNodeWith(sites []edgesite.Site, pool edgecache.Pool, referenced map[string][]byte) (*node, error) {
	n := &node{root: *state, pool: pool}
	_ = n.openresty("-s", "stop")
	time.Sleep(200 * time.Millisecond)
	_ = os.RemoveAll(*state)
	for _, dir := range []string{"logs", "run", "site-index", "site-objects", "temp", "shared/cache"} {
		if err := os.MkdirAll(filepath.Join(*state, dir), 0o777); err != nil {
			return nil, err
		}
	}
	_ = os.Chmod(filepath.Join(*state, "shared", "cache"), 0o777)
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return nil, err
	}
	keys := 0
	for _, s := range sites {
		keys += len(s.IndexEntries())
	}
	conf, err := goldendyn.Config(goldendyn.ConfigInput{Root: *state, LuaRoot: *luaRoot, Ports: ports, IndexKeys: keys, Workers: *workers, Cache: pool})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(*state, "nginx.conf"), conf, 0o644); err != nil {
		return nil, err
	}
	if err := n.openresty(); err != nil {
		return nil, err
	}
	control := siteindex.NewControl(filepath.Join(*state, "run", "cdnca-site-admin.sock"))
	n.activator = &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(*state, "site-index"), Access: siteindex.Access{GID: workerGID()}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*state, "site-objects"), Access: siteindex.Access{GID: workerGID()}}}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := control.Status(context.Background()); err == nil {
			break
		} else if time.Now().After(deadline) {
			return nil, err
		}
	}
	objects := make([]siteindex.Object, 0, len(sites))
	for _, s := range sites {
		raw, err := edgesite.Encode(s)
		if err != nil {
			return nil, err
		}
		object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
		if err != nil {
			return nil, err
		}
		object.Referenced = referenced
		objects = append(objects, object)
	}
	activation, err := n.activator.Activate(context.Background(), objects)
	if err != nil {
		return nil, err
	}
	if err := n.activator.WaitGeneration(context.Background(), activation.Generation); err != nil {
		return nil, err
	}
	n.control = dyncache.UnixControl{Socket: filepath.Join(*state, "run", "cdnca-site-admin.sock")}
	n.generations = &dyncache.Generations{Path: filepath.Join(*state, "generations.json"), Control: n.control}
	n.prewarmer = dyncache.Prewarmer{Token: strings.Repeat("ab", 32), Address: "127.0.0.1", Timeout: 10 * time.Second, MaxBytes: 64 << 20}
	return n, nil
}

// reactivate replaces the node's sites (a new publication, no restart).
func (n *node) reactivate(sites []edgesite.Site) error {
	objects := make([]siteindex.Object, 0, len(sites))
	for _, s := range sites {
		raw, err := edgesite.Encode(s)
		if err != nil {
			return err
		}
		object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
		if err != nil {
			return err
		}
		objects = append(objects, object)
	}
	activation, err := n.activator.Activate(context.Background(), objects)
	if err != nil {
		return err
	}
	return n.activator.WaitGeneration(context.Background(), activation.Generation)
}

func (n *node) startCache() error {
	if err := n.generations.Sync(context.Background()); err != nil {
		return err
	}
	return dyncache.SetPrewarmToken(context.Background(), n.control, n.prewarmer.Token)
}

func (n *node) zones() dyncache.Zones {
	return dyncache.Zones{Root: filepath.Join(n.root, goldendyn.SharedDirectory, "cache"), Count: n.pool.Zones}
}

func (n *node) stop() { _ = n.openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

func (n *node) errors() []string {
	raw, _ := os.ReadFile(filepath.Join(n.root, goldendyn.SharedDirectory, "error.log"))
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "[error]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[alert]") || strings.Contains(line, "[emerg]") {
			lines = append(lines, line)
		}
	}
	return lines
}

// ---------------------------------------------------------------- client

var client = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256, DisableCompression: true}, Timeout: 10 * time.Second}

type answer struct {
	status              int
	cache, reason, body string
	contentRange        string
	acceptRanges        string
	headers             http.Header
	err                 error
}

func get(host, path string, headers map[string]string) answer {
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), nil)
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
		body: string(body), contentRange: response.Header.Get("Content-Range"), acceptRanges: response.Header.Get("Accept-Ranges"), headers: response.Header}
}

func (a answer) String() string {
	if a.err != nil {
		return a.err.Error()
	}
	return fmt.Sprintf("%d %s %s %s len=%d", a.status, a.cache, a.reason, a.contentRange, len(a.body))
}

func adminGet(n *node, path string) ([]byte, error) {
	return siteindex.ControlGet(context.Background(), n.control.Socket, path)
}

// ---------------------------------------------------------------- functional

func functional(o *originServer) {
	rules := []edgeconfig.CacheRuleDocument{
		{Order: 1, Extensions: []string{".css"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 2},
		{Order: 2, PathPrefix: "/api/", Action: edgeconfig.CacheRuleActionNoCache},
		{Order: 3, StatusCodes: []int{404}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 60},
	}
	long := []edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".css"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 3600, BrowserTTLSeconds: 600}}
	simple, ruled, longRuled := policy(nil, 64<<20), policy(rules, 64<<20), policy(long, 64<<20)
	sites := []edgesite.Site{
		makeSite(1, "range.d8.test", true, &simple),
		makeSite(2, "norange.d8.test", false, &simple),
		makeSite(3, "rules.d8.test", false, &ruled),
		makeSite(4, "long.d8.test", false, &longRuled),
		makeSite(5, "nocache.d8.test", true, nil),
	}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	n, err := startNode(sites, pool)
	if err != nil {
		check("start", false, "%v", err)
		return
	}
	defer n.stop()

	// fail closed until the agent synced the purge generations
	a := get("range.d8.test", "/before-sync.bin", nil)
	b := get("range.d8.test", "/before-sync.bin", nil)
	check("BEFORE-SYNC-NOT-CACHED", a.cache == "BYPASS" && a.reason == "purge_state" && b.cache == "BYPASS", "%v / %v", a, b)
	if err := n.startCache(); err != nil {
		check("sync", false, "%v", err)
		return
	}

	// plan differential: Lua (cdnca_cache admin /cache/plan) == edgecache.Build
	for _, site := range sites[:4] {
		plan, _ := edgecache.Build(site)
		raw, _ := edgesite.Encode(site)
		signatures := make([]string, 0, len(plan.Routes))
		for signature := range plan.Routes {
			if signature != "" {
				signatures = append(signatures, signature)
			}
		}
		sort.Strings(signatures)
		body, err := adminGet(n, "/cache/plan?digest="+edgesite.Digest(raw)+"&signatures="+strings.Join(signatures, ";"))
		var lua struct {
			Zone   string `json:"zone"`
			Routes map[string]struct {
				Cache    bool   `json:"cache"`
				TTLs     string `json:"ttls"`
				Browsers string `json:"browsers"`
			} `json:"routes"`
		}
		if err == nil {
			err = json.Unmarshal(body, &lua)
		}
		zone, _ := edgecache.ZoneIndex(site.Cache.KeyPrefix, pool.Zones)
		same := err == nil && lua.Zone == edgecache.ZoneName(zone, "") && len(lua.Routes) == len(plan.Routes)
		for signature, route := range plan.Routes {
			got, ok := lua.Routes[signature]
			same = same && ok && got.Cache == route.Cache && got.TTLs == route.TTLs
		}
		check("PLAN-LUA-EQUALS-GO-"+site.Hosts.Primary, same, "go=%v lua=%s err=%v", plan.Routes, body, err)
	}

	// simple cache: MISS then HIT, origin once
	a, b = get("norange.d8.test", "/a.css", nil), get("norange.d8.test", "/a.css", nil)
	check("SIMPLE-MISS-HIT", a.cache == "MISS" && b.cache == "HIT" && o.count("norange.d8.test", "/a.css") == 1, "%v / %v", a, b)
	// Range on a range site: the cached object answers 206 (ge-cache D)
	o.count("range.d8.test", "/v.bin")
	a = get("range.d8.test", "/v.bin?size=1000", map[string]string{"Range": "bytes=10-19"})
	b = get("range.d8.test", "/v.bin?size=1000", map[string]string{"Range": "bytes=100-199"})
	c := get("range.d8.test", "/v.bin?size=1000", nil)
	check("RANGE-FROM-CACHE", a.status == 206 && a.contentRange == "bytes 10-19/1000" && len(a.body) == 10 && a.cache == "MISS" &&
		b.status == 206 && b.cache == "HIT" && b.contentRange == "bytes 100-199/1000" && c.status == 200 && c.cache == "HIT" && len(c.body) == 1000,
		"%v / %v / %v", a, b, c)
	check("RANGE-ORIGIN-ONCE-WHOLE", o.count("range.d8.test", "/v.bin") == 1 && o.lastRange("range.d8.test", "/v.bin") == "",
		"origin %d range %q", o.count("range.d8.test", "/v.bin"), o.lastRange("range.d8.test", "/v.bin"))
	a = get("range.d8.test", "/v.bin?size=1000", map[string]string{"Range": "bytes=0-1,4-5"})
	check("RANGE-MULTI-FROM-CACHE", a.status == 206 && a.cache == "HIT", "%v", a)
	a = get("range.d8.test", "/v.bin?size=1000", map[string]string{"Range": "bytes=5000-6000"})
	check("RANGE-416-FROM-CACHE", a.status == 416 && a.cache == "HIT", "%v", a)
	// range off: a cached request is still cut from the cached object (v7
	// v2Range: proxy_force_ranges on every cached location; the site's Range
	// setting only decides what a bypassed request forwards)
	a = get("norange.d8.test", "/w.bin?size=100", map[string]string{"Range": "bytes=2-5"})
	b = get("norange.d8.test", "/w.bin?size=100", map[string]string{"Range": "bytes=2-5"})
	check("RANGE-OFF-FROM-CACHE", a.status == 206 && len(a.body) == 4 && b.cache == "HIT" && b.status == 206 &&
		o.lastRange("norange.d8.test", "/w.bin") == "", "%v / %v range %q", a, b, o.lastRange("norange.d8.test", "/w.bin"))
	a = get("norange.d8.test", "/wb.bin?size=100", map[string]string{"Range": "bytes=2-5", "Authorization": "Bearer x"})
	// bypassed on a range-off site: the origin gets no Range, the edge cuts
	// the client's range from the full response (v7 proxy_force_ranges)
	check("RANGE-OFF-BYPASS-NOT-FORWARDED", a.status == 206 && len(a.body) == 4 && a.cache == "BYPASS" && o.lastRange("norange.d8.test", "/wb.bin") == "",
		"%v range %q", a, o.lastRange("norange.d8.test", "/wb.bin"))
	// a bypassed request of a range site forwards Range (v7)
	a = get("range.d8.test", "/post-like.bin?size=100", map[string]string{"Range": "bytes=2-5", "Authorization": "Bearer x"})
	check("RANGE-BYPASS-FORWARDED", a.status == 206 && a.cache == "BYPASS" && a.reason == "authorization" &&
		o.lastRange("range.d8.test", "/post-like.bin") == "bytes=2-5", "%v range %q", a, o.lastRange("range.d8.test", "/post-like.bin"))
	// a site without cache: Range forwarded, no cache header
	a = get("nocache.d8.test", "/n.bin?size=100", map[string]string{"Range": "bytes=2-5"})
	check("NOCACHE-RANGE", a.status == 206 && a.cache == "" && o.lastRange("nocache.d8.test", "/n.bin") == "bytes=2-5", "%v", a)

	// request cookies: ignored on a rule-matched request (ge-cache C), bypass without rules
	a = get("rules.d8.test", "/c.css", map[string]string{"Cookie": "track=1"})
	b = get("rules.d8.test", "/c.css", map[string]string{"Cookie": "track=2"})
	check("COOKIE-RULE-MATCHED-CACHED", a.cache == "MISS" && b.cache == "HIT", "%v / %v", a, b)
	a = get("norange.d8.test", "/cookie.css", map[string]string{"Cookie": "track=1"})
	check("COOKIE-NO-RULES-BYPASS", a.cache == "BYPASS" && a.reason == "cookie", "%v", a)
	// rules.d8.test's rule 3 (status only) matches every path (v7 too); long.d8.test has only a .css rule
	a = get("long.d8.test", "/page.html", nil)
	check("NO-RULE-BYPASS", a.cache == "BYPASS" && a.reason == "no_cache_rule", "%v", a)
	a = get("long.d8.test", "/page.html", map[string]string{"Cookie": "track=1"})
	check("NO-RULE-COOKIE-BYPASS", a.cache == "BYPASS" && a.reason == "cookie", "%v", a)
	a, b = get("rules.d8.test", "/api/x.json", nil), get("rules.d8.test", "/api/x.json", nil)
	// rule 2 (no cache) decides every status of /api/: v7 BYPASS no_cache_rule
	check("RULE-NO-CACHE", a.cache == "BYPASS" && a.reason == "no_cache_rule" && b.cache == "BYPASS" && a.acceptRanges == "bytes" &&
		o.count("rules.d8.test", "/api/x.json") == 2, "%v / %v", a, b)
	// only rule 3 (404 cached) names /page.html: the request reads the cache,
	// a 200 is not stored (v7 MISS, not BYPASS)
	a, b = get("rules.d8.test", "/page.html", nil), get("rules.d8.test", "/page.html", nil)
	check("RULE-STATUS-ONLY-MISS", a.cache == "MISS" && b.cache == "MISS" && a.reason == "" && a.acceptRanges == "bytes", "%v / %v", a, b)
	a, b = get("rules.d8.test", "/e404/x.css", nil), get("rules.d8.test", "/e404/x.css", nil)
	check("RULE-STATUS-404-CACHED", a.status == 404 && b.status == 404 && b.cache == "HIT", "%v / %v", a, b)
	a, b = get("norange.d8.test", "/nostore/x.css", nil), get("norange.d8.test", "/nostore/x.css", nil)
	check("NO-STORE-BYPASS", a.cache == "BYPASS" && a.reason == "origin_no_store" && b.cache == "BYPASS", "%v / %v", a, b)
	// v7: every cached site answers Accept-Ranges (proxy_force_ranges), also on a bypass
	a = get("norange.d8.test", "/ar.css", nil)
	b = get("norange.d8.test", "/ar.css", map[string]string{"Authorization": "Bearer x"})
	check("ACCEPT-RANGES-EVERY-CACHED-SITE", a.acceptRanges == "bytes" && b.acceptRanges == "bytes" && b.cache == "BYPASS", "%v %q / %v %q",
		a, a.acceptRanges, b, b.acceptRanges)

	// per-site TTL through patch 24: same path, 2s on rules.d8.test, 1h on long.d8.test
	get("rules.d8.test", "/ttl.css", nil)
	get("long.d8.test", "/ttl.css", nil)
	time.Sleep(3 * time.Second)
	a, b = get("rules.d8.test", "/ttl.css", nil), get("long.d8.test", "/ttl.css", nil)
	// expired: revalidated with the origin's ETag (proxy_cache_revalidate, v7)
	check("TTL-PER-SITE", a.cache == "REVALIDATED" && b.cache == "HIT", "rules(2s) %v / long(1h) %v", a, b)

	// purge generation: immediate, per site
	get("norange.d8.test", "/g.css", nil)
	get("range.d8.test", "/g.css", nil)
	generation, purged, err := n.zones().PurgeSite(context.Background(), n.generations, cacheSite(sites[1]))
	a, b = get("norange.d8.test", "/g.css", nil), get("range.d8.test", "/g.css", nil)
	check("PURGE-SITE-IMMEDIATE-ISOLATED", err == nil && generation == 1 && purged.Affected >= 1 && a.cache == "MISS" && b.cache == "HIT",
		"gen %d %+v err %v / %v / %v", generation, purged, err, a, b)
	// after a restart the node waits for the agent (fail closed), then serves the new generation
	n.stop()
	if err := n.openresty(); err != nil {
		check("restart", false, "%v", err)
		return
	}
	// the D3 cold start rebuilds the index from the current file by itself
	status, _ := n.activator.Control.Status(context.Background())
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if current, err := n.activator.Control.Status(context.Background()); err == nil && current.Generation > 0 {
			status = current
			break
		}
	}
	a = get("norange.d8.test", "/g.css", nil)
	_ = n.startCache()
	b = get("norange.d8.test", "/g.css", nil)
	check("RESTART-FAIL-CLOSED-THEN-HIT", status.Generation > 0 && a.cache == "BYPASS" && a.reason == "purge_state" && b.cache == "HIT",
		"index gen %d; before sync %v / after %v", status.Generation, a, b)

	// prewarm through the shared server
	outcome := n.prewarmer.Prewarm(context.Background(), cacheSite(sites[1]), dyncache.Target{Host: "norange.d8.test", Port: edge, URI: "/warm.css", Path: "/warm.css"}, "http")
	a = get("norange.d8.test", "/warm.css", nil)
	check("PREWARM", outcome.Code == "PREWARMED" && a.cache == "HIT", "%+v / %v", outcome, a)
	outcome = n.prewarmer.Prewarm(context.Background(), cacheSite(sites[1]), dyncache.Target{Host: "rules.d8.test", Port: edge, URI: "/warm.css", Path: "/warm.css"}, "http")
	check("PREWARM-SITE-MISMATCH", outcome.Code == "SITE_MISMATCH", "%+v", outcome)
	// a visitor's forged token gives no key echo
	forged := get("norange.d8.test", "/warm.css", map[string]string{"X-Cdnca-Cache-Task": "00"})
	check("PREWARM-TOKEN-REQUIRED", forged.cache == "HIT", "%v", forged)

	for _, line := range n.errors() {
		if !strings.Contains(line, "connect() failed") {
			fmt.Println("LOG", line)
		}
	}
}

// ---------------------------------------------------------------- ge-cache policy fields

func extensions(o *originServer) {
	stale := policy(nil, 64<<20)
	stale.StaleIfError = true
	background := stale
	background.BackgroundUpdate = true
	sized := policy([]edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".bin"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 60}}, 64<<20)
	sized.MinObjectBytes, sized.MaxObjectBytes = 16, 1000
	sliced := policy(nil, 64<<20)
	sliced.SliceBytes = 320 << 10 // runs in the 256 KiB slice variant
	short := []edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".css"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 1}}
	staleShort, backgroundShort := policy(short, 64<<20), policy(short, 64<<20)
	staleShort.StaleIfError = true
	backgroundShort.StaleIfError, backgroundShort.BackgroundUpdate = true, true
	sites := []edgesite.Site{
		makeSite(11, "stale.d8.test", false, &staleShort),
		makeSite(12, "bg.d8.test", false, &backgroundShort),
		makeSite(13, "size.d8.test", false, &sized),
		makeSite(14, "slice.d8.test", true, &sliced),
		makeSite(15, "plain.d8.test", false, &stale),
		makeSite(16, "bgplain.d8.test", false, &background),
	}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	n, err := startNode(sites, pool)
	if err != nil {
		check("ext-start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("ext-sync", false, "%v", err)
		return
	}
	// plans: Lua == Go for the new fields
	for _, site := range sites {
		plan, _ := edgecache.Build(site)
		raw, _ := edgesite.Encode(site)
		body, err := adminGet(n, "/cache/plan?digest="+edgesite.Digest(raw)+"&signatures=1")
		var lua struct {
			Variant string `json:"variant"`
			Slice   int64  `json:"slice_bytes"`
			Min     int64  `json:"min_object_bytes"`
			Max     int64  `json:"max_object_bytes"`
			Routes  map[string]struct {
				TTLs string `json:"ttls"`
			} `json:"routes"`
		}
		if err == nil {
			err = json.Unmarshal(body, &lua)
		}
		same := err == nil && lua.Variant == plan.Variant() && lua.Slice == plan.SliceBytes &&
			lua.Min == plan.MinObjectBytes && lua.Max == plan.MaxObjectBytes
		for signature, route := range plan.Routes {
			same = same && lua.Routes[signature].TTLs == route.TTLs
		}
		check("EXT-PLAN-LUA-EQUALS-GO-"+site.Hosts.Primary, same, "go variant=%s slice=%d min=%d max=%d routes=%v lua=%s err=%v",
			plan.Variant(), plan.SliceBytes, plan.MinObjectBytes, plan.MaxObjectBytes, plan.Routes, body, err)
	}

	// stale_if_error: an expired object is served while the origin fails
	a := get("stale.d8.test", "/s.css", nil)
	time.Sleep(2200 * time.Millisecond)
	o.failNext.Store(true)
	b := get("stale.d8.test", "/s.css", nil)
	o.failNext.Store(false)
	check("STALE-IF-ERROR", a.cache == "MISS" && b.status == 200 && b.cache == "STALE" && len(b.body) == 64, "%v / %v", a, b)
	// background_update: an expired object is answered at once (STALE/UPDATING), refreshed behind
	get("bg.d8.test", "/slow/u.css", nil)
	time.Sleep(2200 * time.Millisecond)
	start := time.Now()
	c := get("bg.d8.test", "/slow/u.css", nil)
	elapsed := time.Since(start)
	time.Sleep(600 * time.Millisecond)
	d := get("bg.d8.test", "/slow/u.css", nil)
	check("BACKGROUND-UPDATE", c.cache == "STALE" && elapsed < 250*time.Millisecond && d.cache == "HIT" && o.count("bg.d8.test", "/slow/u.css") == 2,
		"%v in %v / %v origin %d", c, elapsed.Round(time.Millisecond), d, o.count("bg.d8.test", "/slow/u.css"))
	// without background update the expired request waits for the origin
	get("stale.d8.test", "/slow/w.css", nil)
	time.Sleep(2200 * time.Millisecond)
	start = time.Now()
	e := get("stale.d8.test", "/slow/w.css", nil)
	waited := time.Since(start)
	// the origin answers 200 with the same ETag: revalidated, after the wait
	check("NO-BACKGROUND-UPDATE-WAITS", (e.cache == "REVALIDATED" || e.cache == "EXPIRED") && waited >= 250*time.Millisecond,
		"%v in %v", e, waited.Round(time.Millisecond))

	// object size bounds: too big / too small are not stored (BYPASS object_size)
	a, b = get("size.d8.test", "/big.bin?size=4000", nil), get("size.d8.test", "/big.bin?size=4000", nil)
	check("MAX-OBJECT-BYTES", a.cache == "BYPASS" && a.reason == "object_size" && b.cache == "BYPASS" && o.count("size.d8.test", "/big.bin") == 2,
		"%v / %v origin %d", a, b, o.count("size.d8.test", "/big.bin"))
	a, b = get("size.d8.test", "/tiny.bin?size=8", nil), get("size.d8.test", "/tiny.bin?size=8", nil)
	check("MIN-OBJECT-BYTES", a.cache == "BYPASS" && a.reason == "object_size" && b.cache == "BYPASS", "%v / %v", a, b)
	a, b = get("size.d8.test", "/ok.bin?size=500", nil), get("size.d8.test", "/ok.bin?size=500", nil)
	check("IN-BOUNDS-CACHED", a.cache == "MISS" && b.cache == "HIT" && a.reason == "", "%v / %v", a, b)

	// slices: the origin is asked one aligned 256 KiB slice at a time
	size := 700 << 10
	path := fmt.Sprintf("/v.bin?size=%d", size)
	a = get("slice.d8.test", path, map[string]string{"Range": "bytes=300000-300009"})
	firstRange := o.lastRange("slice.d8.test", "/v.bin")
	b = get("slice.d8.test", path, map[string]string{"Range": "bytes=300010-300019"})
	check("SLICE-ORIGIN-PER-SLICE", a.status == 206 && len(a.body) == 10 && firstRange == "bytes=262144-524287" && b.status == 206 && b.cache == "HIT" &&
		o.count("slice.d8.test", "/v.bin") == 1, "%v / %v origin %d range %q", a, b, o.count("slice.d8.test", "/v.bin"), firstRange)
	c = get("slice.d8.test", path, nil)
	check("SLICE-WHOLE-OBJECT", c.status == 200 && len(c.body) == size && o.count("slice.d8.test", "/v.bin") == 3 && c.acceptRanges == "bytes",
		"%v origin %d", c, o.count("slice.d8.test", "/v.bin"))
	d = get("slice.d8.test", path, nil)
	check("SLICE-WHOLE-HIT", d.status == 200 && d.cache == "HIT" && len(d.body) == size && o.count("slice.d8.test", "/v.bin") == 3, "%v", d)
	purged, err := n.zones().Purge(context.Background(), dyncache.Site{SiteID: sites[3].SiteID, Prefix: sites[3].Cache.KeyPrefix,
		Token: sites[3].Cache.Generation, Domain: sites[3].Cache.Domain, KeyByHost: true, Names: []string{"slice.d8.test"},
		Ports: map[int]string{edge: "http"}, Sliced: true},
		[]dyncache.Target{{Host: "slice.d8.test", Port: edge, URI: path, Path: "/v.bin"}}, false, n.generations)
	e = get("slice.d8.test", path, map[string]string{"Range": "bytes=0-9"})
	check("SLICE-URL-PURGE-EVERY-SLICE", err == nil && purged.Affected == 3 && e.cache == "MISS", "%+v err %v / %v", purged, err, e)

	for _, line := range n.errors() {
		if !strings.Contains(line, "connect() failed") && !strings.Contains(line, "upstream prematurely") {
			fmt.Println("LOG", line)
		}
	}
}

// ---------------------------------------------------------------- rule match (ge36)

// ruleMatch: cache rules on a path regular expression and on the response
// Content-Type (CACHE_RULE_MATCH), Lua plan == Go plan.
func ruleMatch(o *originServer) {
	cache := func(order int, ttl int64) edgeconfig.CacheRuleDocument {
		return edgeconfig.CacheRuleDocument{Order: order, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: ttl, BrowserTTLSeconds: ttl}
	}
	regex := cache(1, 300)
	regex.PathRegex = `^/v[0-9]+/assets/`
	typed := cache(2, 600)
	typed.ContentTypes = []string{"image/*", "text/css"}
	noHTML := edgeconfig.CacheRuleDocument{Order: 3, Extensions: []string{".html"}, Action: edgeconfig.CacheRuleActionNoCache}
	document := policy([]edgeconfig.CacheRuleDocument{regex, typed, noHTML}, 64<<20)
	sites := []edgesite.Site{makeSite(21, "rx.d8.test", false, &document)}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	n, err := startNode(sites, pool)
	if err != nil {
		check("rm-start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("rm-sync", false, "%v", err)
		return
	}
	plan, _ := edgecache.Build(sites[0])
	signatures := make([]string, 0, len(plan.Routes))
	for signature := range plan.Routes {
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	raw, _ := edgesite.Encode(sites[0])
	body, err := adminGet(n, "/cache/plan?digest="+edgesite.Digest(raw)+"&signatures="+strings.Join(signatures, ";"))
	var lua struct {
		Routes map[string]struct {
			Cache    bool   `json:"cache"`
			MayCache bool   `json:"may_cache"`
			TTLs     string `json:"ttls"`
		} `json:"routes"`
	}
	if err == nil {
		err = json.Unmarshal(body, &lua)
	}
	same := err == nil && len(lua.Routes) == len(plan.Routes)
	for signature, route := range plan.Routes {
		got := lua.Routes[signature]
		same = same && got.TTLs == route.TTLs && got.Cache == route.Cache && got.MayCache == route.MayCache
	}
	check("RULEMATCH-PLAN-LUA-EQUALS-GO", same, "go=%v lua=%s err=%v", plan.Routes, body, err)

	// path_regex: /v2/assets/ cached by rule 1 (300s); /assets/ is not named by it
	a, b := get("rx.d8.test", "/v2/assets/app.js?ct=application/javascript", nil), get("rx.d8.test", "/v2/assets/app.js?ct=application/javascript", nil)
	check("PATH-REGEX-CACHED", a.cache == "MISS" && b.cache == "HIT" && strings.Contains(b.headers.Get("Cache-Control"), "max-age=300"), "%v / %v cc=%q", a, b, b.headers.Get("Cache-Control"))
	// not named by rule 1: only rule 2 (any path) is left, JavaScript drops it
	a, b = get("rx.d8.test", "/v2x/assets/app.js?ct=application/javascript", nil), get("rx.d8.test", "/v2x/assets/app.js?ct=application/javascript", nil)
	check("PATH-REGEX-NO-MATCH", a.cache == "BYPASS" && a.reason == "content_type" && b.cache == "BYPASS" && o.count("rx.d8.test", "/v2x/assets/app.js") == 2,
		"%v / %v origin %d", a, b, o.count("rx.d8.test", "/v2x/assets/app.js"))
	// content_types: an image anywhere cached by rule 2 (600s); JSON not stored
	a, b = get("rx.d8.test", "/img/p.png?ct=image/png", nil), get("rx.d8.test", "/img/p.png?ct=image/png", nil)
	check("CONTENT-TYPE-CACHED", a.cache == "MISS" && b.cache == "HIT" && strings.Contains(b.headers.Get("Cache-Control"), "max-age=600"), "%v / %v cc=%q", a, b, b.headers.Get("Cache-Control"))
	a, b = get("rx.d8.test", "/api/x?ct=application/json", nil), get("rx.d8.test", "/api/x?ct=application/json", nil)
	check("CONTENT-TYPE-NOT-STORED", a.cache == "BYPASS" && a.reason == "content_type" && b.cache == "BYPASS" && o.count("rx.d8.test", "/api/x") == 2,
		"%v / %v origin %d", a, b, o.count("rx.d8.test", "/api/x"))
	a = get("rx.d8.test", "/s.css?ct=text/css%3B%20charset=utf-8", nil)
	check("CONTENT-TYPE-PARAMETERS-IGNORED", a.cache == "MISS", "%v", a)
	// .html no_cache (rule 3) loses to an image rule 2 before it, wins for HTML
	a, b = get("rx.d8.test", "/x.html?ct=image/gif", nil), get("rx.d8.test", "/x.html?ct=image/gif", nil)
	check("CONTENT-TYPE-FIRST-RULE-WINS", a.cache == "MISS" && b.cache == "HIT", "%v / %v", a, b)
	a = get("rx.d8.test", "/y.html?ct=text/html", nil)
	check("CONTENT-TYPE-DROPPED-NO-CACHE", a.cache == "BYPASS" && a.reason == "content_type" && strings.Contains(a.headers.Get("Cache-Control"), "no-cache"),
		"%v cc=%q", a, a.headers.Get("Cache-Control"))
	// a /v2/assets/ HTML: rule 1 (regex) caches it, rule 2 dropped
	a, b = get("rx.d8.test", "/v2/assets/i.html?ct=text/html", nil), get("rx.d8.test", "/v2/assets/i.html?ct=text/html", nil)
	check("REGEX-AND-TYPE-COMBINED", a.cache == "MISS" && b.cache == "HIT", "%v / %v", a, b)
	for _, line := range n.errors() {
		if !strings.Contains(line, "connect() failed") && !strings.Contains(line, "upstream prematurely") {
			fmt.Println("LOG", line)
		}
	}
}

// ---------------------------------------------------------------- per-rule settings

// ruleExtras: edgeconfig.CacheRuleExtras on the real node. The site's
// policy is override (rules exist only there) and keeps the query; each
// rule then sets its own.
func ruleExtras(o *originServer) {
	yes, no, slice := true, false, int64(256<<10)
	cache := func(order int, ttl int64) edgeconfig.CacheRuleDocument {
		return edgeconfig.CacheRuleDocument{Order: order, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: ttl}
	}
	home := cache(1, 300) // 首页: single path "/", ignore the query
	home.PathExact, home.IgnoreQuery = "/", true
	forced := cache(2, 300) // 强制 CDN 缓存 under /maxage5/
	forced.PathPrefix, forced.ForceCache = "/maxage5/", &yes
	honour := cache(6, 300) // 强制 CDN 缓存 off: the origin's max-age=1 wins
	honour.PathPrefix, honour.ForceCache = "/honour/", &no
	vary := cache(3, 300) // 忽略 Vary
	vary.PathPrefix, vary.IgnoreVary = "/vary/", true
	video := cache(4, 300) // 分片回源 for .mp4
	video.Extensions, video.SliceBytes = []string{".mp4"}, &slice
	wordpress := cache(5, 300) // WordPress: 不缓存条件 on the login cookie and wp-admin
	wordpress.PathPrefix = "/"
	wordpress.NoCache = []edgeconfig.CacheNoCacheCondition{
		{Source: edgeconfig.CacheConditionHeader, Name: "cookie", Pattern: "wordpress_logged_in"},
		{Source: edgeconfig.CacheConditionPath, Pattern: "^/wp-admin/"},
	}
	honour.Order, wordpress.Order = 5, 6
	document := policy([]edgeconfig.CacheRuleDocument{home, forced, vary, video, honour, wordpress}, 64<<20)
	sites := []edgesite.Site{makeSite(31, "rx2.d8.test", false, &document)}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	n, err := startNode(sites, pool)
	if err != nil {
		check("rx-start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("rx-sync", false, "%v", err)
		return
	}
	plan, _ := edgecache.Build(sites[0])
	signatures := make([]string, 0, len(plan.Routes))
	for signature := range plan.Routes {
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	raw, _ := edgesite.Encode(sites[0])
	body, err := adminGet(n, "/cache/plan?digest="+edgesite.Digest(raw)+"&signatures="+strings.Join(signatures, ";"))
	var lua struct {
		Routes map[string]struct {
			Cache       bool   `json:"cache"`
			TTLs        string `json:"ttls"`
			Variant     any    `json:"variant"`
			IgnoreQuery bool   `json:"ignore_query"`
			NoCache     int    `json:"no_cache"`
		} `json:"routes"`
	}
	if err == nil {
		err = json.Unmarshal(body, &lua)
	}
	same := err == nil && len(lua.Routes) == len(plan.Routes)
	for signature, route := range plan.Routes {
		got := lua.Routes[signature]
		variant, _ := got.Variant.(string)
		same = same && got.TTLs == route.TTLs && got.Cache == route.Cache && variant == route.Variant &&
			got.IgnoreQuery == route.IgnoreQuery && got.NoCache == len(route.NoCache)
	}
	check("EXTRAS-PLAN-LUA-EQUALS-GO", same, "go=%+v lua=%s err=%v", plan.Routes, body, err)

	// 单个路径 + 忽略 URL 参数: "/" and "/?a=1" are one object; "/index" is not "/"
	a, b := get("rx2.d8.test", "/?utm=1", nil), get("rx2.d8.test", "/?utm=2", nil)
	check("EXACT-PATH-IGNORE-QUERY", a.cache == "MISS" && b.cache == "HIT", "%v / %v", a, b)
	a = get("rx2.d8.test", "/index", nil)
	check("EXACT-PATH-ONLY", a.cache == "MISS" && o.count("rx2.d8.test", "/index") == 1, "%v", a)
	// the site keeps the query elsewhere: /q?x=1 and /q?x=2 are two objects
	a, b = get("rx2.d8.test", "/q?x=1", nil), get("rx2.d8.test", "/q?x=2", nil)
	check("SITE-QUERY-KEPT", a.cache == "MISS" && b.cache == "MISS", "%v / %v", a, b)
	// 强制 CDN 缓存: the origin's max-age=1 is overridden by the rule (300s)
	get("rx2.d8.test", "/maxage5/a", nil)
	time.Sleep(2500 * time.Millisecond)
	a = get("rx2.d8.test", "/maxage5/a", nil)
	check("FORCE-CACHE-OVERRIDES-ORIGIN", a.cache == "HIT" && o.count("rx2.d8.test", "/maxage5/a") == 1, "%v origin %d", a, o.count("rx2.d8.test", "/maxage5/a"))
	// (max-age=1 is whole seconds: wait past it; the ETag revalidates)
	get("rx2.d8.test", "/honour/maxage5/a", nil)
	time.Sleep(2500 * time.Millisecond)
	a = get("rx2.d8.test", "/honour/maxage5/a", nil)
	check("NO-FORCE-HONOURS-ORIGIN", (a.cache == "EXPIRED" || a.cache == "REVALIDATED") && o.count("rx2.d8.test", "/honour/maxage5/a") == 2,
		"%v origin %d", a, o.count("rx2.d8.test", "/honour/maxage5/a"))
	// 忽略 Vary: two devices share the first device's object
	a, b = get("rx2.d8.test", "/vary/p", map[string]string{"X-Device": "phone"}), get("rx2.d8.test", "/vary/p", map[string]string{"X-Device": "desktop"})
	check("IGNORE-VARY", a.cache == "MISS" && b.cache == "HIT" && b.body == "device=phone", "%v %q / %v %q", a, a.body, b, b.body)
	// 分片回源: the origin is asked for 256 KiB slices
	a = get("rx2.d8.test", "/v/clip.mp4?size=600000", nil)
	ranges := o.lastRange("rx2.d8.test", "/v/clip.mp4")
	check("RULE-SLICE", a.status == 200 && len(a.body) == 600000 && strings.HasPrefix(ranges, "bytes=") && o.count("rx2.d8.test", "/v/clip.mp4") == 3,
		"%v last range %q origin %d", a, ranges, o.count("rx2.d8.test", "/v/clip.mp4"))
	// a non-video under the same site is not sliced
	get("rx2.d8.test", "/big.bin?size=600000", nil)
	check("SITE-NOT-SLICED", o.lastRange("rx2.d8.test", "/big.bin") == "" && o.count("rx2.d8.test", "/big.bin") == 1, "range %q", o.lastRange("rx2.d8.test", "/big.bin"))
	// 不缓存条件: the logged-in cookie and /wp-admin/ bypass, others cache
	a, b = get("rx2.d8.test", "/post/1", nil), get("rx2.d8.test", "/post/1", map[string]string{"Cookie": "wordpress_logged_in_abc=1"})
	check("NO-CACHE-COOKIE", a.cache == "MISS" && b.cache == "BYPASS" && b.reason == "no_cache_condition" && o.count("rx2.d8.test", "/post/1") == 2,
		"%v / %v origin %d", a, b, o.count("rx2.d8.test", "/post/1"))
	a, b = get("rx2.d8.test", "/wp-admin/x", nil), get("rx2.d8.test", "/wp-admin/x", nil)
	check("NO-CACHE-PATH", a.cache == "BYPASS" && a.reason == "no_cache_condition" && b.cache == "BYPASS" && o.count("rx2.d8.test", "/wp-admin/x") == 2, "%v / %v", a, b)
	// an anonymous visitor still gets the cached copy
	a = get("rx2.d8.test", "/post/1", nil)
	check("NO-CACHE-ANONYMOUS-HIT", a.cache == "HIT", "%v", a)
	for _, line := range n.errors() {
		if !strings.Contains(line, "connect() failed") && !strings.Contains(line, "upstream prematurely") {
			fmt.Println("LOG", line)
		}
	}
}

// ---------------------------------------------------------------- follow redirects (ge36)

// noRedirects: the edge's own answer, never the client's following.
var noRedirects = &http.Client{Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func getRaw(method, host, path string) answer {
	request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), nil)
	request.Host = host
	response, err := noRedirects.Do(request)
	if err != nil {
		return answer{err: err}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return answer{status: response.StatusCode, cache: response.Header.Get("X-CDN-Cache"), reason: response.Header.Get("X-CDN-Cache-Reason"),
		body: string(body), headers: response.Header}
}

// followRedirects: origin redirect following (ORIGIN_FOLLOW_REDIRECT) on a
// cached site, a site without cache and a site with an error page and a
// conditional origin route with a fallback pool: the three error_page users
// of the shared server (site error pages are the header filter's, the
// conditional fallback the balancer's) keep working next to it.
func followRedirects(o *originServer) {
	cached := policy([]edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".css"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 60}}, 64<<20)
	plain := makeSite(31, "fr.d8.test", false, &cached)
	plain.Origin.FollowRedirect = &edgesite.FollowRedirect{MaxHops: 2}
	nocache := makeSite(32, "frn.d8.test", false, nil)
	nocache.Origin.FollowRedirect = &edgesite.FollowRedirect{MaxHops: 3, CrossOrigin: true}
	off := makeSite(33, "fro.d8.test", false, &cached)
	// the error page + conditional origin fallback site: 404 has a page,
	// /down/ goes to a dead pool with the working one as fallback
	page := []byte("<h1>site 404 page</h1>")
	pageDigest := edgesite.Digest(page)
	pages := makeSite(34, "frp.d8.test", false, &cached)
	pages.Origin.FollowRedirect = &edgesite.FollowRedirect{MaxHops: 3}
	pages.Errors, _ = edgesite.ErrorPagesFor([]edgesite.ErrorPageRule{{ID: "p404", Category: "origin_response", Codes: []int{404},
		MIMEType: "text/html", Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset, ID: "0d8a0000-0000-4000-8000-0000000004a4", Revision: 1, SHA256: pageDigest}}}, nil)
	dead := pages.Origin.Pools[0]
	dead.ID = "dead"
	dead.Endpoints = []edgesite.Endpoint{{ID: "d", Scheme: "http", Host: "127.0.0.1", Port: 19899, Weight: 1}}
	pages.Origin.Pools = []edgesite.Pool{dead, pages.Origin.Pools[0]}
	pages.Origin.Routes = []edgesite.Route{{ID: "down", Priority: 10, PathPrefix: "/down", PoolID: "dead", FallbackPoolID: "primary"}}
	sites := []edgesite.Site{plain, nocache, off, pages}
	for _, site := range sites {
		if err := edgesite.Validate(site); err != nil {
			check("follow-site-"+site.Hosts.Primary, false, "%v", err)
			return
		}
	}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	n, err := startNodeWith(sites, pool, map[string][]byte{pageDigest: page})
	if err != nil {
		check("follow-start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("follow-sync", false, "%v", err)
		return
	}

	// cached site: the final response is served and stored under the original URL
	a := getRaw("GET", "fr.d8.test", "/r/302/a.css")
	b := getRaw("GET", "fr.d8.test", "/r/302/a.css")
	check("FOLLOW-302-CACHED", a.status == 200 && a.cache == "MISS" && a.headers.Get("X-Origin-Redirect") == "" && len(a.body) == 64 &&
		b.status == 200 && b.cache == "HIT" && o.count("fr.d8.test", "/r/302/a.css") == 1 && o.count("fr.d8.test", "/final/a.css") == 1,
		"%v / %v origin r=%d final=%d", a, b, o.count("fr.d8.test", "/r/302/a.css"), o.count("fr.d8.test", "/final/a.css"))
	for _, code := range []int{301, 303, 307, 308} {
		path := fmt.Sprintf("/r/%d/c%d.txt", code, code)
		a = getRaw("GET", "fr.d8.test", path)
		check(fmt.Sprintf("FOLLOW-%d", code), a.status == 200 && len(a.body) == 64, "%v", a)
	}
	// absolute Location naming the site's own host is the same origin
	a = getRaw("GET", "fr.d8.test", "/r/302/abs?to=http://fr.d8.test/final/abs")
	check("FOLLOW-ABSOLUTE-SAME-HOST", a.status == 200 && o.count("fr.d8.test", "/final/abs") == 1, "%v", a)
	// the pool's origin address is the same origin too
	a = getRaw("GET", "fr.d8.test", "/r/302/org?to=http://127.0.0.1:19801/final/org")
	check("FOLLOW-ORIGIN-ADDRESS", a.status == 200 && o.count("fr.d8.test", "/final/org") == 1, "%v", a)
	// another host without cross_origin: the redirect goes to the visitor, never stored
	a = getRaw("GET", "fr.d8.test", "/r/302/x.css?to=http://other.example/x")
	b = getRaw("GET", "fr.d8.test", "/r/302/x.css?to=http://other.example/x")
	check("FOLLOW-CROSS-ORIGIN-REFUSED", a.status == 302 && a.headers.Get("Location") == "http://other.example/x" &&
		strings.Contains(a.headers.Get("Cache-Control"), "no-store") && b.status == 302 && o.count("fr.d8.test", "/r/302/x.css") == 2,
		"%v loc=%q cc=%q / %v origin %d", a, a.headers.Get("Location"), a.headers.Get("Cache-Control"), b, o.count("fr.d8.test", "/r/302/x.css"))
	// hops: max 2 -> a chain of 3 redirects returns the third
	a = getRaw("GET", "fr.d8.test", "/r/302/h1?to=/r/302/h2%3Fto%3D/r/302/h3")
	check("FOLLOW-MAX-HOPS", a.status == 302 && strings.HasSuffix(a.headers.Get("Location"), "/final/h3"), "%v loc=%q", a, a.headers.Get("Location"))
	// a redirect loop ends at max hops
	a = getRaw("GET", "fr.d8.test", "/r/301/loop")
	check("FOLLOW-LOOP-BOUNDED", a.status == 301 && o.count("fr.d8.test", "/r/301/loop") == 3, "%v origin %d", a, o.count("fr.d8.test", "/r/301/loop"))
	// POST is never followed
	a = getRaw("POST", "fr.d8.test", "/r/302/p")
	check("FOLLOW-POST-NOT-FOLLOWED", a.status == 302 && o.count("fr.d8.test", "/final/p") == 0, "%v", a)
	// HEAD is followed
	a = getRaw("HEAD", "fr.d8.test", "/r/302/hd")
	check("FOLLOW-HEAD", a.status == 200 && o.count("fr.d8.test", "/final/hd") == 1, "%v", a)

	// a site without cache: followed, and cross_origin goes to the pool with that Host
	a = getRaw("GET", "frn.d8.test", "/r/307/n")
	check("FOLLOW-NO-CACHE-SITE", a.status == 200 && a.cache == "" && o.count("frn.d8.test", "/final/n") == 1, "%v", a)
	a = getRaw("GET", "frn.d8.test", "/r/302/c?to=http://elsewhere.d8.test/final/c")
	check("FOLLOW-CROSS-ORIGIN-ALLOWED", a.status == 200 && o.count("elsewhere.d8.test", "/final/c") == 1, "%v origin %d", a, o.count("elsewhere.d8.test", "/final/c"))

	// following off: the origin's redirect reaches the visitor unchanged
	a = getRaw("GET", "fro.d8.test", "/r/302/o.css")
	check("FOLLOW-OFF", a.status == 302 && a.headers.Get("X-Origin-Redirect") == "1" && o.count("fro.d8.test", "/final/o.css") == 0, "%v", a)

	// coexistence: site error page after a followed redirect, conditional
	// origin fallback, both with following on
	a = getRaw("GET", "frp.d8.test", "/r/302/missing?to=/e404/missing")
	check("FOLLOW-THEN-ERROR-PAGE", a.status == 404 && strings.Contains(a.body, "site 404 page"), "%v", a)
	a = getRaw("GET", "frp.d8.test", "/e404/direct")
	check("ERROR-PAGE-WITH-FOLLOW-ON", a.status == 404 && strings.Contains(a.body, "site 404 page"), "%v", a)
	a = getRaw("GET", "frp.d8.test", "/down/x.css")
	b = getRaw("GET", "frp.d8.test", "/down/x.css")
	check("CONDITIONAL-FALLBACK-WITH-FOLLOW-ON", a.status == 200 && a.cache == "MISS" && b.cache == "HIT", "%v / %v", a, b)
	a = getRaw("GET", "frp.d8.test", "/down/r/302/y.css")
	check("CONDITIONAL-FALLBACK-THEN-FOLLOW", a.status == 200 && o.count("frp.d8.test", "/final/y.css") == 1, "%v", a)
	for _, line := range n.errors() {
		if !strings.Contains(line, "connect() failed") && !strings.Contains(line, "upstream prematurely") && !strings.Contains(line, "no live origin") {
			fmt.Println("LOG", line)
		}
	}
}

// ---------------------------------------------------------------- scale

func scaleRun(o *originServer) {
	count := *scale
	sites := make([]edgesite.Site, 0, count)
	document := policy(nil, 1<<30)
	small := policy(nil, 64<<20) // the soft quota victim
	for index := range count {
		d := &document
		if index == 0 {
			d = &small
		}
		sites = append(sites, makeSite(1000+index, fmt.Sprintf("s%05d.scale.d8.test", index), false, d))
	}
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 8 << 30})
	started := time.Now()
	n, err := startNode(sites, pool)
	if err != nil {
		check("scale-start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("scale-sync", false, "%v", err)
		return
	}
	fmt.Printf("INFO scale: %d sites, pool %d zones x %d MiB (keys %d MiB), started+activated in %v\n",
		count, pool.Zones, pool.MaxBytes>>20, pool.KeysZoneBytes>>20, time.Since(started).Round(time.Millisecond))

	// Zipf workload over (site, object): 32 objects per site
	random := rand.New(rand.NewSource(1))
	zipf := rand.NewZipf(random, 1.1, 1, uint64(count*32-1))
	var hits, misses, other atomic.Int64
	work := make(chan uint64, 1024)
	var wait sync.WaitGroup
	latencies := make([][]float64, 32)
	for worker := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for item := range work {
				site, object := int(item/32), int(item%32)
				t0 := time.Now()
				a := get(fmt.Sprintf("s%05d.scale.d8.test", site), fmt.Sprintf("/o%d.css?size=2048", object), nil)
				latencies[worker] = append(latencies[worker], float64(time.Since(t0).Microseconds()))
				switch a.cache {
				case "HIT":
					hits.Add(1)
				case "MISS":
					misses.Add(1)
				default:
					other.Add(1)
				}
			}
		}()
	}
	originBefore := o.total.Load()
	t0 := time.Now()
	for range *requests {
		work <- zipf.Uint64()
	}
	close(work)
	wait.Wait()
	elapsed := time.Since(t0)
	var all []float64
	for _, values := range latencies {
		all = append(all, values...)
	}
	sort.Float64s(all)
	p := func(q float64) float64 { return all[int(math.Min(float64(len(all)-1), q*float64(len(all))))] }
	hitRate := float64(hits.Load()) / float64(*requests)
	distinct := misses.Load()
	fmt.Printf("INFO workload: %d requests in %v (%.0f req/s), HIT %d MISS %d other %d, origin %d, p50 %.0fµs p99 %.0fµs\n",
		*requests, elapsed.Round(time.Millisecond), float64(*requests)/elapsed.Seconds(), hits.Load(), misses.Load(), other.Load(),
		o.total.Load()-originBefore, p(0.5), p(0.99))
	// every MISS is the first request of a distinct object: the ideal hit rate
	ideal := 1 - float64(distinct)/float64(*requests)
	check("SCALE-HIT-RATE", other.Load() == 0 && o.total.Load()-originBefore == misses.Load() && hitRate > 0.5 && math.Abs(hitRate-ideal) < 1e-9,
		"hit rate %.4f (every miss is a first access: %d distinct objects; origin %d)", hitRate, distinct, o.total.Load()-originBefore)

	// purge isolation on the shared pool: A and B share a zone, same paths
	zones := n.zones()
	var a, b edgesite.Site
	byZone := map[int][]edgesite.Site{}
	for _, site := range sites[1:] {
		zone, _ := edgecache.ZoneIndex(site.Cache.KeyPrefix, pool.Zones)
		byZone[zone] = append(byZone[zone], site)
		if len(byZone[zone]) == 2 {
			a, b = byZone[zone][0], byZone[zone][1]
			break
		}
	}
	for _, site := range []edgesite.Site{a, b} {
		for _, path := range []string{"/p/1.css", "/p/2.css", "/q.css"} {
			get(site.Hosts.Primary, path, nil)
		}
	}
	usage := func(site edgesite.Site) int {
		objects := 0
		_ = zones.Walk(context.Background(), site.Cache.KeyPrefix, func(dyncache.Entry) error {
			objects++
			return nil
		})
		return objects
	}
	beforeB := usage(b)
	target, _ := dyncache.ParseTarget(cacheSite(a), "http://"+a.Hosts.Primary+":"+strconv.Itoa(edge)+"/q.css", false)
	exact, err1 := zones.Purge(context.Background(), cacheSite(a), []dyncache.Target{target}, false, n.generations)
	prefixTarget, _ := dyncache.ParseTarget(cacheSite(a), "http://"+a.Hosts.Primary+":"+strconv.Itoa(edge)+"/p/", true)
	prefix, err2 := zones.Purge(context.Background(), cacheSite(a), []dyncache.Target{prefixTarget}, true, nil)
	aq, ap := get(a.Hosts.Primary, "/q.css", nil), get(a.Hosts.Primary, "/p/1.css", nil)
	bq, bp := get(b.Hosts.Primary, "/q.css", nil), get(b.Hosts.Primary, "/p/1.css", nil)
	check("SCALE-PURGE-ISOLATION", err1 == nil && err2 == nil && exact.Affected == 1 && prefix.Affected == 2 &&
		aq.cache == "MISS" && ap.cache == "MISS" && bq.cache == "HIT" && bp.cache == "HIT" && usage(b) == beforeB,
		"A(%s) exact %+v prefix %+v -> %v %v; B(%s, same zone) %v %v objects %d->%d", a.Hosts.Primary, exact, prefix, aq, ap, b.Hosts.Primary, bq, bp, beforeB, usage(b))
	t1 := time.Now()
	_, whole, err := zones.PurgeSite(context.Background(), n.generations, cacheSite(a))
	purgeTime := time.Since(t1)
	aq, bq = get(a.Hosts.Primary, "/o1.css?size=2048", nil), get(b.Hosts.Primary, "/q.css", nil)
	check("SCALE-PURGE-SITE-ISOLATION", err == nil && aq.cache == "MISS" && bq.cache == "HIT", "A whole site %+v in %v; A %v B %v",
		whole, purgeTime.Round(time.Millisecond), aq, bq)

	// soft quota: site 0 (64 MiB) gets 80 MiB, every other site keeps its objects
	victim := sites[0]
	before, _ := zones.UsageBySite(context.Background())
	for index := range 80 {
		get(victim.Hosts.Primary, fmt.Sprintf("/big/%d.bin?size=%d", index, 1<<20), nil)
	}
	over, _ := zones.UsageBySite(context.Background())
	quotaSites := map[string]dyncache.Site{}
	for _, site := range sites {
		quotaSites[site.Cache.KeyPrefix] = cacheSite(site)
	}
	t2 := time.Now()
	cleaned, err := zones.CleanQuota(context.Background(), quotaSites, 0.9)
	cleanTime := time.Since(t2)
	after, _ := zones.UsageBySite(context.Background())
	othersKept := true
	for prefix, value := range before {
		if prefix == victim.Cache.KeyPrefix || prefix == a.Cache.KeyPrefix {
			continue
		}
		if after[prefix] == nil || after[prefix].Bytes != value.Bytes {
			othersKept = false
		}
	}
	victimOver := over[victim.Cache.KeyPrefix]
	victimAfter := after[victim.Cache.KeyPrefix]
	check("SCALE-SOFT-QUOTA", err == nil && cleaned.Sites == 1 && victimOver != nil && victimOver.Bytes > victim.Cache.Policy.DiskQuotaBytes &&
		victimAfter != nil && victimAfter.Bytes <= victim.Cache.Policy.DiskQuotaBytes*9/10 && othersKept,
		"victim %d -> %d bytes (quota %d), removed %d objects in %v over %d sites, others unchanged %v",
		victimOver.Bytes, victimAfter.Bytes, victim.Cache.Policy.DiskQuotaBytes, cleaned.Removed, cleanTime.Round(time.Millisecond), len(before), othersKept)
	newest := get(victim.Hosts.Primary, "/big/79.bin?size=1048576", nil)
	oldest := get(victim.Hosts.Primary, "/big/0.bin?size=1048576", nil)
	check("SCALE-SOFT-QUOTA-LRU", newest.cache == "HIT" && oldest.cache == "MISS", "newest %v oldest %v", newest, oldest)
	for _, line := range n.errors() {
		fmt.Println("LOG", line)
	}
}

func main() {
	flag.Parse()
	parts := map[string]bool{}
	for _, part := range strings.Split(*only, ",") {
		if part != "" {
			parts[part] = true
		}
	}
	o := &originServer{counts: map[string]int{}, ranges: map[string][]string{}}
	listener, err := net.Listen("tcp", origin)
	if err != nil {
		panic(err)
	}
	go func() { _ = http.Serve(listener, o) }()
	if len(parts) == 0 || parts["functional"] {
		fmt.Println("== functional")
		functional(o)
	}
	if len(parts) == 0 || parts["extensions"] {
		fmt.Println("== extensions")
		extensions(o)
	}
	if len(parts) == 0 || parts["rulematch"] {
		fmt.Println("== rulematch")
		ruleMatch(o)
	}
	if len(parts) == 0 || parts["ruleextras"] {
		fmt.Println("== ruleextras")
		ruleExtras(o)
	}
	if len(parts) == 0 || parts["follow"] {
		fmt.Println("== follow")
		followRedirects(o)
	}
	if len(parts) == 0 || parts["statusheader"] {
		fmt.Println("== statusheader")
		statusHeader(o)
	}
	if *scale > 0 && (len(parts) == 0 || parts["scale"]) {
		fmt.Println("== scale")
		scaleRun(o)
	}
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- statusheader

// statusHeader: 响应头显示缓存状态. The control
// plane compiles cache_status_header (the site's switch, off at attack
// escalation B and above); the node answers X-CDN-Cache/X-CDN-Cache-Reason
// only when it is on, the agent's prewarm always gets them, and an
// origin's own headers of those names never reach the client.
func statusHeader(o *originServer) {
	simple := policy(nil, 64<<20)
	on := makeSite(31, "shon.d8.test", false, &simple)
	off := makeSite(32, "shoff.d8.test", false, &simple)
	off.CacheStatusHeader = false
	pool, _ := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	n, err := startNode([]edgesite.Site{on, off}, pool)
	if err != nil {
		check("start", false, "%v", err)
		return
	}
	defer n.stop()
	if err := n.startCache(); err != nil {
		check("sync", false, "%v", err)
		return
	}
	absent := func(a answer) bool {
		return a.err == nil && len(a.headers.Values("X-CDN-Cache")) == 0 && len(a.headers.Values("X-CDN-Cache-Reason")) == 0
	}

	a, b := get("shon.d8.test", "/a.css", nil), get("shon.d8.test", "/a.css", nil)
	bypass := get("shon.d8.test", "/a.css", map[string]string{"Authorization": "Bearer x"})
	check("cache-status-header-on", a.cache == "MISS" && b.cache == "HIT" && bypass.cache == "BYPASS" && bypass.reason == "authorization",
		"%v / %v / %v", a, b, bypass)

	a, b = get("shoff.d8.test", "/a.css", nil), get("shoff.d8.test", "/a.css", nil)
	bypass = get("shoff.d8.test", "/a.css", map[string]string{"Authorization": "Bearer x"})
	// hidden, still cached: the origin is asked once
	check("cache-status-header-off", a.status == 200 && absent(a) && absent(b) && absent(bypass) && o.count("shoff.d8.test", "/a.css") == 2,
		"%v / %v / %v origin %d", a, b, bypass, o.count("shoff.d8.test", "/a.css"))

	// forged by the origin: removed on and off (MISS, then a cached HIT
	// whose stored headers carry them)
	f1, f2 := get("shon.d8.test", "/forge/x.css", nil), get("shon.d8.test", "/forge/x.css", nil)
	g1, g2 := get("shoff.d8.test", "/forge/x.css", nil), get("shoff.d8.test", "/forge/x.css", nil)
	single := func(a answer, want string) bool {
		return len(a.headers.Values("X-CDN-Cache")) == 1 && a.cache == want && a.reason == ""
	}
	check("cache-status-header-origin-forged", single(f1, "MISS") && single(f2, "HIT") && absent(g1) && absent(g2),
		"on %v %v / off %v %v", f1.headers, f2.headers, g1.headers, g2.headers)

	// attack escalation: the same site published again with the switch
	// compiled off hides both headers at once, back on after the next one
	escalated := on
	escalated.Revision, escalated.CacheStatusHeader = 2, false
	if err := n.reactivate([]edgesite.Site{escalated, off}); err != nil {
		check("cache-status-header-escalated", false, "publish B: %v", err)
		return
	}
	hidden := get("shon.d8.test", "/a.css", nil)
	restored := on
	restored.Revision = 3
	if err := n.reactivate([]edgesite.Site{restored, off}); err != nil {
		check("cache-status-header-escalated", false, "publish A: %v", err)
		return
	}
	shown := get("shon.d8.test", "/a.css", nil)
	check("cache-status-header-escalated", hidden.status == 200 && absent(hidden) && shown.cache == "HIT", "B %v / A %v", hidden, shown)

	// the agent's prewarm reads X-CDN-Cache on a site with the switch off
	outcome := n.prewarmer.Prewarm(context.Background(), cacheSite(off), dyncache.Target{Host: "shoff.d8.test", Port: edge, URI: "/warm.css", Path: "/warm.css"}, "http")
	again := n.prewarmer.Prewarm(context.Background(), cacheSite(off), dyncache.Target{Host: "shoff.d8.test", Port: edge, URI: "/warm.css", Path: "/warm.css"}, "http")
	visitor := get("shoff.d8.test", "/warm.css", nil)
	forged := get("shoff.d8.test", "/warm.css", map[string]string{"X-Cdnca-Cache-Task": "00"})
	check("cache-status-header-prewarm", outcome.Code == "PREWARMED" && again.Code == "ALREADY_CACHED" && absent(visitor) && absent(forged),
		"%+v / %+v / visitor %v / forged token %v", outcome, again, visitor, forged)
}
