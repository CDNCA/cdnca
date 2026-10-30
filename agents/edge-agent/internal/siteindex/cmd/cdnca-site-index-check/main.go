// Command cdnca-site-index-check is the dynamic routing D3 acceptance run
// against a real OpenResty (tests/dynroute-index/run.sh starts it inside the
// node runtime image, one --rm --network none container): site selection by
// Host (exact, alias, wildcard, longest wildcard, case, port), not ready
// 503, unknown 421, generation switches under load without a failed
// request, rollback, cold start rebuild, and the scale measurements (index
// size, build time, lookup p50/p99, cold rebuild time).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

var (
	luaRoot   = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	confPath  = flag.String("conf", "/d3/nginx.conf", "skeleton template")
	stateRoot = flag.String("state", "/tmp/d3state", "state directory")
	workers   = flag.Int("workers", 2, "worker_processes")
	scale     = flag.Int("scale", 0, "sites for the scale measurement (0 = skip)")
	only      = flag.String("only", "", "comma-separated checks")
)

const (
	scope  = "0d3a0000-0000-4000-8000-000000000001"
	tenant = "0d3a0000-0000-4000-8000-000000000002"
	portA  = 18080
	portB  = 18081
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

func siteID(number int) string { return fmt.Sprintf("0d3a0000-0000-4000-8000-%012d", number) }

func makeSite(number int, revision int64, primary string, aliases []string, maxBody int64, ports ...int) edgesite.Site {
	listeners := make([]edgesite.Listener, 0, len(ports))
	for _, port := range ports {
		listeners = append(listeners, edgesite.Listener{Port: port, AddressFamily: edgesite.FamilyIPv4})
	}
	if aliases == nil {
		aliases = []string{}
	}
	sort.Strings(aliases)
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID(number), Revision: revision,
		Hosts: edgesite.Hosts{Primary: primary, Aliases: aliases}, Listeners: listeners,
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "origin-0", Scheme: "http", Host: "192.0.2.1", Port: 80, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 10}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
		Limits:   edgesite.Limits{MaxBodyBytes: maxBody},
	}
}

func encode(site edgesite.Site) siteindex.Object {
	raw, err := edgesite.Encode(site)
	if err != nil {
		panic(err)
	}
	object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
	if err != nil {
		panic(err)
	}
	return object
}

type node struct {
	prefix    string
	activator *siteindex.Activator
	control   *siteindex.Control
}

func render(indexSize string, lru int) error {
	template, err := os.ReadFile(*confPath)
	if err != nil {
		return err
	}
	conf := strings.NewReplacer("__WORKERS__", strconv.Itoa(*workers), "__LUA_ROOT__", *luaRoot,
		"__STATE__", *stateRoot, "__INDEX_SIZE__", indexSize, "__LRU_ITEMS__", strconv.Itoa(lru)).Replace(string(template))
	return os.WriteFile(filepath.Join(*stateRoot, "nginx", "nginx.conf"), []byte(conf), 0o644)
}

func openresty(args ...string) error {
	command := exec.Command("openresty", append([]string{"-p", filepath.Join(*stateRoot, "nginx") + "/", "-c", "nginx.conf"}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

func newNode(indexSize string, lru int) (*node, error) {
	_ = os.RemoveAll(*stateRoot)
	for _, dir := range []string{"nginx/logs", "run", "site-index", "site-objects"} {
		if err := os.MkdirAll(filepath.Join(*stateRoot, dir), 0o755); err != nil {
			return nil, err
		}
	}
	if err := render(indexSize, lru); err != nil {
		return nil, err
	}
	if err := openresty(); err != nil {
		return nil, err
	}
	control := siteindex.NewControl(filepath.Join(*stateRoot, "run", "cdnca-site-admin.sock"))
	n := &node{prefix: *stateRoot, control: control, activator: &siteindex.Activator{
		Control: control,
		Files:   siteindex.Files{Root: filepath.Join(*stateRoot, "site-index"), Access: siteindex.Access{GID: workerGID()}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*stateRoot, "site-objects"), Access: siteindex.Access{GID: workerGID()}},
	}}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := control.Status(context.Background()); err == nil {
			return n, nil
		} else if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// workerGID is the group of the OpenResty workers (nginx's compiled default
// user nobody), as the agent sets it on a node.
func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func (n *node) stop() { _ = openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

type reply struct {
	status            int
	site, matched     string
	generation        string
	maxBody, body     string
	same, tenant, err string
}

var client = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256, DisableCompression: true}, Timeout: 10 * time.Second}

func get(port int, host, path string) reply {
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	request.Host = host
	response, err := client.Do(request)
	if err != nil {
		return reply{err: err.Error()}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return reply{status: response.StatusCode, site: response.Header.Get("X-Cdnca-Site"), matched: response.Header.Get("X-Cdnca-Matched"),
		generation: response.Header.Get("X-Cdnca-Generation"), maxBody: response.Header.Get("X-Cdnca-Max-Body"),
		same: response.Header.Get("X-Cdnca-Same"), tenant: response.Header.Get("X-Cdnca-Tenant"), body: strings.TrimSpace(string(body))}
}

func post(port int, host, path string, size int) int {
	request, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), strings.NewReader(strings.Repeat("x", size)))
	request.Host = host
	response, err := client.Do(request)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode
}

// rawGet sends a hand-written request line + headers (Host forms net/http
// will not produce).
func rawGet(port int, head string) int {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "%s\r\nConnection: close\r\n\r\n", head)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	status, _ := strconv.Atoi(fields[1])
	return status
}

func routingSites() []siteindex.Object {
	return []siteindex.Object{
		encode(makeSite(101, 1, "shop.example.test", []string{"www.shop.example.test", "*.shop.example.test"}, 0, portA, portB)),
		encode(makeSite(102, 1, "api.shop.example.test", []string{"*.eu.shop.example.test", "blog.example.test"}, 2048, portA)),
		encode(makeSite(103, 1, "other.example.test", nil, 0, portB)),
	}
}

func checkRouting(n *node) {
	ctx := context.Background()
	sites := routingSites()
	// Before the first activation every port is not ready.
	r := get(portA, "shop.example.test", "/")
	check("not-ready-before-activation", r.status == 503, "status %d", r.status)
	activation, err := n.activator.Activate(ctx, sites)
	check("activate", err == nil && activation.Generation >= 1, "gen %d rebuilt=%v err=%v", activation.Generation, activation.Rebuilt, err)
	if err != nil {
		return
	}
	shop, api, other := sites[0].Site.SiteID, sites[1].Site.SiteID, sites[2].Site.SiteID
	for _, c := range []struct {
		name, host    string
		port          int
		site, matched string
		status        int
		maxBody       string
	}{
		{"primary", "shop.example.test", portA, shop, "shop.example.test", 200, "1048576"},
		{"alias", "www.shop.example.test", portA, shop, "www.shop.example.test", 200, "1048576"},
		{"wildcard-one-level", "img.shop.example.test", portA, shop, "*.shop.example.test", 200, ""},
		{"wildcard-two-levels", "a.b.shop.example.test", portA, shop, "*.shop.example.test", 200, ""},
		{"exact-beats-wildcard", "api.shop.example.test", portA, api, "api.shop.example.test", 200, "2048"},
		{"longest-wildcard", "x.eu.shop.example.test", portA, api, "*.eu.shop.example.test", 200, ""},
		{"longest-wildcard-deeper", "y.x.eu.shop.example.test", portA, api, "*.eu.shop.example.test", 200, ""},
		{"wildcard-not-bare", "eu.shop.example.test", portA, shop, "*.shop.example.test", 200, ""},
		{"case-insensitive", "WWW.Shop.Example.TEST", portA, shop, "www.shop.example.test", 200, ""},
		{"host-with-port", "shop.example.test:18080", portA, shop, "shop.example.test", 200, ""},
		{"trailing-dot", "shop.example.test.", portA, shop, "shop.example.test", 200, ""},
		{"second-alias-other-site", "blog.example.test", portA, api, "blog.example.test", 200, ""},
		{"port-b-shop", "shop.example.test", portB, shop, "shop.example.test", 200, ""},
		{"port-b-other", "other.example.test", portB, other, "other.example.test", 200, ""},
		{"api-not-on-port-b", "api.shop.example.test", portB, shop, "*.shop.example.test", 200, ""},
		{"other-not-on-port-a", "other.example.test", portA, "", "", 421, ""},
		{"unknown-host", "nope.example.test", portA, "", "", 421, ""},
		{"ip-host", "127.0.0.1", portA, "", "", 421, ""},
		{"bare-parent-of-wildcard", "example.test", portA, "", "", 421, ""},
	} {
		r := get(c.port, c.host, "/")
		ok := r.status == c.status && r.site == c.site && r.matched == c.matched && (c.maxBody == "" || r.maxBody == c.maxBody)
		if c.status == 200 {
			ok = ok && r.same == "true" && r.tenant == tenant
		}
		check("route-"+c.name, ok, "port %d host %s -> %d site=%s matched=%s max_body=%s same=%s", c.port, c.host, r.status, r.site, r.matched, r.maxBody, r.same)
	}
	check("route-no-host-http10", rawGet(portA, "GET / HTTP/1.0") == 421, "HTTP/1.0 without Host")
	check("route-ipv6-literal-host", rawGet(portA, "GET / HTTP/1.1\r\nHost: [::1]") == 421, "Host [::1]")
	r = get(portA, "nope.example.test", "/.well-known/cdnca-market-probe")
	check("node-location-for-unknown", r.status == 204, "status %d", r.status)
	r = get(portA, "shop.example.test", "/.well-known/cdnca-market-probe")
	check("site-beats-node-location", r.status == 200 && r.body == "site:"+shop, "status %d body %q", r.status, r.body)
	r = get(portA, "www.shop.example.test", "/__exec")
	check("selection-survives-exec", r.status == 200 && r.site == shop && r.body == "shop.example.test", "status %d site %s body %q", r.status, r.site, r.body)
	check("upload-site-limit-ok", post(portA, "api.shop.example.test", "/__upload", 2048) == 200, "2048 bytes")
	check("upload-site-limit-413", post(portA, "api.shop.example.test", "/__upload", 2049) == 413, "2049 bytes")
	check("upload-system-limit", post(portA, "shop.example.test", "/__upload", 4096) == 200, "4096 bytes under the system limit")
	probe, err := n.control.Probe(ctx, portA, "img.shop.example.test")
	check("probe", err == nil && probe.State == "ok" && probe.Digest == sites[0].Digest.String(), "%+v %v", probe, err)
	health, err := n.activator.WaitHealthy(ctx, activation.Generation, siteindex.ProbesFor(sites), 3*time.Second)
	check("health", err == nil && health.Healthy, "%v %v", health.Reasons, err)

	// A missing site object is not ready, never another site.
	digest := sites[2].Digest.String()
	_ = os.Remove(n.activator.Objects.Path(digest))
	n.restart() // drop the worker LRU
	r = get(portB, "other.example.test", "/")
	check("missing-object-not-ready", r.status == 503, "status %d", r.status)
	_ = n.activator.Objects.Put(digest, sites[2].Raw)
}

func (n *node) restart() {
	_ = openresty("-s", "reload")
	time.Sleep(700 * time.Millisecond)
}

// checkSwitch: generation switches (changes and a new port) while a load
// generator hits every site; no request may fail or see a site that is
// in neither generation.
func checkSwitch(n *node) {
	ctx := context.Background()
	const count = 400
	build := func(revision int64, renamed bool) []siteindex.Object {
		objects := make([]siteindex.Object, 0, count)
		for i := range count {
			name := fmt.Sprintf("s%d.switch.test", i)
			aliases := []string{fmt.Sprintf("alias%d.switch.test", i)}
			if renamed && i%2 == 0 {
				aliases = append(aliases, fmt.Sprintf("extra%d.switch.test", i))
			}
			objects = append(objects, encode(makeSite(1000+i, revision, name, aliases, 0, portA)))
		}
		return objects
	}
	generations := [][]siteindex.Object{build(1, false), build(2, true), build(3, false), build(4, true)}
	if _, err := n.activator.Activate(ctx, generations[0]); err != nil {
		check("switch-initial", false, "%v", err)
		return
	}
	var stop atomic.Bool
	var total, failed atomic.Int64
	var mu sync.Mutex
	var bad []string
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := worker; !stop.Load(); i += 16 {
				id := i % count
				host := fmt.Sprintf("s%d.switch.test", id)
				if i%3 == 0 {
					host = fmt.Sprintf("alias%d.switch.test", id)
				}
				r := get(portA, host, "/")
				total.Add(1)
				if r.status != 200 || r.site != siteID(1000+id) || r.same != "true" {
					failed.Add(1)
					mu.Lock()
					if len(bad) < 5 {
						bad = append(bad, fmt.Sprintf("%s -> %d %s %s %s", host, r.status, r.site, r.same, r.err))
					}
					mu.Unlock()
				}
			}
		}()
	}
	switches := 0
	started := time.Now()
	var maxSwitch time.Duration
	for round := range 40 {
		objects := generations[(round+1)%len(generations)]
		t0 := time.Now()
		activation, err := n.activator.Activate(ctx, objects)
		if err != nil {
			check("switch-activate", false, "round %d: %v", round, err)
			break
		}
		maxSwitch = max(maxSwitch, time.Since(t0))
		if activation.Rebuilt {
			check("switch-no-rebuild", false, "round %d rebuilt", round)
		}
		switches++
		if round%10 == 9 {
			// a rollback in the middle of the load
			if _, err := n.activator.Rollback(ctx); err != nil {
				check("switch-rollback", false, "round %d: %v", round, err)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	checkRetention("switch", n)
	check("switch-zero-failures", failed.Load() == 0 && total.Load() > 1000,
		"%d switches (incl. 4 rollbacks) in %s, max activation %s, %d requests, %d failed %v",
		switches, time.Since(started).Round(time.Millisecond), maxSwitch.Round(time.Microsecond), total.Load(), failed.Load(), bad)
	// "extra" aliases exist exactly in generations 2 and 4.
	status, _ := n.control.Status(ctx)
	r := get(portA, "extra0.switch.test", "/")
	check("switch-final-state", r.status == 200 || r.status == 421, "gen %d extra0 -> %d", status.Generation, r.status)
}

// checkRetention: the object directory holds exactly the objects of the
// index files kept (current and previous generation).
func checkRetention(name string, n *node) {
	want := map[string]bool{}
	entries, _ := os.ReadDir(n.activator.Files.Root)
	files := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".idx") {
			continue
		}
		generation, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "gen-"), ".idx"), 10, 64)
		index, err := n.activator.Files.Read(generation)
		if err != nil {
			check(name+"-retention", false, "%s: %v", entry.Name(), err)
			return
		}
		files++
		for _, digest := range index.Digests() {
			want[digest] = true
		}
	}
	have, _ := n.activator.Objects.List()
	extra, missing := 0, 0
	for _, digest := range have {
		if !want[digest] {
			extra++
		}
		delete(want, digest)
	}
	missing = len(want)
	check(name+"-retention", files <= 2 && extra == 0 && missing == 0, "%d index files, %d objects, %d extra, %d missing", files, len(have), extra, missing)
}

func checkRollback(n *node) {
	ctx := context.Background()
	v1 := []siteindex.Object{encode(makeSite(201, 1, "a.rollback.test", nil, 0, portA)), encode(makeSite(202, 1, "b.rollback.test", nil, 0, portA))}
	v2 := []siteindex.Object{encode(makeSite(201, 2, "a.rollback.test", []string{"new.rollback.test"}, 0, portA)), encode(makeSite(203, 1, "c.rollback.test", nil, 0, portA, portB))}
	first, err := n.activator.Activate(ctx, v1)
	if err != nil {
		check("rollback-setup", false, "%v", err)
		return
	}
	second, err := n.activator.Activate(ctx, v2)
	if err != nil {
		check("rollback-setup", false, "%v", err)
		return
	}
	c := get(portB, "c.rollback.test", "/")
	b := get(portA, "b.rollback.test", "/")
	check("rollback-new-active", c.status == 200 && b.status == 421 && get(portA, "new.rollback.test", "/").status == 200,
		"gen %d: c on new port %d, removed b %d", second.Generation, c.status, b.status)
	back, err := n.activator.Rollback(ctx)
	check("rollback-single-step", err == nil && back == first.Generation, "back to %d (want %d) %v", back, first.Generation, err)
	a := get(portA, "a.rollback.test", "/")
	b = get(portA, "b.rollback.test", "/")
	newAlias := get(portA, "new.rollback.test", "/")
	cB := get(portB, "c.rollback.test", "/")
	check("rollback-restored", a.status == 200 && a.generation == strconv.FormatUint(first.Generation, 10) && b.status == 200 && newAlias.status == 421 && cB.status == 503,
		"a %d gen %s, b %d, new alias %d, c on port B (not in the old generation) %d", a.status, a.generation, b.status, newAlias.status, cB.status)
	_, err = n.activator.Rollback(ctx)
	check("rollback-only-one-step", errors.Is(err, siteindex.ErrConflict), "%v", err)
	// Forward rollback to the generation before, after a convergence.
	third, err := n.activator.Activate(ctx, v2)
	if err != nil {
		check("rollback-forward-setup", false, "%v", err)
		return
	}
	forward, err := n.activator.RollbackTo(ctx, first.Generation)
	_ = third
	checkRetention("rollback", n)
	check("rollback-forward", err == nil && get(portA, "b.rollback.test", "/").status == 200 && get(portA, "new.rollback.test", "/").status == 421,
		"gen %d (%d changes) %v", forward.Generation, forward.Changes, err)
}

func checkColdStart(n *node) {
	ctx := context.Background()
	sites := routingSites()
	activation, err := n.activator.Activate(ctx, sites)
	if err != nil {
		check("cold-setup", false, "%v", err)
		return
	}
	// A new shared dictionary size is a new zone: reload resets it.
	if err := render("33m", 10000); err != nil {
		check("cold-render", false, "%v", err)
		return
	}
	n.restart()
	deadline := time.Now().Add(10 * time.Second)
	var status siteindex.Status
	for time.Now().Before(deadline) {
		status, _ = n.control.Status(ctx)
		if status.Generation == activation.Generation {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	r := get(portA, "img.shop.example.test", "/")
	check("cold-start-rebuild", status.Generation == activation.Generation && r.status == 200 && r.site == sites[0].Site.SiteID,
		"gen %d (want %d) rebuild %+v, request %d", status.Generation, activation.Generation, status.Rebuild, r.status)
	// A corrupt index file: rebuild fails, ports stay not ready (503).
	file := filepath.Join(n.activator.Files.Root, fmt.Sprintf("gen-%d.idx", activation.Generation))
	raw, _ := os.ReadFile(file)
	raw[len(raw)-40] ^= 0xff
	_ = os.Chmod(file, 0o644)
	_ = os.WriteFile(file, raw, 0o644)
	_ = n.control.Rebuild(ctx)
	time.Sleep(500 * time.Millisecond)
	status, _ = n.control.Status(ctx)
	r = get(portA, "shop.example.test", "/")
	check("cold-corrupt-not-ready", status.Generation == 0 && status.Rebuild != nil && status.Rebuild.Error != "" && r.status == 503,
		"gen %d rebuild error %q, request %d", status.Generation, func() string {
			if status.Rebuild == nil {
				return ""
			}
			return status.Rebuild.Error
		}(), r.status)
	// The agent recovers by activating again (full rebuild from a new file).
	activation, err = n.activator.Activate(ctx, sites)
	r = get(portA, "shop.example.test", "/")
	check("cold-recover", err == nil && activation.Rebuilt && r.status == 200, "rebuilt=%v %v request %d", activation.Rebuilt, err, r.status)
	// The same size reload keeps the index (no rebuild, no 503 window).
	before, _ := n.control.Status(ctx)
	n.restart()
	after, _ := n.control.Status(ctx)
	check("reload-keeps-index", after.Generation == before.Generation && get(portA, "shop.example.test", "/").status == 200,
		"gen %d -> %d", before.Generation, after.Generation)
}

func checkNoMemory(n *node) {
	ctx := context.Background()
	// A 1m index dictionary holds a few thousand keys; ask for more.
	if err := render("1m", 10000); err != nil {
		return
	}
	n.restart()
	small := []siteindex.Object{encode(makeSite(301, 1, "small.nomem.test", nil, 0, portA))}
	if _, err := n.activator.Activate(ctx, small); err != nil {
		check("nomem-setup", false, "%v", err)
		return
	}
	big := append([]siteindex.Object(nil), small...)
	for i := range 12000 {
		big = append(big, encode(makeSite(10000+i, 1, fmt.Sprintf("n%d.nomem.test", i), nil, 0, portA)))
	}
	_, err := n.activator.Activate(ctx, big)
	r := get(portA, "small.nomem.test", "/")
	missing := get(portA, "n1.nomem.test", "/")
	check("nomem-refused-keeps-generation", errors.Is(err, siteindex.ErrNoMemory) && r.status == 200 && missing.status == 421,
		"err=%v, old site %d, new site %d", err, r.status, missing.status)
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(float64(len(sorted))*p))]
}

func checkScale(count int) {
	ctx := context.Background()
	indexSize := fmt.Sprintf("%dm", max(16, count*128*125/100/(1<<20)+16))
	n, err := newNode(indexSize, 10000)
	if err != nil {
		check("scale-start", false, "%v", err)
		return
	}
	defer n.stop()
	var memory runtime.MemStats
	t0 := time.Now()
	objects := make([]siteindex.Object, 0, count)
	encodedBytes := 0
	for i := range count {
		object := encode(makeSite(1_000_000+i, 1, fmt.Sprintf("s%d.scale.test", i), nil, 0, portA))
		encodedBytes += len(object.Raw)
		objects = append(objects, object)
	}
	generateTime := time.Since(t0)
	t1 := time.Now()
	index, err := siteindex.Build(1, objects)
	buildTime := time.Since(t1)
	if err != nil {
		check("scale-build", false, "%v", err)
		return
	}
	t2 := time.Now()
	raw, _ := siteindex.MarshalIndex(index)
	marshalTime := time.Since(t2)
	runtime.ReadMemStats(&memory)
	fmt.Printf("SCALE sites=%d keys=%d generate=%s build=%s marshal=%s index_file_bytes=%d site_objects_bytes=%d go_heap=%dMiB\n",
		count, len(index.Entries), generateTime.Round(time.Millisecond), buildTime.Round(time.Millisecond), marshalTime.Round(time.Millisecond),
		len(raw), encodedBytes, memory.HeapAlloc>>20)
	t4 := time.Now()
	activation, err := n.activator.Activate(ctx, objects)
	activateTime := time.Since(t4)
	status, _ := n.control.Status(ctx)
	rebuildSeconds := 0.0
	if status.Rebuild != nil {
		rebuildSeconds = status.Rebuild.Finished - status.Rebuild.Started
	}
	used := status.Capacity - status.Free
	fmt.Printf("SCALE first_activation(objects written + index file + rebuild)=%s (rebuild in nginx %.3fs) dict=%s used=%dMiB bytes_per_key=%.1f\n",
		activateTime.Round(time.Millisecond), rebuildSeconds, indexSize, used>>20, float64(used)/float64(len(index.Entries)))
	check("scale-activate", err == nil && activation.Generation == 1, "%v", err)

	// Lookup cost in the worker: hits (first lookup reads and decodes the
	// object; LRU 10000 items, so hits beyond it reload: measure both).
	bench := func(query string) map[string]float64 {
		response, err := siteindex.ControlGet(ctx, filepath.Join(n.prefix, "run", "cdnca-site-admin.sock"), "/__bench?"+query)
		if err != nil {
			return map[string]float64{"error": 1}
		}
		var result map[string]float64
		_ = json.Unmarshal(response, &result)
		return result
	}
	hot := bench(fmt.Sprintf("n=200000&count=5000&port=%d&prefix=s%%d.scale.test", portA))
	hot = bench(fmt.Sprintf("n=200000&count=5000&port=%d&prefix=s%%d.scale.test", portA))
	cold := bench(fmt.Sprintf("n=20000&count=%d&port=%d&prefix=s%%d.scale.test", count, portA))
	miss := bench(fmt.Sprintf("n=200000&count=%d&port=%d&miss=1", count, portA))
	fmt.Printf("SCALE lookup hit(lru) p50=%.2fus p99=%.2fus | hit(object read) p50=%.2fus p99=%.2fus | miss(+3 wildcard probes) p50=%.2fus p99=%.2fus\n",
		hot["p50_us"], hot["p99_us"], cold["p50_us"], cold["p99_us"], miss["p50_us"], miss["p99_us"])
	check("scale-lookup-found", hot["found"] == hot["n"] && cold["found"] == cold["n"] && miss["found"] == 0, "hot %v cold %v miss %v", hot["found"], cold["found"], miss["found"])

	// End to end requests at p50/p99 (one keepalive client, sequential).
	var latencies []float64
	for i := range 5000 {
		host := fmt.Sprintf("s%d.scale.test", (i*7919)%count)
		t := time.Now()
		r := get(portA, host, "/")
		latencies = append(latencies, float64(time.Since(t).Microseconds()))
		if r.status != 200 {
			check("scale-request", false, "%s -> %d", host, r.status)
			break
		}
	}
	sort.Float64s(latencies)
	fmt.Printf("SCALE request(end to end, 1 client) p50=%.0fus p99=%.0fus\n", percentile(latencies, 0.5), percentile(latencies, 0.99))

	// Cold start: a new zone (size change) rebuilt by the worker timer,
	// while a client measures how long requests are 503 and the stall.
	newSize := fmt.Sprintf("%dm", max(16, count*128*125/100/(1<<20)+17))
	_ = render(newSize, 10000)
	var probeStop atomic.Bool
	var notReady, ok, other atomic.Int64
	var maxLatency atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !probeStop.Load() {
			t := time.Now()
			r := get(portA, "s1.scale.test", "/")
			elapsed := time.Since(t).Microseconds()
			if elapsed > maxLatency.Load() {
				maxLatency.Store(elapsed)
			}
			switch r.status {
			case 503:
				notReady.Add(1)
			case 200:
				ok.Add(1)
			default:
				other.Add(1)
			}
		}
	}()
	t5 := time.Now()
	n.restart()
	var rebuilt siteindex.Status
	for time.Since(t5) < 5*time.Minute {
		rebuilt, _ = n.control.Status(ctx)
		if rebuilt.Generation == 1 && rebuilt.Rebuild != nil && rebuilt.Rebuild.Finished > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	wall := time.Since(t5)
	time.Sleep(200 * time.Millisecond)
	probeStop.Store(true)
	<-done
	seconds := 0.0
	if rebuilt.Rebuild != nil {
		seconds = rebuilt.Rebuild.Finished - rebuilt.Rebuild.Started
	}
	fmt.Printf("SCALE cold_rebuild keys=%d in_nginx=%.3fs wall_after_reload=%s requests: 503=%d 200=%d other=%d max_latency=%dms\n",
		len(index.Entries), seconds, wall.Round(time.Millisecond), notReady.Load(), ok.Load(), other.Load(), maxLatency.Load()/1000)
	check("scale-cold-rebuild", rebuilt.Generation == 1 && other.Load() == 0, "gen %d other statuses %d", rebuilt.Generation, other.Load())

	// One small change on top of the big index: change set latency.
	changed := append([]siteindex.Object(nil), objects...)
	for i := range 100 {
		changed[i] = encode(makeSite(1_000_000+i, 2, fmt.Sprintf("s%d.scale.test", i), []string{fmt.Sprintf("n%d.scale.test", i)}, 0, portA))
	}
	t6 := time.Now()
	small, err := n.activator.Activate(ctx, changed)
	fmt.Printf("SCALE incremental 100 sites (+100 keys, 100 changed digests): %s (build %s, index file %s, node stage+commit %s, cleanup %s), change sets %d, changes %d, rebuilt=%v\n",
		time.Since(t6).Round(time.Millisecond), small.Phases["build"].Round(time.Millisecond), small.Phases["file"].Round(time.Millisecond),
		small.Phases["node"].Round(time.Millisecond), small.Phases["cleanup"].Round(time.Millisecond), small.ChangeSets, small.Changes, small.Rebuilt)
	check("scale-incremental", err == nil && !small.Rebuilt && get(portA, "n5.scale.test", "/").status == 200, "%v", err)
}

func main() {
	flag.Parse()
	selected := map[string]bool{}
	for _, name := range strings.Split(*only, ",") {
		if name != "" {
			selected[name] = true
		}
	}
	run := func(name string, fn func(*node)) {
		if len(selected) > 0 && !selected[name] {
			return
		}
		n, err := newNode("32m", 10000)
		if err != nil {
			check(name+"-start", false, "%v", err)
			return
		}
		defer n.stop()
		fmt.Printf("== %s\n", name)
		fn(n)
		if logs, err := os.ReadFile(filepath.Join(n.prefix, "nginx", "logs", "error.log")); err == nil {
			for _, line := range strings.Split(string(logs), "\n") {
				if strings.Contains(line, "[error]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[alert]") || strings.Contains(line, "[emerg]") {
					if !strings.Contains(line, "index rebuild failed") && !strings.Contains(line, "too large body") {
						fmt.Println("LOG", line)
					}
				}
			}
		}
	}
	run("routing", checkRouting)
	run("rollback", checkRollback)
	run("switch", checkSwitch)
	run("cold", checkColdStart)
	run("nomem", checkNoMemory)
	if *scale > 0 && (len(selected) == 0 || selected["scale"]) {
		fmt.Println("== scale")
		checkScale(*scale)
	}
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}
