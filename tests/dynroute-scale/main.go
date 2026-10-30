// Command cdnca-dynroute-scale is the D13-d dynamic routing scale benchmark
// (tests/dynroute-scale/run.sh): the agent runtime (internal/dynroute.Runtime,
// as the daemon drives it) over N sites on a real OpenResty, one --rm
// --network none container. It reports, per N:
//   - cold start: first Apply of all sites (skeleton + start + full rebuild);
//   - memory: agent (Go heap, RSS) and OpenResty (master/worker RSS, PSS),
//     the index dictionary's capacity and use;
//   - requests: per request p50/p99 (one keepalive client, random sites: the
//     first request of a site reads its object; then warm), and 16 clients;
//   - incremental: 1 site edited, 100 sites edited, 1 site added, 1 removed
//     (Apply duration, phases, reloads, time until the change is served);
//   - reload: a site on a new port (the skeleton changes);
//   - agent restart (Recover over a running OpenResty) and node restart
//     (OpenResty stopped: started and rebuilt from the index file).
//
// The source lives in tests/ and is compiled into the edge-agent module with
// go build -overlay (run.sh), so no product directory carries it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

var (
	luaRoot   = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	stateRoot = flag.String("state", "/tmp/d13d", "state root")
	workers   = flag.Int("workers", 2, "worker_processes")
	binary    = flag.String("openresty", "/usr/local/openresty/bin/openresty", "OpenResty binary")
	sitesFlag = flag.Int("sites", 10000, "sites")
	requests  = flag.Int("requests", 20000, "sequential requests per pass")
	cachePM   = flag.Int("cache-permille", 100, "sites with a cache policy (per mille)")
)

const (
	scope      = "0d13d000-0000-4000-8000-000000000001"
	tenant     = "0d13d000-0000-4000-8000-000000000002"
	portPlain  = 18380
	portExtra  = 18381
	originPort = 19813
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

// result lines: "RESULT <key> <value>" (collected into the results md)
func result(key string, format string, args ...any) {
	fmt.Printf("RESULT %s %s\n", key, fmt.Sprintf(format, args...))
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000) }

// ---------------------------------------------------------------- sites

func siteID(number int) string { return fmt.Sprintf("0d13d000-0000-4000-8000-%012d", number) }
func host(number int) string   { return fmt.Sprintf("s%d.d13d.test", number) }

func makeSite(number int, revision int64, port int) edgesite.Site {
	site := edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID(number), Revision: revision,
		Hosts:     edgesite.Hosts{Primary: host(number), Aliases: []string{"www." + host(number)}},
		Listeners: []edgesite.Listener{{Port: port, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: originPort, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 30000, TotalBudgetMS: 40000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
		Limits:   edgesite.Limits{MaxBodyBytes: 64 << 20},
	}
	if number%1000 < *cachePM {
		document := edgeconfig.CachePolicyDocument{Revision: 1, Mode: edgeconfig.CacheOverride, Rules: []edgeconfig.CacheRuleDocument{},
			QueryMode: edgeconfig.CacheQueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: 64 << 20}
		cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(tenant, site.SiteID), Domain: site.Hosts.Primary, KeyByHost: true, Policy: document}
		cache.Generation, _ = edgesite.CacheGeneration(*cache)
		site.Cache = cache
	}
	return site
}

var store *objectstore.Store

// encode makes the site's object and puts it in the object store, as the
// gateway client does before handing the release to the runtime.
func encode(site edgesite.Site) siteindex.Object {
	raw, err := edgesite.Encode(site)
	if err != nil {
		panic(fmt.Sprintf("site %s: %v", site.Hosts.Primary, err))
	}
	digest := edgesite.Digest(raw)
	if err := store.Put(digest, raw); err != nil {
		panic(err)
	}
	object, err := siteindex.DecodeObject(digest, raw)
	if err != nil {
		panic(err)
	}
	return object
}

// ---------------------------------------------------------------- measures

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func masterPID() int {
	raw, _ := os.ReadFile(filepath.Join(*stateRoot, "shared", "nginx.pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return pid
}

func children(pid int) []int {
	raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	var pids []int
	for _, field := range strings.Fields(string(raw)) {
		child, _ := strconv.Atoi(field)
		pids = append(pids, child)
	}
	return pids
}

// rollup reads Rss and Pss (KiB) of pid.
func rollup(pid int) (rss, pss int64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/smaps_rollup", pid))
	if err != nil {
		return -1, -1
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "Rss:":
			rss = value
		case "Pss:":
			pss = value
		}
	}
	return rss, pss
}

func cmdline(pid int) string {
	raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
}

func mib(kib int64) string { return fmt.Sprintf("%.1fMiB", float64(kib)/1024) }

func memory(label string, control *siteindex.Control) {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	selfRSS, _ := rollup(os.Getpid())
	result(label+".agent", "rss=%s heap_inuse=%.1fMiB heap_sys=%.1fMiB", mib(selfRSS), float64(stats.HeapInuse)/(1<<20), float64(stats.HeapSys)/(1<<20))
	master := masterPID()
	mrss, mpss := rollup(master)
	totalPSS := mpss
	var workerRSS, workerPSS []string
	for _, child := range children(master) {
		rss, pss := rollup(child)
		totalPSS += pss
		if strings.Contains(cmdline(child), "worker process") {
			workerRSS, workerPSS = append(workerRSS, mib(rss)), append(workerPSS, mib(pss))
		}
	}
	result(label+".openresty", "master_rss=%s master_pss=%s worker_rss=%v worker_pss=%v total_pss=%s", mib(mrss), mib(mpss), workerRSS, workerPSS, mib(totalPSS))
	if status, err := control.Status(context.Background()); err == nil {
		result(label+".index_dict", "capacity=%.0fMiB used=%.2fMiB", float64(status.Capacity)/(1<<20), float64(status.Capacity-status.Free)/(1<<20))
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(float64(len(sorted))*p))]
}

func newClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64, DisableCompression: true}}
}

func get(client *http.Client, port int, name, path string) (int, string, error) {
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	request.Host = name
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body), nil
}

// pass is count sequential requests on one keepalive client to random sites
// (sites picked from order); it returns p50/p99 and the status counts.
func pass(label string, order []int, count, clients int) {
	statuses := map[int]int{}
	var mu sync.Mutex
	var latencies []time.Duration
	var wg sync.WaitGroup
	started := time.Now()
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			client := newClient()
			random := rand.New(rand.NewSource(int64(c + 1)))
			local := make([]time.Duration, 0, count/clients)
			localStatus := map[int]int{}
			for i := 0; i < count/clients; i++ {
				number := order[random.Intn(len(order))]
				begin := time.Now()
				status, _, err := get(client, portPlain, host(number), "/p")
				local = append(local, time.Since(begin))
				if err != nil {
					status = 0
				}
				localStatus[status]++
			}
			mu.Lock()
			latencies = append(latencies, local...)
			for k, v := range localStatus {
				statuses[k] += v
			}
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	elapsed := time.Since(started)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	result("request."+label, "clients=%d n=%d p50=%dus p99=%dus max=%dus rps=%.0f statuses=%v", clients, len(latencies),
		percentile(latencies, 0.5).Microseconds(), percentile(latencies, 0.99).Microseconds(), latencies[len(latencies)-1].Microseconds(),
		float64(len(latencies))/elapsed.Seconds(), statuses)
	check("request-"+label+"-200", statuses[200] == len(latencies), "%v", statuses)
}

// coldFirst requests each of count random sites once (each one's first
// request: object read + digest check + LRU fill).
func coldFirst(order []int, count int) {
	client := newClient()
	random := rand.New(rand.NewSource(42))
	picked := random.Perm(len(order))[:min(count, len(order))]
	latencies := make([]time.Duration, 0, len(picked))
	bad := 0
	for _, index := range picked {
		begin := time.Now()
		status, _, err := get(client, portPlain, host(order[index]), "/first")
		latencies = append(latencies, time.Since(begin))
		if err != nil || status != 200 {
			bad++
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	result("request.first_per_site", "n=%d p50=%dus p99=%dus max=%dus non200=%d", len(latencies),
		percentile(latencies, 0.5).Microseconds(), percentile(latencies, 0.99).Microseconds(), latencies[len(latencies)-1].Microseconds(), bad)
	check("request-first-200", bad == 0, "non-200 %d", bad)
}

// ---------------------------------------------------------------- run

type bench struct {
	ctx     context.Context
	config  dynroute.Config
	runtime *dynroute.Runtime
	input   dynroute.Input
	byNum   map[int]siteindex.Object
	reloads int
}

func (b *bench) objects() []siteindex.Object {
	numbers := make([]int, 0, len(b.byNum))
	for number := range b.byNum {
		numbers = append(numbers, number)
	}
	sort.Ints(numbers)
	objects := make([]siteindex.Object, 0, len(numbers))
	for _, number := range numbers {
		objects = append(objects, b.byNum[number])
	}
	return objects
}

func (b *bench) apply(label string) (dynroute.Result, time.Duration) {
	b.input.Objects = b.objects()
	begin := time.Now()
	applied, err := b.runtime.Apply(b.ctx, b.input)
	took := time.Since(begin)
	if applied.Reloaded {
		b.reloads++
	}
	phases := []string{}
	for _, name := range []string{"build", "file", "node", "cleanup"} {
		if d, ok := applied.Activation.Phases[name]; ok {
			phases = append(phases, name+"="+ms(d))
		}
	}
	result("apply."+label, "sites=%d took=%s activation=%s changes=%d sets=%d rebuilt=%v reloaded=%v started=%v phases=[%s]",
		len(b.input.Objects), ms(took), ms(applied.Activation.Duration), applied.Activation.Changes, applied.Activation.ChangeSets,
		applied.Activation.Rebuilt, applied.Reloaded, applied.Started, strings.Join(phases, " "))
	check("apply-"+label, err == nil, "%v", err)
	return applied, took
}

// served polls until host answers want on port and returns how long after
// the call began (the change already active when Apply returned: ~0).
func served(port int, name string, want int) (time.Duration, int) {
	client := newClient()
	begin := time.Now()
	status := 0
	for deadline := begin.Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		status, _, _ = get(client, port, name, "/v")
		if status == want {
			break
		}
	}
	return time.Since(begin), status
}

func main() {
	flag.Parse()
	ctx := context.Background()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", originPort))
	if err != nil {
		fmt.Println("FAIL origin", err)
		os.Exit(1)
	}
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.Copy(io.Discard, request.Body)
			writer.Header().Set("Cache-Control", "no-store")
			fmt.Fprintf(writer, "origin %s %s", request.Host, request.URL.Path)
		}))
	}()
	_ = os.RemoveAll(*stateRoot)
	// the state root itself 0755: workers traverse it (MkdirAll of node alone would make it 0750 root:root)
	if err := os.MkdirAll(*stateRoot, 0o755); err != nil {
		fmt.Println("FAIL state", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join(*stateRoot, "node"), 0o750); err != nil {
		fmt.Println("FAIL state", err)
		os.Exit(1)
	}
	objectsRoot := filepath.Join(*stateRoot, "node", "objects")
	if store, err = objectstore.OpenShared(objectsRoot, max(workerGID(), 0)); err != nil {
		fmt.Println("FAIL object store", err)
		os.Exit(1)
	}
	config := dynroute.Config{StateRoot: filepath.Join(*stateRoot, "node"), SharedRoot: filepath.Join(*stateRoot, "shared"), ObjectsRoot: objectsRoot,
		LuaRoot: *luaRoot, OpenResty: *binary, WorkerGID: workerGID(), CacheMaxBytes: 512 << 20, Workers: *workers, HealthTimeout: 120 * time.Second}
	rt, err := dynroute.New(config)
	if err != nil {
		fmt.Println("FAIL runtime", err)
		os.Exit(1)
	}
	b := &bench{ctx: ctx, config: config, runtime: rt, byNum: map[int]siteindex.Object{},
		input: dynroute.Input{ScopeVersions: map[string]string{scope: "0d13d000-0000-4000-8000-0000000000a1"}}}
	n := *sitesFlag
	result("config", "sites=%d workers=%d cache_permille=%d requests=%d gomaxprocs=%d", n, *workers, *cachePM, *requests, runtime.GOMAXPROCS(0))

	// -------------------------------------------------------- objects
	begin := time.Now()
	order := make([]int, 0, n)
	for number := 1; number <= n; number++ {
		b.byNum[number] = encode(makeSite(number, 1, portPlain))
		order = append(order, number)
	}
	var bytes int64
	for _, object := range b.byNum {
		bytes += int64(len(object.Raw))
	}
	result("objects", "sites=%d encode_and_store=%s avg_object=%dB total=%.1fMiB", n, ms(time.Since(begin)), bytes/int64(n), float64(bytes)/(1<<20))

	// -------------------------------------------------------- cold start
	cold, coldTook := b.apply("cold_start")
	check("cold-start-shape", cold.Started && cold.Activation.Rebuilt, "started %v rebuilt %v", cold.Started, cold.Activation.Rebuilt)
	result("cold_start", "total=%s", ms(coldTook))
	control := siteindex.NewControl(filepath.Join(config.StateRoot, edgeskeleton.ControlSocket))
	if status, statusErr := control.Status(ctx); statusErr == nil && status.Rebuild != nil {
		result("cold_start.rebuild", "entries=%d nginx_rebuild=%.0fms", status.Rebuild.Total, (status.Rebuild.Finished-status.Rebuild.Started)*1000)
	}
	status, _, _ := get(newClient(), portPlain, "unknown.d13d.test", "/")
	check("unknown-host-421", status == 421, "%d", status)
	memory("memory.after_cold_start", control)

	// -------------------------------------------------------- requests
	coldFirst(order, min(n, 2000))
	pass("warm_1client", order, *requests, 1)
	pass("warm_16clients", order, *requests*2, 16)
	memory("memory.after_requests", control)

	// -------------------------------------------------------- incremental
	pid := masterPID()
	edit := 7
	b.byNum[edit] = encode(func() edgesite.Site { s := makeSite(edit, 2, portPlain); s.Hosts.Aliases = sortedAliases(s, "edit."+host(edit)); return s }())
	one, oneTook := b.apply("edit_1")
	after, got := served(portPlain, "edit."+host(edit), 200)
	result("incremental.edit_1", "apply=%s then_served=%s (status %d) reloaded=%v master_same=%v", ms(oneTook), ms(after), got, one.Reloaded, masterPID() == pid)
	check("edit-1-no-reload", !one.Reloaded && !one.Activation.Rebuilt && masterPID() == pid && got == 200, "reloaded %v rebuilt %v status %d", one.Reloaded, one.Activation.Rebuilt, got)

	// Health check cost (what Apply does after every activation,
	// dynroute/apply.go:112): probes for every site vs for the changed one.
	health := &siteindex.Activator{Control: control}
	begin = time.Now()
	allHealth, allErr := health.Check(ctx, b.runtime.Generation(), siteindex.ProbesFor(b.objects()))
	allTook := time.Since(begin)
	begin = time.Now()
	oneHealth, oneErr := health.Check(ctx, b.runtime.Generation(), siteindex.ProbesFor([]siteindex.Object{b.byNum[edit]}))
	oneTook = time.Since(begin)
	result("health_check", "probes_all=%d took=%s healthy=%v | probes_changed=1 took=%s healthy=%v", len(b.byNum), ms(allTook), allHealth.Healthy, ms(oneTook), oneHealth.Healthy)
	check("health-check", allErr == nil && oneErr == nil && allHealth.Healthy && oneHealth.Healthy, "%v %v", allErr, oneErr)

	for number := 101; number <= 200; number++ {
		s := makeSite(number, 2, portPlain)
		s.Hosts.Aliases = sortedAliases(s, "edit."+host(number))
		b.byNum[number] = encode(s)
	}
	hundred, hundredTook := b.apply("edit_100")
	after, got = served(portPlain, "edit."+host(150), 200)
	result("incremental.edit_100", "apply=%s then_served=%s (status %d) reloaded=%v", ms(hundredTook), ms(after), got, hundred.Reloaded)
	check("edit-100-no-reload", !hundred.Reloaded && got == 200, "reloaded %v status %d", hundred.Reloaded, got)

	added := n + 1
	b.byNum[added] = encode(makeSite(added, 1, portPlain))
	add, addTook := b.apply("add_1")
	after, got = served(portPlain, host(added), 200)
	result("incremental.add_1", "apply=%s then_served=%s (status %d) reloaded=%v", ms(addTook), ms(after), got, add.Reloaded)
	check("add-1-no-reload", !add.Reloaded && got == 200, "reloaded %v status %d", add.Reloaded, got)

	delete(b.byNum, added)
	remove, removeTook := b.apply("remove_1")
	after, got = served(portPlain, host(added), 421)
	result("incremental.remove_1", "apply=%s then_421=%s (status %d) reloaded=%v", ms(removeTook), ms(after), got, remove.Reloaded)
	check("remove-1-no-reload", !remove.Reloaded && got == 421, "reloaded %v status %d", remove.Reloaded, got)

	// -------------------------------------------------------- reload (new port)
	extra := n + 2
	b.byNum[extra] = encode(makeSite(extra, 1, portExtra))
	port, portTook := b.apply("new_port")
	after, got = served(portExtra, host(extra), 200)
	result("reload.new_port", "apply=%s then_served=%s (status %d) reloaded=%v master_same=%v", ms(portTook), ms(after), got, port.Reloaded, masterPID() == pid)
	check("new-port-reloads", port.Reloaded && !port.Started && masterPID() == pid && got == 200, "reloaded %v status %d", port.Reloaded, got)
	status, _, _ = get(newClient(), portPlain, host(n/2), "/after-reload")
	check("after-reload-200", status == 200, "%d", status)
	delete(b.byNum, extra)
	back, backTook := b.apply("port_removed")
	result("reload.port_removed", "apply=%s reloaded=%v", ms(backTook), back.Reloaded)
	memory("memory.after_incremental", control)

	// -------------------------------------------------------- agent restart
	begin = time.Now()
	restarted, err := dynroute.New(config)
	if err == nil {
		err = restarted.Recover(ctx)
	}
	recoverTook := time.Since(begin)
	status, _, _ = get(newClient(), portPlain, host(n/3), "/r")
	result("restart.agent", "new+recover=%s master_same=%v sites=%d", ms(recoverTook), masterPID() == pid, len(restarted.Sites()))
	check("agent-restart", err == nil && masterPID() == pid && status == 200 && len(restarted.Sites()) == len(b.byNum), "%v status %d sites %d", err, status, len(restarted.Sites()))

	// -------------------------------------------------------- node restart
	if err := restarted.Stop(ctx); err != nil {
		check("node-stop", false, "%v", err)
	}
	begin = time.Now()
	again, err := dynroute.New(config)
	if err == nil {
		err = again.Recover(ctx)
	}
	nodeTook := time.Since(begin)
	status, _, _ = get(newClient(), portPlain, host(n/4), "/r")
	result("restart.node", "start+rebuild+recover=%s", ms(nodeTook))
	check("node-restart", err == nil && status == 200 && masterPID() != pid, "%v status %d", err, status)
	b.runtime = again
	_, settleTook := b.apply("after_node_restart")
	result("restart.node_first_apply", "apply=%s", ms(settleTook))
	pass("after_node_restart_1client", order, *requests/4, 1)
	memory("memory.end", control)

	result("reloads", "count=%d (cold start counts as start)", b.reloads)
	raw, _ := json.Marshal(map[string]int{"failures": failures})
	fmt.Printf("RESULT summary %s\n", raw)
	_ = again.Stop(ctx)
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}

// sortedAliases adds name to the site's aliases (edgesite wants them sorted).
func sortedAliases(site edgesite.Site, name string) []string {
	aliases := append(append([]string{}, site.Hosts.Aliases...), name)
	sort.Strings(aliases)
	return aliases
}
