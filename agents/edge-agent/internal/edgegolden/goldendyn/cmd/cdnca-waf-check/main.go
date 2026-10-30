// Command cdnca-waf-check is the dynamic routing D11 acceptance run on a
// real OpenResty with the managed WAF engine (tests/dynroute-waf/run.sh
// starts it in the node runtime image with the ModSecurity extension
// mounted, one --rm --network none container). It starts a mock origin and a
// dynamic routing node (goldendyn.Config + internal/dynwaf) and checks, on
// one shared server:
//   - sites of different CRS profile packs (PL1 / PL2 / PL1 observe-only)
//     and different exclusions do not leak into each other, request by
//     request, alternating;
//   - the request body tiers: one site rejects a body above its limit, one
//     inspects only the first bytes (ge-waf S1 "body over 64KB": reject /
//     inspect the first bytes), both in the same server;
//   - allow CIDRs switch the engine off for that site only;
//   - an exclusion change is a new site object: next request, no reload
//     (the nginx master and workers keep their pids);
//   - fail closed: a site whose tier location is missing answers 500;
//     a forged context header changes nothing; the context never reaches
//     the origin;
//   - the OWASP CRS request catalog (catalog.go): normal traffic passes,
//     attacks of every rule family are blocked, log-only passes, site
//     exclusions drop only the excluded rules;
//   - -only tenants (tenants.go, waf-share): two tenants' sites, each in its
//     own configuration scope with its own profile pack and exclusions,
//     on one node; neither tenant's settings reach the other's site.
//   - with -scale N: N managed WAF sites (each with its own exclusions) on
//     the node, the extra time per request of the managed WAF, compared
//     with the same sites without it.
//   - -only perf (perf.go): ADR 0011 §6.5 rule matching cost of generated
//     1k / 10k / 50k rule plans through the match index.
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
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldenrelease"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

var (
	luaRoot     = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	modSecurity = flag.String("modsecurity", "/usr/local/openresty/modsecurity", "engine extension directory")
	state       = flag.String("state", "/tmp/d11", "state directory")
	workers     = flag.Int("workers", 2, "worker_processes")
	scale       = flag.Int("scale", 0, "managed WAF sites for the per-request cost (0 = skip)")
	scaleTarget = flag.Int("scale-targets", 0, "-scale: automatic exclusions in force per site (sites in exclusion buckets of their tier; 0 = none)")
	rounds      = flag.Int("rounds", 3, "alternating measurement rounds")
	requests    = flag.Int("requests", 2000, "requests per round and variant")
	only        = flag.String("only", "", "comma separated parts: functional,tiers,catalog,apps,adaptive,tuning,tenants,scale,eval,perf,wafadapt,wafheader,exclprobe,repeat (eval, perf, wafadapt, wafheader, exclprobe and repeat run only when named)")
	appsDir     = flag.String("apps", "/d11/crs-apps", "directory of the CRS application pack goldens (libs/rulepack/testdata/crs-apps)")
)

// nodeApps are the application exclusion packs the node holds (-only apps).
var nodeApps map[string]edgeconfig.CRSApp

const (
	scope  = "0d110000-0000-4000-8000-000000000001"
	tenant = "0d110000-0000-4000-8000-000000000002"
	edge   = 18311
	origin = "127.0.0.1:19811"
	// probes (from the CRS PL1 golden and PoC section 5)
	sqli = "/q?id=1%27%20OR%20%271%27%3D%271"
	xss  = "/q?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	// fires several CRS PL2 command injection rules and no PL1 one (CRS
	// regression 932200-8; eval: 200 on PL1, 403 on PL2). A single PL2
	// heuristic (/q?a='''') no longer blocks on 严格防护 since two-level
	// scoring.
	pl2Probe = "/q?host=www.google.com;c%24-at%2B%2Fet%24-c%2Fpas%24-swd"
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

type originServer struct {
	mu      sync.Mutex
	headers []http.Header
}

func (o *originServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	_, _ = io.Copy(io.Discard, request.Body)
	if request.URL.Path == "/origin-500" {
		// a response the node rules' phase 5 audits (origin errors)
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(writer, "origin error\n")
		return
	}
	o.mu.Lock()
	o.headers = append(o.headers, request.Header.Clone())
	if len(o.headers) > 64 {
		o.headers = o.headers[len(o.headers)-64:]
	}
	o.mu.Unlock()
	_, _ = io.WriteString(writer, "ok "+request.Host+"\n")
}

func (o *originServer) last() http.Header {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.headers) == 0 {
		return http.Header{}
	}
	return o.headers[len(o.headers)-1]
}

// ---------------------------------------------------------------- sites

func siteID(number int) string { return fmt.Sprintf("0d110000-0000-4000-8000-%012d", number) }

type wafSpec struct {
	profile    edgeconfig.CRSProfile
	exclusions []int
	allow      []string
	body       int
	partial    bool
}

func makeSite(number int, host string, waf *wafSpec) edgesite.Site {
	site := edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID(number), Revision: 1,
		Hosts:     edgesite.Hosts{Primary: host, Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: edge, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: 19811, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 5000, TotalBudgetMS: 10000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
		Limits:   edgesite.Limits{MaxBodyBytes: 64 << 20},
	}
	if waf != nil {
		action, body := "reject", waf.body
		if waf.partial {
			action = "partial"
		}
		if body == 0 {
			body = 1 << 20
		}
		exclusions, allow := append([]int{}, waf.exclusions...), append([]string{}, waf.allow...)
		sort.Ints(exclusions)
		sort.Strings(allow)
		site.Security.ManagedWAF = &edgesite.ManagedWAF{PolicyID: "0d110000-0000-4000-8000-0000000000d1", PolicyVersion: 1,
			Profile: edgesite.ManagedWAFProfile{RequestBodyLimit: body, RequestBodyNoFilesLimit: body,
				RequestBodyLimitAction: action, ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000,
				InspectionLimitAction: "log"},
			CRSProfile: waf.profile.Ref, Exclusions: exclusions, AllowCIDRs: allow}
	}
	return site
}

func profiles() map[string]edgeconfig.CRSProfile {
	result, err := goldenrelease.CRSProfiles()
	if err != nil {
		panic(err)
	}
	return result
}

func profileNamed(all map[string]edgeconfig.CRSProfile, pack string) edgeconfig.CRSProfile {
	for _, profile := range all {
		if profile.Ref.PackID == pack {
			return profile
		}
	}
	panic("no " + pack)
}

// ---------------------------------------------------------------- node

type node struct {
	root      string
	activator *siteindex.Activator
	waf       dynwaf.Result
}

func openresty(args ...string) error {
	output, err := exec.Command("openresty", append([]string{"-p", *state + "/", "-c", "nginx.conf"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v %s", args, err, output)
	}
	return nil
}

// evalProfiles, when set, replaces the golden packs (-only eval adds its
// paranoia 4 probe pack).
var evalProfiles map[string]edgeconfig.CRSProfile

func prepareWAF(sites []edgesite.Site) (dynwaf.Result, error) {
	packs := profiles()
	if evalProfiles != nil {
		packs = evalProfiles
	}
	files, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
	if err != nil {
		return dynwaf.Result{}, err
	}
	return dynwaf.Prepare(dynwaf.Input{Sites: sites, Profiles: packs, Apps: nodeApps,
		CRSText: &edgeconfig.CRSRuleText{Version: rulecatalog.CRSRulesBundle().Version, Files: files},
		Engine: &dynwaf.Engine{ModulePath: filepath.Join(*modSecurity, "modules", "ngx_http_modsecurity_module.so"),
			UnicodeMapPath: filepath.Join(*modSecurity, "unicode.mapping")},
		Root: filepath.Join(*state, "managed-waf"), AuditLog: filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log"),
		Targets: siteTargets, Tuning: nodeTuning})
}

// siteTargets are the automatic exclusions in force by site (-only
// adaptive): each such site runs in an exclusion bucket of its tier.
var siteTargets map[string][]edgeconfig.DynamicWAFTarget

// autoDefenseGate renders the auto defense gate (-only wafadapt: the
// runtime's overlay writes waf.tighten through it).
var autoDefenseGate bool

// nodeTuning are the official CRS tuning entries the node rules render
// (-only tuning).
var nodeTuning []edgeconfig.CRSTuningEntry

// rulePlanRoot holds the sites' rule pack mount plans (-only tuning: the
// tuning pack mount's plan, as the agent writes it); "" = none.
var rulePlanRoot string

func writeConfig(sites []edgesite.Site, waf *edgeskeleton.ManagedWAF) error {
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return err
	}
	keys := 0
	for _, s := range sites {
		keys += len(s.IndexEntries())
	}
	conf, err := goldendyn.Config(goldendyn.ConfigInput{Root: *state, LuaRoot: *luaRoot, Ports: ports, IndexKeys: keys,
		Workers: *workers, ManagedWAF: waf, AutoDefense: autoDefenseGate, RulePlanRoot: rulePlanRoot, Cache: nodeCache, Telemetry: nodeTelemetry})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*state, "nginx.conf"), conf, 0o644)
}

// startNode starts a node for sites; withWAF false renders no engine at all
// (the cost baseline).
func startNode(sites []edgesite.Site, withWAF bool) (*node, error) {
	_ = openresty("-s", "stop")
	time.Sleep(200 * time.Millisecond)
	_ = os.RemoveAll(*state)
	for _, dir := range []string{"logs", "run", "site-index", "site-objects", "temp", goldendyn.SharedDirectory, goldendyn.SharedDirectory + "/cache"} {
		if err := os.MkdirAll(filepath.Join(*state, dir), 0o777); err != nil {
			return nil, err
		}
	}
	n := &node{root: *state}
	var skeleton *edgeskeleton.ManagedWAF
	if withWAF {
		var err error
		if n.waf, err = prepareWAF(sites); err != nil {
			return nil, err
		}
		skeleton = n.waf.Skeleton
	}
	if err := writeConfig(sites, skeleton); err != nil {
		return nil, err
	}
	if err := openresty(); err != nil {
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
	return n, n.activate(sites)
}

// rerender writes the node's WAF configuration and skeleton again for sites
// (the current siteTargets / nodeTuning) and reloads, as the agent's dynamic
// routing does when what the managed WAF renders changed.
func rerender(sites []edgesite.Site) error {
	waf, err := prepareWAF(sites)
	if err != nil {
		return err
	}
	if err := writeConfig(sites, waf.Skeleton); err != nil {
		return err
	}
	if scaleReload() < 0 {
		return fmt.Errorf("reload failed")
	}
	return nil
}

func (n *node) activate(sites []edgesite.Site) error {
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

func stop() { _ = openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

func pids() string {
	raw, _ := exec.Command("sh", "-c", "ps -o pid= -o args= | grep '[n]ginx: ' | awk '{print $1}' | sort | tr '\\n' ,").Output()
	return string(raw)
}

func errorLines() []string {
	raw, _ := os.ReadFile(filepath.Join(*state, goldendyn.SharedDirectory, "error.log"))
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "[crit]") || strings.Contains(line, "[alert]") || strings.Contains(line, "[emerg]") {
			lines = append(lines, line)
		}
	}
	return lines
}

// ---------------------------------------------------------------- client

var client = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64, DisableCompression: true,
	DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}, Timeout: 20 * time.Second}

// sourceClient sends from a given loopback source address (allow CIDRs).
func sourceClient(source string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	return &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}, Timeout: 20 * time.Second}
}

func do(c *http.Client, method, host, path string, body io.Reader, headers map[string]string) int {
	request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", edge, path), body)
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if body != nil && headers["Content-Type"] == "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := c.Do(request)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode
}

func get(host, path string) int { return do(client, http.MethodGet, host, path, nil, nil) }

// ---------------------------------------------------------------- functional

func functional(server *originServer) {
	all := profiles()
	pl1, pl2, observe := profileNamed(all, "system/crs-pl1"), profileNamed(all, "system/crs-pl2"), profileNamed(all, "system/crs-pl1-log")
	// a: PL1, excludes the SQLi probe's rule (942100, PoC section 5)
	// b: PL1, nothing excluded            c: PL2 (more rules)
	// d: PL1 observe-only (log)           e: no managed WAF
	// f: PL1, 1 MiB body limit, reject    g: PL1, 64 KiB, inspect the first bytes (partial)
	// h: PL1, allow 127.0.0.9/32          i: PL1, excludes the XSS probe's rules
	sites := []edgesite.Site{
		makeSite(1, "a.waf.test", &wafSpec{profile: pl1, exclusions: []int{942100}}),
		makeSite(2, "b.waf.test", &wafSpec{profile: pl1}),
		makeSite(3, "c.waf.test", &wafSpec{profile: pl2}),
		makeSite(4, "d.waf.test", &wafSpec{profile: observe}),
		makeSite(5, "e.waf.test", nil),
		makeSite(6, "f.waf.test", &wafSpec{profile: pl1, body: 64 << 10}),
		makeSite(7, "g.waf.test", &wafSpec{profile: pl1, body: 64 << 10, partial: true}),
		makeSite(8, "h.waf.test", &wafSpec{profile: pl1, allow: []string{"127.0.0.9/32"}}),
		makeSite(9, "i.waf.test", &wafSpec{profile: pl1, exclusions: []int{941100, 941110, 941160, 941390}}),
		unbufferedSite(makeSite(11, "u.waf.test", &wafSpec{profile: pl1})),
	}
	n, err := startNode(sites, true)
	if err != nil {
		check("start", false, "%v", err)
		return
	}
	defer stop()
	check("tiers", len(n.waf.Skeleton.Tiers) == 5, "tiers=%d (pl1 1M, pl2 1M, pl1-log 1M, pl1 64K reject, pl1 64K partial)", len(n.waf.Skeleton.Tiers))
	check("clean", get("b.waf.test", "/hello?q=world") == 200 && get("a.waf.test", "/hello?q=world") == 200, "clean requests pass")

	// isolation, alternating six rounds (PoC: ctl acts on its transaction only)
	type want struct {
		host, path string
		status     int
	}
	cases := []want{
		{"a.waf.test", sqli, 200}, {"b.waf.test", sqli, 403}, {"c.waf.test", sqli, 403}, {"d.waf.test", sqli, 200},
		{"e.waf.test", sqli, 200}, {"i.waf.test", sqli, 403}, {"i.waf.test", xss, 200}, {"a.waf.test", xss, 403},
		{"b.waf.test", xss, 403},
	}
	mismatches := []string{}
	for round := range 6 {
		order := rand.New(rand.NewSource(int64(round))).Perm(len(cases))
		for _, index := range order {
			c := cases[index]
			if got := get(c.host, c.path); got != c.status {
				mismatches = append(mismatches, fmt.Sprintf("r%d %s %s=%d want %d", round, c.host, c.path, got, c.status))
			}
		}
	}
	check("isolation", len(mismatches) == 0, "%d requests over 9 sites x 6 rounds in random order; mismatches %v", 6*len(cases), mismatches)

	// PL2 evaluates rules PL1 does not: a probe only PL2 rules of the
	// scored sets see
	if probe := os.Getenv("CDNCA_D11_PROBE"); probe != "" {
		for _, candidate := range strings.Split(probe, " ") {
			fmt.Printf("INFO probe %s PL1=%d PL2=%d\n", candidate, get("b.waf.test", candidate), get("c.waf.test", candidate))
		}
	}
	b, c := get("b.waf.test", pl2Probe), get("c.waf.test", pl2Probe)
	check("profiles", b == 200 && c == 403, "PL2-only probe: PL1 site %d, PL2 site %d", b, c)

	// detector signals (waf-strict-algo 2b): the node's SSTI detector is a
	// strong signal on 严格防护 only; a plain placeholder is not an expression
	expression, placeholder := "/q?t="+url.QueryEscape("{{7*7}}"), "/q?t="+url.QueryEscape("{{name}}")
	be, ce, cp := get("b.waf.test", expression), get("c.waf.test", expression), get("c.waf.test", placeholder)
	check("detector-signal", be == 200 && ce == 403 && cp == 200, "{{7*7}}: PL1 site %d, PL2 site %d; {{name}} on PL2 %d", be, ce, cp)

	// request body tiers (ge-waf S1: over the limit -> reject, or inspect
	// the first bytes only)
	payload := "x=" + strings.Repeat("a", 70<<10) + "&q=1' OR '1'='1"
	f := do(client, http.MethodPost, "f.waf.test", "/post", strings.NewReader(payload), nil)
	g := do(client, http.MethodPost, "g.waf.test", "/post", strings.NewReader(payload), nil)
	gSmall := do(client, http.MethodPost, "g.waf.test", "/post", strings.NewReader("q=1' OR '1'='1"), nil)
	check("body-reject", f == 403 || f == 413, "70 KiB body on the 64 KiB reject tier: %d", f)
	check("body-partial", g == 200 && gSmall == 403, "70 KiB body, attack after 64 KiB on the partial tier: %d (attack inside: %d)", g, gSmall)
	big := do(client, http.MethodPost, "b.waf.test", "/post", strings.NewReader(payload), nil)
	check("body-default", big == 403, "the same body on a 1 MiB site is inspected whole: %d", big)

	// allow CIDRs: engine off for that site and source only
	from9 := sourceClient("127.0.0.9")
	h9 := do(from9, http.MethodGet, "h.waf.test", sqli, nil, nil)
	b9 := do(from9, http.MethodGet, "b.waf.test", sqli, nil, nil)
	h1 := get("h.waf.test", sqli)
	check("allow-cidr", h9 == 200 && b9 == 403 && h1 == 403, "allowed source on h %d, same source on b %d, other source on h %d", h9, b9, h1)

	// 数据实时返回 (SITE_EDGE_OPTIONS) on a managed WAF site: the request
	// leaves its tier location for @cdnca_unbuffered_response; the request
	// phases (403) and the response phases (phase 5: an origin 5xx is
	// audited) must still be those of the site's transaction, as on b.
	unbufferedPhases()

	// forged context and leakage
	forged := do(client, http.MethodGet, "b.waf.test", sqli, nil, map[string]string{"X-Cdnca-Waf-Txid": "c3;s=" + siteID(1) + ";i=l;e=0;g=1;b=0;p=0;d=,;f=0;k=,;u=,;x=,942100,;|1"})
	check("forged", forged == 403, "a client header naming another context: %d", forged)
	get("b.waf.test", "/hello?q=leak")
	leaked := false
	for name, values := range server.last() {
		for _, value := range values {
			if strings.Contains(value, "c3;s=") || strings.Contains(strings.ToLower(name), "cdnca") {
				leaked = true
			}
		}
	}
	check("no-leak", !leaked, "the context never reaches the origin (headers %v)", server.last())

	// exclusion change: next request, no reload
	before := pids()
	sites[1] = makeSite(2, "b.waf.test", &wafSpec{profile: pl1, exclusions: []int{942100}})
	sites[1].Revision = 2
	again, err := prepareWAF(sites)
	sameDir := err == nil && again.Digest == n.waf.Digest
	if err := n.activate(sites); err != nil {
		check("live-change", false, "activate: %v", err)
	} else {
		after := get("b.waf.test", sqli)
		other := get("a.waf.test", xss)
		check("live-change", after == 200 && other == 403 && pids() == before && sameDir,
			"b excludes 942100 now: %d; a unchanged: %d; nginx pids same: %v; WAF files same: %v", after, other, pids() == before, sameDir)
	}

	// fail closed: a site whose tier is not in the skeleton (the agent
	// must refuse; if a site object still arrives, the request is 500)
	sites = append(sites, makeSite(10, "z.waf.test", &wafSpec{profile: pl1, body: 32 << 10}))
	if err := n.activate(sites); err != nil {
		check("fail-closed", false, "activate: %v", err)
	} else {
		z := get("z.waf.test", "/hello")
		check("fail-closed", z == 500, "site of an unknown tier: %d", z)
	}
	if lines := errorLines(); len(lines) != 0 {
		check("error-log", false, "%d crit/alert/emerg lines: %v", len(lines), lines[:min(3, len(lines))])
	} else {
		check("error-log", true, "no crit/alert/emerg")
	}
}

// ---------------------------------------------------------------- scale

type sample struct{ p50, p90, p99, mean float64 }

func measure(hosts []string, path string) (sample, int) {
	durations := make([]float64, 0, *requests)
	bad := 0
	random := rand.New(rand.NewSource(7))
	for range *requests {
		host := hosts[random.Intn(len(hosts))]
		started := time.Now()
		if get(host, path) != 200 {
			bad++
		}
		durations = append(durations, float64(time.Since(started).Microseconds()))
	}
	sort.Float64s(durations)
	sum := 0.0
	for _, value := range durations {
		sum += value
	}
	at := func(q float64) float64 { return durations[min(len(durations)-1, int(q*float64(len(durations))))] }
	return sample{p50: at(0.5), p90: at(0.9), p99: at(0.99), mean: sum / float64(len(durations))}, bad
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// scaleReload sends the master HUP and waits until none of the old workers
// is left and the node answers again (the configuration is parsed and
// merged in the master before it starts new workers).
func scaleReload() time.Duration {
	pidFile := filepath.Join(*state, goldendyn.SharedDirectory, "nginx.pid")
	children := func() string {
		out, _ := exec.Command("sh", "-c", "cat /proc/$(cat "+pidFile+")/task/*/children").Output()
		return strings.TrimSpace(string(out))
	}
	before := children()
	started := time.Now()
	if err := openresty("-s", "reload"); err != nil {
		fmt.Printf("INFO reload failed after %v: %.300s\n", time.Since(started).Round(time.Millisecond), err)
		return -1
	}
	for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		now := children()
		if now == "" || now == before {
			continue
		}
		old := false
		for _, pid := range strings.Fields(before) {
			if strings.Contains(" "+now+" ", " "+pid+" ") {
				old = true
			}
		}
		if !old {
			return time.Since(started)
		}
	}
	fmt.Printf("INFO reload failed: old workers still running after 5m\n")
	return -1
}

func scaleRun() {
	all := profiles()
	pl1, pl2 := profileNamed(all, "system/crs-pl1"), profileNamed(all, "system/crs-pl2")
	exports := pl1.Exports
	random := rand.New(rand.NewSource(11))
	sites := make([]edgesite.Site, 0, *scale)
	plain := make([]edgesite.Site, 0, *scale)
	hosts := make([]string, 0, *scale)
	for index := range *scale {
		host := fmt.Sprintf("s%d.scale.test", index)
		profile := pl1
		if index%4 == 3 {
			profile = pl2
		}
		// each site its own exclusions (0-8 of the profile's exports)
		chosen := map[int]bool{}
		for range random.Intn(9) {
			chosen[exports[random.Intn(len(exports))]] = true
		}
		ids := make([]int, 0, len(chosen))
		for id := range chosen {
			ids = append(ids, id)
		}
		sites = append(sites, makeSite(1000+index, host, &wafSpec{profile: profile, exclusions: ids}))
		plain = append(plain, makeSite(1000+index, host, nil))
		hosts = append(hosts, host)
	}
	started := time.Now()
	waf, err := prepareWAF(sites)
	if err != nil {
		check("scale-prepare", false, "%v", err)
		return
	}
	prepare := time.Since(started)
	rules, _ := os.ReadFile(waf.Skeleton.RulesPath)
	fmt.Printf("INFO scale sites=%d tiers=%d prepare=%v node_rules=%dB\n", *scale, len(waf.Skeleton.Tiers), prepare.Round(time.Millisecond), len(rules))
	type result struct {
		name   string
		sample []sample
		bad    int
		rss    string
		reload []time.Duration
	}
	variants := []struct {
		name    string
		sites   []edgesite.Site
		waf     bool
		targets map[string][]edgeconfig.DynamicWAFTarget
	}{{"no-waf", plain, false, nil}, {"waf", sites, true, nil}}
	if *scaleTarget > 0 {
		// every site in an exclusion bucket with scaleTarget exclusions of its
		// profile's exported rules on synthetic parameter names (the clean
		// request's q is never one: the cost measured is the bucket's rules)
		targets := map[string][]edgeconfig.DynamicWAFTarget{}
		for index, site := range sites {
			exports := pl1.Exports
			if index%4 == 3 {
				exports = pl2.Exports
			}
			list := make([]edgeconfig.DynamicWAFTarget, 0, *scaleTarget)
			for n := range *scaleTarget {
				list = append(list, edgeconfig.DynamicWAFTarget{Rule: exports[n%len(exports)], Location: "args", Name: fmt.Sprintf("p%d_%d", index, n)})
			}
			sort.Slice(list, func(i, j int) bool {
				return list[i].Rule < list[j].Rule || list[i].Rule == list[j].Rule && list[i].Name < list[j].Name
			})
			targets[site.SiteID] = list
		}
		variants = append(variants, struct {
			name    string
			sites   []edgesite.Site
			waf     bool
			targets map[string][]edgeconfig.DynamicWAFTarget
		}{fmt.Sprintf("waf-%dx%d", len(sites), *scaleTarget), sites, true, targets})
	}
	results := map[string]*result{}
	for round := range *rounds {
		for _, variant := range variants {
			siteTargets = variant.targets
			started := time.Now()
			_, err := startNode(variant.sites, variant.waf)
			siteTargets = nil
			if err != nil {
				check("scale-start", false, "%s: %v", variant.name, err)
				return
			}
			start := time.Since(started)
			// reload: HUP, until the master has a new worker set and the
			// node answers
			reload := scaleReload()
			measure(hosts[:min(200, len(hosts))], "/hello?q=world") // warm the worker caches
			s, bad := measure(hosts, "/hello?q=world")
			rss, _ := exec.Command("sh", "-c", "grep VmRSS /proc/$(cat "+filepath.Join(*state, goldendyn.SharedDirectory, "nginx.pid")+")/status | awk '{print $2}'").Output()
			r := results[variant.name]
			if r == nil {
				r = &result{name: variant.name}
				results[variant.name] = r
			}
			r.sample = append(r.sample, s)
			r.bad += bad
			r.rss = strings.TrimSpace(string(rss))
			workers, _ := exec.Command("sh", "-c", "for p in $(cat /proc/$(cat "+filepath.Join(*state, goldendyn.SharedDirectory, "nginx.pid")+
				")/task/*/children); do awk '/VmRSS/{print $2}' /proc/$p/status; done | sort -n | tail -1").Output()
			fmt.Printf("INFO round %d %s p50=%.0fus p90=%.0fus p99=%.0fus mean=%.0fus non200=%d master_rss=%skB worker_rss=%skB start=%v reload=%v\n",
				round, variant.name, s.p50, s.p90, s.p99, s.mean, bad, r.rss, strings.TrimSpace(string(workers)),
				start.Round(time.Millisecond), reload.Round(time.Millisecond))
			r.reload = append(r.reload, reload)
			stop()
		}
	}
	median := func(values []sample, get func(sample) float64) float64 {
		list := make([]float64, len(values))
		for index, value := range values {
			list[index] = get(value)
		}
		sort.Float64s(list)
		return list[len(list)/2]
	}
	base, waf2 := results["no-waf"], results["waf"]
	p50 := func(s sample) float64 { return s.p50 }
	p99 := func(s sample) float64 { return s.p99 }
	summary := map[string]any{"sites": *scale, "tiers": len(waf.Skeleton.Tiers), "requests_per_round": *requests, "rounds": *rounds,
		"no_waf_p50_us": median(base.sample, p50), "waf_p50_us": median(waf2.sample, p50),
		"no_waf_p99_us": median(base.sample, p99), "waf_p99_us": median(waf2.sample, p99),
		"extra_p50_us": median(waf2.sample, p50) - median(base.sample, p50), "master_rss_kb": map[string]string{"no_waf": base.rss, "waf": waf2.rss}}
	bad := base.bad + waf2.bad
	if *scaleTarget > 0 {
		// the exclusions' own cost: against the same WAF without them
		ex := results[variants[2].name]
		summary["targets_per_site"] = *scaleTarget
		summary["targets_p50_us"], summary["targets_p99_us"] = median(ex.sample, p50), median(ex.sample, p99)
		summary["targets_extra_p50_us"] = median(ex.sample, p50) - median(waf2.sample, p50)
		summary["targets_extra_p99_us"] = median(ex.sample, p99) - median(waf2.sample, p99)
		summary["master_rss_kb"].(map[string]string)["targets"] = ex.rss
		summary["reload_ms"] = map[string]int64{"waf": medianDuration(waf2.reload).Milliseconds(), "targets": medianDuration(ex.reload).Milliseconds()}
		bad += ex.bad
	}
	encoded, _ := json.Marshal(summary)
	fmt.Printf("SCALE %s\n", encoded)
	check("scale", bad == 0, "every clean request 200 (%d failures)", bad)
}

func main() {
	flag.Parse()
	server := &originServer{}
	listener, err := net.Listen("tcp", origin)
	if err != nil {
		fmt.Println("FAIL origin", err)
		os.Exit(1)
	}
	go func() { _ = http.Serve(listener, server) }()
	parts := map[string]bool{}
	for _, part := range strings.Split(*only, ",") {
		if part != "" {
			parts[part] = true
		}
	}
	if len(parts) == 0 || parts["functional"] {
		functional(server)
	}
	if len(parts) == 0 || parts["functional"] || parts["unbuffered"] {
		unbufferedCacheRun()
	}
	if len(parts) == 0 || parts["tiers"] {
		tiersRun()
	}
	if len(parts) == 0 || parts["catalog"] {
		catalogRun()
	}
	if len(parts) == 0 || parts["apps"] {
		appsRun()
	}
	if len(parts) == 0 || parts["adaptive"] {
		adaptiveRun()
	}
	if len(parts) == 0 || parts["tuning"] {
		tuningRun()
	}
	if parts["buckets"] {
		bucketsRun()
	}
	if parts["repeat"] {
		repeatRun()
	}
	if parts["managedwaflog"] {
		managedWAFLogRun()
	}
	if len(parts) == 0 || parts["tenants"] {
		tenantsRun()
	}
	if parts["eval"] {
		evalRun()
	}
	if *scale > 0 && (len(parts) == 0 || parts["scale"]) {
		scaleRun()
	}
	if parts["perf"] {
		perfRun()
	}
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}

// unbufferedSite turns 数据实时返回 on (Origin.Unbuffered response).
func unbufferedSite(site edgesite.Site) edgesite.Site {
	site.Origin.Unbuffered = []string{edgesite.UnbufferedResponse}
	return site
}

// unbufferedPhases: u.waf.test (PL1, 数据实时返回) against b.waf.test (PL1,
// buffered): same request phase verdicts, and an origin 500 written to the
// audit log by the node rules' phase 5 on both.
func unbufferedPhases() {
	u, b := get("u.waf.test", sqli), get("b.waf.test", sqli)
	check("unbuffered-request-phase", u == 403 && b == 403, "SQLi probe: unbuffered %d, buffered %d", u, b)
	clean := get("u.waf.test", "/hello?q=world")
	check("unbuffered-clean", clean == 200, "clean request on the unbuffered site: %d", clean)
	auditPath := filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log")
	audited := func(host string) (int, bool) {
		before := fileSize(auditPath)
		status := get(host, "/origin-500")
		time.Sleep(300 * time.Millisecond) // the audit log is written after the response
		for _, record := range auditRecords(auditPath, before) {
			if strings.Contains(record, "/origin-500") && strings.Contains(record, host) {
				return status, true
			}
		}
		return status, false
	}
	bStatus, bAudited := audited("b.waf.test")
	uStatus, uAudited := audited("u.waf.test")
	check("unbuffered-response-phase", bStatus == 500 && uStatus == 500 && bAudited && uAudited,
		"origin 500: buffered status %d audited %v; unbuffered status %d audited %v", bStatus, bAudited, uStatus, uAudited)
}

// nodeCache is the node's cache pool (Zones 0 = no cache module; a node
// always has one, edgecache.PlanPool's minimum is 64 MiB).
var nodeCache edgecache.Pool

// unbufferedCacheRun: unbufferedPhases on a node with a cache pool, where
// the cache module (cdnca_cache bypass) moves the request to the
// unbuffered location, as on a production node.
func unbufferedCacheRun() {
	pool, err := edgecache.PlanPool(edgecache.PoolInput{MaxBytes: 256 << 20})
	if err != nil {
		check("unbuffered-cache start", false, "%v", err)
		return
	}
	nodeCache = pool
	defer func() { nodeCache = edgecache.Pool{} }()
	pl1 := profileNamed(profiles(), "system/crs-pl1")
	sites := []edgesite.Site{makeSite(2, "b.waf.test", &wafSpec{profile: pl1}),
		unbufferedSite(makeSite(11, "u.waf.test", &wafSpec{profile: pl1}))}
	if _, err := startNode(sites, true); err != nil {
		check("unbuffered-cache start", false, "%v", err)
		return
	}
	defer stop()
	fmt.Println("-- with the cache module")
	unbufferedPhases()
	for _, line := range errorLines() {
		check("unbuffered-cache error log", false, "%s", line)
	}
}
