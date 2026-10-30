// Command cdnca-dyntelemetry-check is the dynamic routing D12 acceptance run
// against a real OpenResty (tests/dynroute-telemetry/run.sh starts it inside
// the node runtime image, one --rm --network none container):
//
//   - golden: the D0 access-logs scenario (tests/edge-golden/cdnca-v7) as a
//     site object on a shared server; the node-level logs, normalized by the
//     Agent path (dyntelemetry.Normalize), compared field by field with the
//     v7 golden (masked fields as the golden masks them);
//   - attribution: SITES sites (default 10000) of several tenants and scopes
//     on two ports, primary/alias/wildcard names, mixed traffic (plain,
//     blocked by a rule, origin 404, unknown Host, node location), two
//     generation switches during the traffic; every logged line must resolve
//     to the site of its request (100%), unknown Hosts must not be logged;
//   - capture: a capture site's events carry the allowlisted header and the
//     attribution;
//   - error log: two reloads with quic reuseport; the only alert/crit/emerg
//     lines are the known noise, filtered by dyntelemetry.ErrorLog.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

var (
	luaRoot   = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	confPath  = flag.String("conf", "/d12/nginx.conf", "skeleton template")
	golden    = flag.String("golden", "/d12/golden", "edge golden corpus (cdnca-v7)")
	stateRoot = flag.String("state", "/tmp/d12state", "state directory")
	workers   = flag.Int("workers", 2, "worker_processes")
	sites     = flag.Int("sites", 10000, "sites for the attribution run")
	requests  = flag.Int("requests", 60000, "requests of the attribution run")
	only      = flag.String("only", "", "comma-separated checks")
)

const nodeID = "0d120000-0000-4000-8000-00000000ffff"

var failures int

func check(name string, ok bool, format string, args ...any) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("%s %s %s\n", status, name, fmt.Sprintf(format, args...))
}

type node struct {
	prefix    string
	activator *siteindex.Activator
	control   *siteindex.Control
	registry  *dyntelemetry.Registry
	versions  map[string]string // scope -> config version of the next activation
	shared    string
	offsets   map[string]int64
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func render(listen string) error {
	template, err := os.ReadFile(*confPath)
	if err != nil {
		return err
	}
	shared := filepath.Join(*stateRoot, "shared")
	server, err := edgeconfig.RenderDynamicRoutingTelemetryServer(shared)
	if err != nil {
		return err
	}
	var vars strings.Builder
	for _, name := range edgeconfig.DynamicRoutingTelemetryVariables {
		fmt.Fprintf(&vars, "      set $%s \"\";\n", name)
	}
	conf := strings.NewReplacer("__WORKERS__", strconv.Itoa(*workers), "__LUA_ROOT__", *luaRoot,
		"__STATE__", *stateRoot, "__INDEX_SIZE__", "32m", "__LRU_ITEMS__", "20000",
		"__TELEMETRY_HTTP__", edgeconfig.RenderDynamicRoutingTelemetryHTTP(),
		"__TELEMETRY_SERVER__", server, "__TELEMETRY_VARS__", vars.String(), "__LISTEN__", listen).Replace(string(template))
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

func newNode(listen string) (*node, error) {
	_ = os.RemoveAll(*stateRoot)
	for _, dir := range []string{"nginx/logs", "run", "site-index", "site-objects", "plans", "shared/telemetry/dynroute", "agent"} {
		if err := os.MkdirAll(filepath.Join(*stateRoot, dir), 0o755); err != nil {
			return nil, err
		}
	}
	if err := render(listen); err != nil {
		return nil, err
	}
	if err := openresty(); err != nil {
		return nil, err
	}
	registry, err := dyntelemetry.OpenRegistry(filepath.Join(*stateRoot, "agent", "attribution.json"))
	if err != nil {
		return nil, err
	}
	control := siteindex.NewControl(filepath.Join(*stateRoot, "run", "cdnca-site-admin.sock"))
	n := &node{prefix: *stateRoot, control: control, registry: registry, versions: map[string]string{},
		shared: filepath.Join(*stateRoot, "shared"), offsets: map[string]int64{}}
	n.activator = &siteindex.Activator{
		Control: control,
		Files:   siteindex.Files{Root: filepath.Join(*stateRoot, "site-index"), Access: siteindex.Access{GID: workerGID()}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*stateRoot, "site-objects"), Access: siteindex.Access{GID: workerGID()}},
		// What the agent does: register the attribution of the generations
		// before the node can serve them.
		Prepare: func(first, last uint64) error { return registry.Register(first, last, n.versions) },
	}
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

func (n *node) stop() { _ = openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

// lines reads the node-level log from where it stopped.
func (n *node) lines(stream string) [][]byte {
	path := filepath.Join(n.shared, "telemetry", "dynroute", stream+".jsonl")
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	_, _ = file.Seek(n.offsets[path], io.SeekStart)
	reader := bufio.NewReaderSize(file, 1<<20)
	var result [][]byte
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		n.offsets[path] += int64(len(line))
		result = append(result, bytes.TrimRight(line, "\n"))
	}
	return result
}

func (n *node) sites() *dyntelemetry.ObjectSites {
	return &dyntelemetry.ObjectSites{Root: n.activator.Objects.Root, Limit: 1 << 20}
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

func emptyCapture() siteobject.TelemetryCapture {
	return siteobject.TelemetryCapture{Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{},
		ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{}}
}

func baseSite(scope, tenant, site string, revision int64, primary string, aliases []string, origin string, port int, ports ...int) edgesite.Site {
	listeners := []edgesite.Listener{}
	for _, value := range append([]int{port}, ports...) {
		listeners = append(listeners, edgesite.Listener{Port: value, AddressFamily: edgesite.FamilyIPv4})
	}
	if aliases == nil {
		aliases = []string{}
	}
	sort.Strings(aliases)
	host, portText, _ := net.SplitHostPort(origin)
	originPort, _ := strconv.Atoi(portText)
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: site, Revision: revision,
		Hosts: edgesite.Hosts{Primary: primary, Aliases: aliases}, Listeners: listeners,
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o1", Scheme: "http", Host: host, Port: originPort, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 5000, TotalBudgetMS: 10000}}}},
		Security:  edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:    []edgesite.ErrorPage{},
		Telemetry: &edgesite.Telemetry{Capture: emptyCapture()},
	}
}

// writePlan writes the D6 rule plan the D7 stand-in runs for a site.
func writePlan(siteID string, policies []edgeconfig.SecurityPolicy) {
	plan, err := edgeconfig.CompileSecurityRulePlan(policies, false, true)
	if err != nil {
		panic(err)
	}
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(*stateRoot, "plans", siteID+".json"), raw, 0o644); err != nil {
		panic(err)
	}
}

// startOrigin answers "<name> <host> <uri>" (the golden mock origin's echo)
// and the scenario's fixed routes.
func startOrigin(address, name string, routes map[string]int, bodies map[string]string) func() {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if status, ok := routes[r.URL.Path]; ok {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, bodies[r.URL.Path])
			return
		}
		_, _ = io.WriteString(w, name+" "+r.Host+" "+r.URL.RequestURI())
	})}
	go server.Serve(listener)
	return func() { _ = server.Close() }
}

var client = &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DisableCompression: true}, Timeout: 10 * time.Second}

// send sends one request the way the golden client does (one connection,
// User-Agent cdnca-edge-golden/1 unless the step sets one).
func send(port int, host, method, path string, headers map[string]string, body string) int {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), reader)
	request.Host = host
	request.Header.Set("User-Agent", edgegolden.UserAgent)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode
}

func main() {
	flag.Parse()
	selected := map[string]bool{}
	for _, name := range strings.Split(*only, ",") {
		if name != "" {
			selected[name] = true
		}
	}
	run := func(name string, listen string, fn func(*node)) {
		if len(selected) > 0 && !selected[name] {
			return
		}
		n, err := newNode(listen)
		if err != nil {
			check(name+"-start", false, "%v", err)
			return
		}
		defer n.stop()
		fmt.Printf("== %s\n", name)
		fn(n)
		summary, err := (&dyntelemetry.ErrorLog{Path: filepath.Join(n.prefix, "nginx", "logs", "error.log")}).Read()
		check(name+"-error-log", err == nil && len(summary.Severe) == 0, "severe=%d noise=%d %v", len(summary.Severe), summary.Noise, summary.Severe)
	}
	run("golden", "    listen 127.0.0.1:18094;", checkGolden)
	run("attribution", "    listen 127.0.0.1:18080;\n    listen 127.0.0.1:18081;", checkAttribution)
	run("capture", "    listen 127.0.0.1:18080;", checkCapture)
	run("quic-noise", quicListen(), checkQUICNoise)
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
