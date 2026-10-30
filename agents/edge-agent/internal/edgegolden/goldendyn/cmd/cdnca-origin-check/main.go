// Command cdnca-origin-check is the dynamic routing D5a acceptance run on a
// real OpenResty (tests/dynroute-origin/run.sh starts it in the node runtime
// image, one --rm --network none container). It starts mock origins in the
// container, a dynamic routing node (goldendyn.Config: shared server, D3
// index, cdnca_origin hooks) and checks what the golden does not cover:
// origin connection reuse never crosses pools (sites, pools and trust
// anchors on one origin address), conditional routes (path prefix, client
// CIDR, node region, route fallback), origin names resolved by DNS, a
// non-idempotent request never sent twice, ingress source binding; then
// measures origin selection with SCALE sites x several pools.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
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
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

var (
	luaRoot = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	state   = flag.String("state", "/tmp/d5a", "state directory")
	workers = flag.Int("workers", 1, "worker_processes")
	scale   = flag.Int("scale", 10000, "sites for the selection measurement (0 = skip)")
	pools   = flag.Int("pools", 4, "pools per site in the measurement")
	region  = flag.String("region", "cn-east", "node region")
)

const (
	scope   = "0d5a0000-0000-4000-8000-000000000001"
	tenant  = "0d5a0000-0000-4000-8000-000000000002"
	edge    = 18180
	edge2   = 18181             // a second HTTP listener (follow_port)
	shared  = "127.0.0.1:19501" // one origin address every keepalive case uses
	anchorA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	anchorB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
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

// ---------------------------------------------------------------- origins

// origin answers "<name> <conn> <host> <uri>": conn numbers the TCP
// connection the request arrived on, so a test sees reuse.
type origin struct {
	name     string
	listener net.Listener
	mu       sync.Mutex
	conns    int
	requests []string
	delay    map[string]time.Duration
	status   map[string]int
	peers    []string
	headers  []http.Header
}

func startOrigin(name, address string) *origin {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	o := &origin{name: name, listener: listener, delay: map[string]time.Duration{}, status: map[string]int{}}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			o.mu.Lock()
			o.conns++
			id := o.conns
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			o.peers = append(o.peers, host)
			o.mu.Unlock()
			go o.serve(conn, id)
		}
	}()
	return o
}

func (o *origin) serve(conn net.Conn, id int) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		o.mu.Lock()
		o.requests = append(o.requests, request.Method+" "+request.RequestURI)
		o.headers = append(o.headers, request.Header.Clone())
		delay, status := o.delay[request.URL.Path], o.status[request.URL.Path]
		o.mu.Unlock()
		time.Sleep(delay)
		if status == 0 {
			status = 200
		}
		body := fmt.Sprintf("%s %d %s %s", o.name, id, request.Host, request.RequestURI)
		location := ""
		if request.URL.Path == "/redirect" {
			status, location = 302, "Location: http://"+o.listener.Addr().String()+"/next?x=1\r\n"
		}
		fmt.Fprintf(conn, "HTTP/1.1 %d X\r\n%sContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", status, location, len(body), body)
	}
}

func (o *origin) lastHeaders() http.Header {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.headers) == 0 {
		return http.Header{}
	}
	return o.headers[len(o.headers)-1]
}

func (o *origin) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.requests)
}

// ---------------------------------------------------------------- DNS

// dnsServer answers A queries from names (UDP, 127.0.0.53:53).
func dnsServer(names map[string]string) {
	conn, err := net.ListenPacket("udp", "127.0.0.53:53")
	if err != nil {
		panic(err)
	}
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil || n < 17 {
				continue
			}
			query := buffer[:n]
			name, end := readName(query, 12)
			qtype := binary.BigEndian.Uint16(query[end:])
			answer := append([]byte{}, query[:end+4]...)
			answer[2], answer[3] = 0x81, 0x80
			address := net.ParseIP(names[name]).To4()
			if qtype == 1 && address != nil {
				binary.BigEndian.PutUint16(answer[6:], 1)
				answer = append(answer, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
				answer = append(answer, address...)
			} else if address == nil {
				answer[3] = 0x83 // NXDOMAIN
			}
			_, _ = conn.WriteTo(answer, peer)
		}
	}()
}

func readName(packet []byte, offset int) (string, int) {
	var labels []string
	for packet[offset] != 0 {
		length := int(packet[offset])
		labels = append(labels, string(packet[offset+1:offset+1+length]))
		offset += 1 + length
	}
	return strings.Join(labels, "."), offset + 1
}

// ---------------------------------------------------------------- sites

func siteID(number int) string { return fmt.Sprintf("0d5a0000-0000-4000-8000-%012d", number) }

func retry(attempts int) edgesite.Retry {
	return edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: attempts, ConnectTimeoutMS: 1000, ReadTimeoutMS: 400, TotalBudgetMS: 3000}
}

func endpoint(id, address string) edgesite.Endpoint {
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	return edgesite.Endpoint{ID: id, Scheme: "http", Host: host, Port: port, Weight: 1}
}

func pool(id string, endpoints ...edgesite.Endpoint) edgesite.Pool {
	return edgesite.Pool{ID: id, Kind: edgesite.PoolOrigin, Algorithm: "round_robin", Endpoints: endpoints, Retry: retry(len(endpoints))}
}

func site(number int, primary string, origin edgesite.Origin) edgesite.Site {
	if origin.Routes == nil {
		origin.Routes = []edgesite.Route{}
	}
	origin.Auth = []edgesite.OriginAuth{}
	sort.Slice(origin.Pools, func(i, j int) bool { return origin.Pools[i].ID < origin.Pools[j].ID })
	return edgesite.Site{Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID(number), Revision: 1,
		Hosts: edgesite.Hosts{Primary: primary, Aliases: []string{}}, Listeners: []edgesite.Listener{{Port: edge, AddressFamily: edgesite.FamilyIPv4}},
		Origin: origin,
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}},
			CC: []edgesite.CCBinding{}},
		Errors: []edgesite.ErrorPage{}}
}

// fixtureSites: the keepalive key is site|pool|trust anchor|SNI; plain
// origins carry no anchor (HTTPS origins are D5b), so the cases here are
// the site and pool parts on one origin address.
func fixtureSites() []edgesite.Site {
	idle := int64(30000)
	reuse := func(p edgesite.Pool) edgesite.Pool { p.KeepaliveIdleTimeoutMS = &idle; return p }
	var sites []edgesite.Site
	// keepalive: site 1 has pools a and b on the same origin address; site 2 its own pool there
	sites = append(sites, site(1, "ka.test", edgesite.Origin{DefaultPoolID: "a",
		Pools:  []edgesite.Pool{reuse(pool("a", endpoint("o", shared))), reuse(pool("b", endpoint("o", shared)))},
		Routes: []edgesite.Route{{ID: "to-b", Priority: 1, PathPrefix: "/b", PoolID: "b"}}}))
	sites = append(sites, site(2, "kb.test", edgesite.Origin{DefaultPoolID: "a",
		Pools: []edgesite.Pool{reuse(pool("a", endpoint("o", shared)))}}))
	// a pool with reuse off on the same address
	off := int64(0)
	noReuse := pool("a", endpoint("o", shared))
	noReuse.KeepaliveIdleTimeoutMS = &off
	sites = append(sites, site(3, "kc.test", edgesite.Origin{DefaultPoolID: "a", Pools: []edgesite.Pool{noReuse}}))
	// conditional routes (v7 order: as listed); region route of another region dropped
	sites = append(sites, site(4, "route.test", edgesite.Origin{DefaultPoolID: "main",
		Pools: []edgesite.Pool{pool("main", endpoint("m", "127.0.0.1:19511")), pool("api", endpoint("a", "127.0.0.1:19512")),
			pool("lan", endpoint("l", "127.0.0.1:19513")), pool("east", endpoint("e", "127.0.0.1:19514")),
			pool("west", endpoint("w", "127.0.0.1:19515")), pool("dead", endpoint("d", "127.0.0.1:19519")),
			pool("spare", endpoint("s", "127.0.0.1:19516"))},
		Routes: []edgesite.Route{
			{ID: "api", Priority: 30, PathPrefix: "/api", PoolID: "api"},
			{ID: "static", Priority: 25, PathPrefix: "/static/", PoolID: "east"},
			{ID: "west", Priority: 20, NodeRegions: []string{"us-west"}, PoolID: "west"},
			{ID: "lan", Priority: 10, ClientCIDRs: []string{"127.0.0.9/32"}, PoolID: "lan"},
			{ID: "dead", Priority: 5, PathPrefix: "/dead", PoolID: "dead", FallbackPoolID: "spare"},
			{ID: "east", Priority: 1, NodeRegions: []string{*region}, PathPrefix: "/east", PoolID: "east"},
		}}))
	// origin name resolved by DNS
	sites = append(sites, site(5, "dns.test", edgesite.Origin{DefaultPoolID: "p",
		Pools: []edgesite.Pool{pool("p", edgesite.Endpoint{ID: "n", Scheme: "http", Host: "origin.dns.test", Port: 19521, Weight: 1})}}))
	// non-idempotent: two endpoints, the first times out reading
	sites = append(sites, site(6, "put.test", edgesite.Origin{DefaultPoolID: "p",
		Pools: []edgesite.Pool{pool("p", endpoint("slow", "127.0.0.1:19531"), endpoint("fast", "127.0.0.1:19532"))}}))
	// ingress source binding
	sites = append(sites, site(7, "bind.test", edgesite.Origin{DefaultPoolID: "p", IngressSource: true,
		Pools: []edgesite.Pool{pool("p", endpoint("o", "127.0.0.1:19541"))}}))
	// forwarding: client address headers, trusted proxy, Location rewrite
	forward := site(8, "fwd.test", edgesite.Origin{DefaultPoolID: "p", TrustedProxyCIDRs: []string{"127.0.0.7/32"},
		Pools: []edgesite.Pool{pool("p", endpoint("o", "127.0.0.1:19551"))}})
	sites = append(sites, forward)
	// tp-b3a-be: follow the visitor's port (follow_port; the edge's HTTP
	// listeners 18180 and 18181, origins there) with the Host 访问域名+端口
	// (visitor_port); a second site sends 访问域名+端口 on a fixed origin port
	follow := pool("p", endpoint("o", "127.0.0.2:19561"))
	follow.FollowPort, follow.RequestHost = true, &edgesite.RequestHost{Mode: edgesite.RequestHostVisitorPort}
	followSite := site(9, "follow.test", edgesite.Origin{DefaultPoolID: "p", Pools: []edgesite.Pool{follow}})
	followSite.Listeners = append(followSite.Listeners, edgesite.Listener{Port: edge2, AddressFamily: edgesite.FamilyIPv4})
	sites = append(sites, followSite)
	visitorPort := pool("p", endpoint("o", "127.0.0.1:19562"))
	visitorPort.RequestHost = &edgesite.RequestHost{Mode: edgesite.RequestHostVisitorPort}
	sites = append(sites, site(10, "vport.test", edgesite.Origin{DefaultPoolID: "p", Pools: []edgesite.Pool{visitorPort}}))
	return sites
}

// ---------------------------------------------------------------- node

type node struct {
	root      string
	activator *siteindex.Activator
}

func startNode(sites []edgesite.Site, settings edgeskeleton.Node) (*node, error) {
	_ = exec.Command("openresty", "-p", *state+"/", "-c", "nginx.conf", "-s", "stop").Run()
	time.Sleep(200 * time.Millisecond)
	_ = os.RemoveAll(*state)
	for _, dir := range []string{"logs", "run", "site-index", "site-objects", "temp"} {
		if err := os.MkdirAll(filepath.Join(*state, dir), 0o755); err != nil {
			return nil, err
		}
	}
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return nil, err
	}
	keys := 0
	for _, s := range sites {
		keys += len(s.IndexEntries())
	}
	raw, err := goldendyn.Config(goldendyn.ConfigInput{Root: *state, LuaRoot: *luaRoot, Ports: ports, Node: &settings,
		IndexKeys: keys, Workers: *workers})
	if err != nil {
		return nil, err
	}
	conf := string(raw)
	// before the skeleton's control socket server (the last server)
	anchor := "  server {\n    listen \"unix:"
	if !strings.Contains(conf, anchor) {
		return nil, fmt.Errorf("skeleton has no control socket server")
	}
	conf = strings.Replace(conf, anchor, benchServer+anchor, 1)
	// the edge's HTTP listeners on loopback 127.0.0.1 only, so the follow
	// port origins can listen on 127.0.0.2 on the same ports (one network
	// namespace); what the edge sees ($server_port) is unchanged
	for _, port := range []int{edge, edge2} {
		conf = strings.ReplaceAll(conf, fmt.Sprintf("listen 0.0.0.0:%d ", port), fmt.Sprintf("listen 127.0.0.1:%d ", port))
	}
	if err := os.WriteFile(filepath.Join(*state, "nginx.conf"), []byte(conf), 0o644); err != nil {
		return nil, err
	}
	if output, err := exec.Command("openresty", "-t", "-p", *state+"/", "-c", "nginx.conf").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("openresty -t: %v %s", err, output)
	} else if len(sites) < 100 {
		fmt.Printf("PASS OPENRESTY-T %s\n", strings.Join(strings.Fields(string(output)), " "))
	}
	if output, err := exec.Command("openresty", "-p", *state+"/", "-c", "nginx.conf").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("start: %v %s", err, output)
	}
	control := siteindex.NewControl(filepath.Join(*state, "run", "cdnca-site-admin.sock"))
	n := &node{root: *state, activator: &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(*state, "site-index"), Access: siteindex.Access{GID: workerGID()}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*state, "site-objects"), Access: siteindex.Access{GID: workerGID()}}}}
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
		objects = append(objects, object)
	}
	if _, err := n.activator.Activate(context.Background(), objects); err != nil {
		return nil, err
	}
	return n, nil
}

// workerGID is the group of the OpenResty workers (nginx's default user
// nobody), as the agent sets it on a node.
func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func (n *node) errorLog(grep string) []string {
	raw, _ := os.ReadFile(filepath.Join(n.root, goldendyn.SharedDirectory, "error.log"))
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, grep) {
			lines = append(lines, line)
		}
	}
	return lines
}

// benchServer measures cdnca_origin's per-request work inside a worker:
// for random sites it selects the site object the way route() does (by
// digest), compiles the plan on first use, then times select_route + one
// balancer selection in the pool's algorithm.
const benchServer = `  server {
    listen 127.0.0.1:18199;
    location = /bench { content_by_lua_block {
      local ffi = require "ffi"
      pcall(ffi.cdef, [[typedef struct { long tv_sec; long tv_nsec; } cdnca_d5a_ts; int cdnca_d5a_clock_gettime(int, cdnca_d5a_ts *) __asm__("clock_gettime");]])
      local ts = ffi.new("cdnca_d5a_ts")
      local function now_us() ffi.C.cdnca_d5a_clock_gettime(1, ts); return tonumber(ts.tv_sec) * 1e6 + tonumber(ts.tv_nsec) / 1e3 end
      local site, origin = require "cdnca_site", require "cdnca_origin"
      local args = ngx.req.get_uri_args()
      local n, count, port = tonumber(args.n), tonumber(args.count), tonumber(args.port)
      local samples, compiles = {}, {}
      for i = 1, n do
        local id = (i * 7919) % count + 1
        local object, state, matched, hex = site.lookup(port, string.format(args.prefix, id))
        if not object then ngx.say("miss ", id, " ", state) return end
        local t0 = now_us()
        local plan = origin.plan_for(object, hex)
        local t1 = now_us()
        local pool = origin.select_route(plan)
        local phase = origin._new_phase(plan, pool)
        local index = origin._algorithms[pool.algorithm](phase, ngx.time())
        origin._free_peer(phase, index, false, ngx.time())
        samples[i] = now_us() - t1
        compiles[i] = t1 - t0
      end
      table.sort(samples) table.sort(compiles)
      local function p(list, q) return list[math.max(1, math.ceil(#list * q))] end
      ngx.say(require("cjson").encode({ n = n, select_p50_us = p(samples, 0.5), select_p99_us = p(samples, 0.99),
        select_max_us = samples[#samples], compile_p50_us = p(compiles, 0.5), compile_p99_us = p(compiles, 0.99) }))
    } }
  }
`

// ---------------------------------------------------------------- client

var client = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

type answer struct {
	status   int
	body     string
	location string
}

func get(method, host, path string, source string, headers ...string) answer {
	return getOn(edge, method, host, path, source, headers...)
}

func getOn(port int, method, host, path string, source string, headers ...string) answer {
	request, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), strings.NewReader(map[bool]string{true: "body", false: ""}[method == "PUT"]))
	request.Host = host
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	c := client
	if source != "" {
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
		c = &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DialContext: dialer.DialContext}, Timeout: 10 * time.Second,
			CheckRedirect: client.CheckRedirect}
	}
	response, err := c.Do(request)
	if err != nil {
		return answer{body: err.Error()}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return answer{status: response.StatusCode, body: string(raw), location: response.Header.Get("Location")}
}

// connOf: the origin's connection number in "<name> <conn> ..."
func connOf(a answer) string {
	fields := strings.Fields(a.body)
	if len(fields) < 2 {
		return "?"
	}
	return fields[0] + "#" + fields[1]
}

// ---------------------------------------------------------------- checks

func functional() {
	sharedOrigin := startOrigin("shared", shared)
	main, api, lan := startOrigin("main", "127.0.0.1:19511"), startOrigin("api", "127.0.0.1:19512"), startOrigin("lan", "127.0.0.1:19513")
	east, west, spare := startOrigin("east", "127.0.0.1:19514"), startOrigin("west", "127.0.0.1:19515"), startOrigin("spare", "127.0.0.1:19516")
	named := startOrigin("named", "127.0.0.1:19521")
	slow, fast := startOrigin("slow", "127.0.0.1:19531"), startOrigin("fast", "127.0.0.1:19532")
	slow.delay["/r"] = time.Second
	bound := startOrigin("bound", "127.0.0.1:19541")
	fwdOrigin := startOrigin("fwd", "127.0.0.1:19551")
	_, _, _, _, _, _ = main, api, lan, east, west, spare
	dnsServer(map[string]string{"origin.dns.test": "127.0.0.1"})

	n, err := startNode(fixtureSites(), edgeskeleton.Node{Region: *region, Resolvers: []string{"127.0.0.53"}, IngressSourceIPv4: "127.0.0.77"})
	if err != nil {
		fmt.Println("FAIL start", err)
		failures++
		return
	}

	// connection reuse: same pool reuses, other pool / other site / reuse off never do
	first, again := get("GET", "ka.test", "/1", ""), get("GET", "ka.test", "/2", "")
	check("KEEPALIVE-SAME-POOL", connOf(first) == connOf(again) && first.status == 200, "%s then %s", connOf(first), connOf(again))
	otherPool := get("GET", "ka.test", "/b", "")
	check("KEEPALIVE-NOT-ACROSS-POOLS", connOf(otherPool) != connOf(first), "site 1 pool b on %s, pool a on %s", connOf(otherPool), connOf(first))
	otherSite := get("GET", "kb.test", "/1", "")
	check("KEEPALIVE-NOT-ACROSS-SITES", connOf(otherSite) != connOf(first) && connOf(otherSite) != connOf(otherPool),
		"site 2 on %s", connOf(otherSite))
	backA, backB := get("GET", "ka.test", "/3", ""), get("GET", "ka.test", "/b/2", "")
	check("KEEPALIVE-POOLS-KEEP-OWN", connOf(backA) == connOf(first) && connOf(backB) == connOf(otherPool),
		"pool a %s, pool b %s", connOf(backA), connOf(backB))
	off1, off2 := get("GET", "kc.test", "/1", ""), get("GET", "kc.test", "/2", "")
	check("KEEPALIVE-OFF", connOf(off1) != connOf(off2) && connOf(off1) != connOf(first), "%s, %s", connOf(off1), connOf(off2))

	// conditional routes
	for _, c := range []struct{ name, path, source, want string }{
		{"ROUTE-DEFAULT", "/x", "", "main"},
		{"ROUTE-PATH-PREFIX", "/api/v1?q=1", "", "api"},
		{"ROUTE-PATH-EXACT", "/api", "", "api"},
		{"ROUTE-PATH-NOT-BYTE-PREFIX", "/apiary", "", "main"}, // segment prefix: v7's byte prefix was a defect
		{"ROUTE-PATH-TRAILING-SLASH", "/static/a.css", "", "east"},
		{"ROUTE-PATH-TRAILING-SLASH-BARE", "/static", "", "main"},
		{"ROUTE-OTHER-REGION-DROPPED", "/west", "", "main"},
		{"ROUTE-CLIENT-CIDR", "/x", "127.0.0.9", "lan"},
		{"ROUTE-ORDER-PATH-BEFORE-CIDR", "/api", "127.0.0.9", "api"},
		{"ROUTE-REGION-AND-PATH", "/east/1", "", "east"},
		{"ROUTE-FALLBACK", "/dead", "", "spare"},
	} {
		a := get("GET", "route.test", c.path, c.source)
		check(c.name, a.status == 200 && strings.HasPrefix(a.body, c.want+" "), "%d %q", a.status, a.body)
	}

	// origin name via DNS
	a := get("GET", "dns.test", "/n", "")
	check("DNS-NAME", a.status == 200 && strings.HasPrefix(a.body, "named ") && named.count() == 1, "%d %q", a.status, a.body)

	// non-idempotent: a PUT whose first origin times out reading is not sent again
	before := fast.count()
	a = get("PUT", "put.test", "/r", "")
	check("PUT-NOT-RESENT", a.status == 504 && fast.count() == before && slow.count() == 1, "%d slow=%d fast=%d", a.status, slow.count(), fast.count()-before)
	a = get("GET", "put.test", "/r", "")
	check("GET-RETRIED", a.status == 200 && strings.HasPrefix(a.body, "fast "), "%d %q", a.status, a.body)

	// ingress source: the origin sees the node's configured source address
	a = get("GET", "bind.test", "/b", "")
	bound.mu.Lock()
	peers := strings.Join(bound.peers, ",")
	bound.mu.Unlock()
	check("INGRESS-BIND", a.status == 200 && peers == "127.0.0.77", "%d peer=%s", a.status, peers)
	sharedOrigin.mu.Lock()
	sharedPeers := strings.Join(sharedOrigin.peers, ",")
	sharedOrigin.mu.Unlock()
	check("NO-BIND-WITHOUT-INGRESS", !strings.Contains(sharedPeers, "127.0.0.77"), "peers %s", sharedPeers)
	// client address headers: never forgeable, a trusted proxy's chain kept
	forwardOrigin := fwdOrigin
	a = get("GET", "fwd.test", "/x", "", "X-Forwarded-For", "198.51.100.7", "X-Real-IP", "198.51.100.8", "X-Forwarded-Proto", "https")
	h := forwardOrigin.lastHeaders()
	check("XFF-NOT-FORGEABLE", a.status == 200 && h.Get("X-Forwarded-For") == "127.0.0.1" && h.Get("X-Real-IP") == "127.0.0.1" &&
		h.Get("X-Forwarded-Proto") == "http", "xff=%q real=%q proto=%q", h.Get("X-Forwarded-For"), h.Get("X-Real-IP"), h.Get("X-Forwarded-Proto"))
	a = get("GET", "fwd.test", "/x", "127.0.0.7", "X-Forwarded-For", "203.0.113.9", "X-Real-IP", "203.0.113.9")
	h = forwardOrigin.lastHeaders()
	check("XFF-TRUSTED-CHAIN", a.status == 200 && h.Get("X-Forwarded-For") == "203.0.113.9, 127.0.0.7" && h.Get("X-Real-IP") == "203.0.113.9",
		"xff=%q real=%q", h.Get("X-Forwarded-For"), h.Get("X-Real-IP"))
	a = get("GET", "fwd.test", "/x", "127.0.0.8", "X-Forwarded-For", "203.0.113.9")
	h = forwardOrigin.lastHeaders()
	check("XFF-UNTRUSTED-PEER", h.Get("X-Forwarded-For") == "127.0.0.8", "xff=%q", h.Get("X-Forwarded-For"))
	a = get("GET", "fwd.test", "/redirect", "")
	check("LOCATION-REWRITE", a.status == 302 && a.location == "http://fwd.test/next?x=1", "%d %q", a.status, a.location)

	// follow_port + visitor_port (tp-b3a-be): each listener's port reaches the
	// origin (127.0.0.2 on that port; the edge listens on 127.0.0.1), and the
	// Host carries it; without follow_port the endpoint's own port is used and
	// visitor_port still sends the visited port
	for _, port := range []int{edge, edge2} {
		startOrigin(fmt.Sprintf("follow%d", port), fmt.Sprintf("127.0.0.2:%d", port))
	}
	unused := startOrigin("unused", "127.0.0.2:19561")
	vport := startOrigin("vport", "127.0.0.1:19562")
	for _, port := range []int{edge, edge2} {
		a = getOn(port, "GET", "follow.test", "/f", "")
		want := fmt.Sprintf("follow%d 1 follow.test:%d /f", port, port)
		check(fmt.Sprintf("FOLLOW-PORT-%d", port), a.status == 200 && a.body == want, "%d %q, want %q", a.status, a.body, want)
	}
	check("FOLLOW-PORT-NOT-ENDPOINT-PORT", unused.count() == 0, "endpoint port got %d requests", unused.count())
	a = get("GET", "vport.test", "/v", "")
	check("VISITOR-PORT-HOST", a.status == 200 && a.body == fmt.Sprintf("vport 1 vport.test:%d /v", edge) && vport.count() == 1,
		"%d %q", a.status, a.body)
	a = get("GET", "fwd.test", "/h", "")
	check("VISITOR-HOST-NO-PORT", a.status == 200 && strings.Contains(a.body, " fwd.test /h"), "%d %q", a.status, a.body)
	lines := n.errorLog("cdnca origin")
	check("NO-ORIGIN-ERRORS", len(lines) == 0, "%d error.log lines %v", len(lines), lines)
}

func measure() {
	if *scale == 0 {
		return
	}
	algorithms := []string{"round_robin", "ip_hash", "url_hash", "least_conn", "random"}
	sites := make([]edgesite.Site, 0, *scale)
	for number := 1; number <= *scale; number++ {
		origin := edgesite.Origin{DefaultPoolID: "p0", Routes: []edgesite.Route{}}
		for p := 0; p < *pools; p++ {
			var endpoints []edgesite.Endpoint
			for e := 0; e < 4; e++ {
				endpoints = append(endpoints, edgesite.Endpoint{ID: fmt.Sprintf("e%d", e), Scheme: "http",
					Host: fmt.Sprintf("10.%d.%d.%d", number%250, p, e+1), Port: 80, Weight: e + 1})
			}
			id := fmt.Sprintf("p%d", p)
			origin.Pools = append(origin.Pools, edgesite.Pool{ID: id, Kind: edgesite.PoolOrigin,
				Algorithm: algorithms[(number+p)%len(algorithms)], Endpoints: endpoints, Retry: retry(2)})
			if p > 0 {
				origin.Routes = append(origin.Routes, edgesite.Route{ID: "r" + id, Priority: 100 - p,
					PathPrefix: fmt.Sprintf("/p%d", p), PoolID: id})
			}
		}
		sites = append(sites, site(100000+number, fmt.Sprintf("s%d.scale.test", number), origin))
	}
	started := time.Now()
	n, err := startNode(sites, edgeskeleton.Node{Region: *region})
	if err != nil {
		fmt.Println("FAIL scale start", err)
		failures++
		return
	}
	fmt.Printf("SCALE sites=%d pools_per_site=%d endpoints_per_pool=4 activation=%s\n", *scale, *pools, time.Since(started).Round(time.Millisecond))
	// pass 1 compiles every site's plan (first request of a site on a
	// worker; url_hash builds its ring on first selection), pass 2 is the
	// steady state (plan cached by digest)
	for _, pass := range []string{"first-request", "steady"} {
		response, err := http.Get(fmt.Sprintf("http://127.0.0.1:18199/bench?n=%d&count=%d&port=%d&prefix=s%%d.scale.test", *scale, *scale, edge))
		if err != nil {
			fmt.Println("FAIL bench", err)
			failures++
			return
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if !json.Valid(raw) {
			log, _ := os.ReadFile(filepath.Join(n.root, goldendyn.SharedDirectory, "error.log"))
			fmt.Println("FAIL bench", string(raw), tailLines(string(log), 10))
			failures++
			return
		}
		fmt.Printf("SCALE %s %s\n", pass, strings.TrimSpace(string(raw)))
	}
	_ = n
}

func main() {
	flag.Parse()
	functional()
	measure()
	_ = exec.Command("openresty", "-p", *state+"/", "-c", "nginx.conf", "-s", "stop").Run()
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}

func tailLines(value string, count int) string {
	lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-count):], "\n")
}
