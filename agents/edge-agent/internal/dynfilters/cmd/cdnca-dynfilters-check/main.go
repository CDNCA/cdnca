// Command cdnca-dynfilters-check is the dynamic routing D9/D10 acceptance
// against a real OpenResty (tests/dynroute-filters/run.sh starts it inside
// the node runtime image, one --rm --network none container):
//
//   - errorpage: the filter replacement against the v7 shape on the same
//     OpenResty (error_page + proxy_intercept_errors + errorpage/handler.lua
//     with the same pages), byte for byte over raw HTTP/1.1 for every PoC §4
//     origin fixture x GET/HEAD x with/without gzip, then HTTP/2 and HTTP/3;
//     module pages and server rewrite exits are never replaced; theme style
//     CSP; a missing asset falls back to the built-in page;
//   - order: the header_filter slots (error page, HTTP policy, cache status,
//     HSTS, Alt-Svc) on normal and replaced responses;
//   - upload: client_max_body_size from the site object (native patch 23) on
//     h1/h2/h3 with and without Content-Length, at the limit and one over,
//     the node system value for a site without its own;
//   - connections: the package budget shared by two sites under concurrency
//     (exactly max in flight, the rest 503), ngx.exec counted once, release
//     on completion, 0 = always 503;
//   - market: the market supply limits (ADR 0012 ML-07) per subscription:
//     TCP connections, new connections per second and QPS under throttle and
//     pause (both enforce on the node), stop (every request 503 on h1/h2/h3),
//     isolation between subscriptions, QUIC not counted as a TCP
//     connection, the per minute statistics on the control socket;
//   - share: the market node share re-split on the serving node count, stop
//     and monthly traffic throttle holds, pause serving (ML-08);
//   - traffic: the over-limit page, ACME exempt, removal without reload;
//   - response: site response rules: status / header
//     conditions, header actions on origin and cached responses, log,
//     error page and block on origin responses only, not stored, h2/h3.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
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

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/errorpage"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
)

var (
	luaRoot   = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	confPath  = flag.String("conf", "/d9/nginx.conf", "skeleton template")
	stateRoot = flag.String("state", "/tmp/d9state", "state directory")
	workers   = flag.Int("workers", 2, "worker_processes")
	probeBin  = flag.String("probe", "/d9/probe", "HTTP/2 + HTTP/3 client")
	only      = flag.String("only", "", "comma-separated checks")
	// ML-07: the market minutes also go the agent's way (dyntelemetry
	// source -> event spool -> telemetry publisher); the wire records are
	// written here for the gateway / control-api / ClickHouse leg.
	recordsOut = flag.String("records", "", "write the subscription minute wire records (JSON lines)")
)

const (
	scope  = "0d9a0000-0000-4000-8000-000000000001"
	tenant = "0d9a0000-0000-4000-8000-000000000002"
	plain  = 18090
	secure = 18443
	v7Port = 17090
	sitePg = "0d9a0000-0000-4000-8000-000000000101" // pages
	siteNo = "0d9a0000-0000-4000-8000-000000000102" // no pages
	siteUp = "0d9a0000-0000-4000-8000-000000000103" // upload limit
	siteC1 = "0d9a0000-0000-4000-8000-000000000104" // connections, subscription A
	siteC2 = "0d9a0000-0000-4000-8000-000000000105" // connections, subscription A
	siteC0 = "0d9a0000-0000-4000-8000-000000000106" // connections 0
	siteTx = "0d9a0000-0000-4000-8000-000000000107" // traffic exceeded
	siteBw = "0d9a0000-0000-4000-8000-000000000108" // bandwidth, subscription B
	subB   = "0d9a0000-0000-4000-8000-0000000000b1"
	// bandwidthBPS: 800 kbit/s = 100 000 B/s for the subscription.
	bandwidthBPS = 800_000
	subA         = "0d9a0000-0000-4000-8000-0000000000a1"
	subZero      = "0d9a0000-0000-4000-8000-0000000000a0"
	certVer      = "0d9a0000-0000-4000-8000-0000000000c1"
	// systemMaxBody is the node system upload limit (sites without their own).
	systemMaxBody = 4096
	siteMaxBody   = 1024
	connMax       = 4
	// Market supply limits (ADR 0012 ML-07), one subscription per metric
	// and action; throttle and pause render the same node limits (pause is
	// DNS only), stop adds stopped.
	marketConns = 3
	marketNew   = 5
	marketQPS   = 10
)

// marketSite is one market check site: metric x action.
type marketSite struct {
	id, host, sub, metric, action string
}

var marketSites = func() []marketSite {
	var sites []marketSite
	index := 0
	for _, metric := range []string{"conn", "new", "qps"} {
		for _, action := range []string{"throttle", "pause", "stop"} {
			index++
			sites = append(sites, marketSite{id: fmt.Sprintf("0d9a0000-0000-4000-8000-0000000002%02d", index),
				host: metric + "-" + action + ".market.test", sub: fmt.Sprintf("0d9a0000-0000-4000-8000-0000000003%02d", index),
				metric: metric, action: action})
		}
	}
	// a second site of conn-throttle's subscription, and another
	// subscription with the same TCP connection limit (isolation)
	sites = append(sites, marketSite{id: "0d9a0000-0000-4000-8000-000000000220", host: "conn-throttle2.market.test",
		sub: sites[0].sub, metric: "conn", action: "throttle"},
		marketSite{id: "0d9a0000-0000-4000-8000-000000000221", host: "conn-other.market.test",
			sub: "0d9a0000-0000-4000-8000-000000000321", metric: "conn", action: "throttle"})
	return sites
}()

func (m marketSite) connections() *edgesite.Connections {
	limit := &edgesite.Connections{SubscriptionID: m.sub, Max: -1, Stopped: m.action == "stop"}
	switch m.metric {
	case "conn":
		limit.MaxConnections = marketConns
	case "new":
		limit.NewPerSecond = marketNew
	case "qps":
		limit.QPS = marketQPS
	}
	return limit
}

var failures int

func check(name string, ok bool, format string, args ...any) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("%s %s %s\n", status, name, fmt.Sprintf(format, args...))
}

// ------------------------------------------------------------ pages

// The pages of the "pages" site: what the v7 policy and the site object
// both carry. The 502/504 pages are global (edge_connect), the rest site.
var themeStyle = "body { background-color: #f5f7f9; color: #515a6e; }\n"

var pageBodies = map[string]string{
	"origin_response|403": "<!doctype html><html><head><title>403</title></head><body><p>site 403</p></body></html>",
	"origin_response|404": "<!doctype html><html><head><title>404</title><style>" + themeStyle + "</style></head><body><main><h1>site 404</h1></main></body></html>",
	"origin_response|500": "site origin 500\n",
	"origin_response|503": "{\"error\":\"site origin 503\"}",
	"edge_route|403":      "site edge 403\n",
	"edge_route|413":      "site edge 413\n",
	"edge_route|503":      "site edge 503\n",
	"edge_connect|502":    "global connect 502\n",
	"edge_connect|504":    "global connect 504\n",
}

func pageMIME(key string) string {
	body := pageBodies[key]
	switch {
	case strings.HasPrefix(body, "<!doctype"):
		return "text/html"
	case strings.HasPrefix(body, "{"):
		return "application/json"
	}
	return "text/plain"
}

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// v7Policy is the same pages as the v7 errorpage policy, compiled by the
// agent's own compiler (what the v7 site runtime copies into its release).
func v7Policy() (errorpage.Artifact, []int) {
	rule := func(id, key string) errorpage.Rule {
		parts := strings.Split(key, "|")
		status, _ := strconv.Atoi(parts[1])
		body := pageBodies[key]
		return errorpage.Rule{ID: id, Category: errorpage.Category(parts[0]), Match: errorpage.StatusMatch{Codes: []int{status}},
			Resource: errorpage.Resource{MIMEType: pageMIME(key), Size: int64(len(body)), SHA256: digestOf(body), Inline: &body}}
	}
	var site, global []errorpage.Rule
	keys := make([]string, 0, len(pageBodies))
	for key := range pageBodies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for index, key := range keys {
		id := fmt.Sprintf("r%02d", index)
		if strings.HasPrefix(key, "edge_connect") {
			global = append(global, rule(id, key))
		} else {
			site = append(site, rule(id, key))
		}
	}
	artifact, err := errorpage.Compile(errorpage.Policy{Schema: errorpage.SchemaV1, Version: "d9", Revision: 1,
		Global: errorpage.Scope{Rules: global}, Sites: []errorpage.SiteScope{{SiteKey: sitePg, Rules: site}}}, "/")
	if err != nil {
		panic(err)
	}
	statuses := map[int]bool{}
	for _, key := range keys {
		status, _ := strconv.Atoi(strings.Split(key, "|")[1])
		statuses[status] = true
	}
	var list []int
	for status := range statuses {
		list = append(list, status)
	}
	sort.Ints(list)
	return artifact, list
}

// sitePages is the same pages as site object error_pages, built with the
// control plane's own rule merge (ErrorPagesFor).
func sitePages(n *node) []edgesite.ErrorPage {
	var global, site []edgesite.ErrorPageRule
	for key, body := range pageBodies {
		parts := strings.Split(key, "|")
		status, _ := strconv.Atoi(parts[1])
		digest := digestOf(body)
		n.putObject([]byte(body))
		rule := edgesite.ErrorPageRule{ID: "rule." + strings.ReplaceAll(key, "|", "."), Category: parts[0], Codes: []int{status},
			MIMEType: pageMIME(key), Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset, ID: "0d9a0000-0000-4000-8000-0000000000e1", Revision: 1, SHA256: digest}}
		if strings.Contains(body, "<style>") {
			rule.StyleHash = errorpagestyle.SourceHash(themeStyle)
		}
		if parts[0] == edgesite.ErrorEdgeConnect {
			global = append(global, rule)
		} else {
			site = append(site, rule)
		}
	}
	// a theme's block page (sec-followup P13): only the node's own 429
	// block gets it, an origin or plain edge 429 is not intercepted
	n.putObject([]byte(themeBlock429))
	global = append(global, edgesite.ErrorPageRule{ID: "theme.edge_route.429", Category: edgesite.ErrorEdgeRoute, Codes: []int{429},
		MIMEType: "text/plain", Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset, ID: "0d9a0000-0000-4000-8000-0000000000e2",
			Revision: 1, SHA256: digestOf(themeBlock429)}})
	pages, err := edgesite.ErrorPagesFor(global, site)
	if err != nil {
		panic(err)
	}
	return pages
}

const themeBlock429 = "theme block 429\n"

// ------------------------------------------------------------ node

type node struct {
	activator *siteindex.Activator
	objects   siteindex.ObjectDir
	pool      dyntls.Pool
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func openresty(args ...string) error {
	command := exec.Command("openresty", append([]string{"-p", filepath.Join(*stateRoot, "nginx") + "/", "-c", "nginx.conf"}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

func newNode() (*node, error) {
	_ = os.RemoveAll(*stateRoot)
	for _, dir := range []string{"nginx/logs", "run", "site-index", "site-objects", "tls-pool"} {
		if err := os.MkdirAll(filepath.Join(*stateRoot, dir), 0o755); err != nil {
			return nil, err
		}
	}
	gid := workerGID()
	if err := dyntls.WritePlaceholder(filepath.Join(*stateRoot, "placeholder.crt"), filepath.Join(*stateRoot, "placeholder.key"), gid); err != nil {
		return nil, err
	}
	artifact, statuses := v7Policy()
	if err := os.WriteFile(filepath.Join(*stateRoot, "v7-policy.lua"), artifact.RuntimeLua, 0o644); err != nil {
		return nil, err
	}
	codes := make([]string, len(statuses))
	for index, status := range statuses {
		codes[index] = strconv.Itoa(status)
	}
	template, err := os.ReadFile(*confPath)
	if err != nil {
		return nil, err
	}
	conf := strings.NewReplacer("__WORKERS__", strconv.Itoa(*workers), "__LUA_ROOT__", *luaRoot, "__STATE__", *stateRoot,
		"__ORIGIN_PORT__", strconv.Itoa(originPort), "__SYSTEM_MAX_BODY__", strconv.Itoa(systemMaxBody),
		"__V7_MAX_BODY__", strconv.Itoa(siteMaxBody), "__V7_STATUSES__", strings.Join(codes, " ")).Replace(string(template))
	if err := os.WriteFile(filepath.Join(*stateRoot, "nginx", "nginx.conf"), []byte(conf), 0o644); err != nil {
		return nil, err
	}
	// The edge's own refusals of the other D tasks (ACL/WAF 403, a
	// security 503, an edge 403 for a status without a page), driven by a
	// request header, in the location as v7 renders them.
	edge := "rewrite_by_lua_block {\n" +
		"  local status = tonumber(ngx.req.get_headers()['x-test-edge-exit'])\n" +
		"  if status then return ngx.exit(status) end\n" +
		"  if ngx.req.get_headers()['x-test-block-exit'] then\n" +
		"    ngx.var.cdnca_security_block_page = '1' ngx.header['Retry-After'] = '3' return ngx.exit(403)\n" +
		"  end\n" +
		"  if ngx.req.get_headers()['x-test-module-page'] then\n" +
		"    ngx.status = 403 ngx.header['Content-Type'] = 'text/plain' ngx.header['Cache-Control'] = 'no-store'\n" +
		"    ngx.say('Request blocked') return ngx.exit(403)\n" +
		"  end\n" +
		"}\n"
	if err := os.WriteFile(filepath.Join(*stateRoot, "edge.conf"), []byte(edge), 0o644); err != nil {
		return nil, err
	}
	if err := openresty(); err != nil {
		return nil, err
	}
	control := siteindex.NewControl(filepath.Join(*stateRoot, "run", "cdnca-site-admin.sock"))
	objects := siteindex.ObjectDir{Root: filepath.Join(*stateRoot, "site-objects"), Access: siteindex.Access{GID: gid}}
	n := &node{objects: objects, pool: dyntls.Pool{Root: filepath.Join(*stateRoot, "tls-pool"), GID: gid},
		activator: &siteindex.Activator{Control: control, Objects: objects,
			Files: siteindex.Files{Root: filepath.Join(*stateRoot, "site-index"), Access: siteindex.Access{GID: gid}}}}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := control.Status(context.Background()); err == nil {
			return n, nil
		} else if time.Now().After(deadline) {
			return nil, err
		}
	}
}

func (n *node) stop() { _ = openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

func (n *node) putObject(content []byte) string {
	digest := edgesite.Digest(content)
	if err := n.objects.Put(digest, content); err != nil {
		panic(err)
	}
	return digest
}

func (n *node) activate(sites []edgesite.Site) error {
	objects := make([]siteindex.Object, 0, len(sites))
	for _, site := range sites {
		raw, err := edgesite.Encode(site)
		if err != nil {
			return fmt.Errorf("site %s: %w", site.SiteID, err)
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
	_, err = n.activator.WaitHealthy(context.Background(), activation.Generation, siteindex.ProbesFor(objects), 10*time.Second)
	return err
}

// ------------------------------------------------------------ sites

func makeSite(id, primary string, revision int64) edgesite.Site {
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: id, Revision: revision,
		Hosts: edgesite.Hosts{Primary: primary, Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: plain, AddressFamily: edgesite.FamilyIPv4},
			{Port: secure, AddressFamily: edgesite.FamilyIPv4, HTTP2: true, HTTP3: true,
				TLS: &edgesite.TLS{CertificateVersionID: certVer, Protocols: []string{"TLSv1.2", "TLSv1.3"}}}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: originPort, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 5000, TotalBudgetMS: 10000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
	}
}

func baseSites(n *node) []edgesite.Site {
	pages := makeSite(sitePg, "pages.example.test", 1)
	pages.Errors = sitePages(n)
	pages.Limits.MaxBodyBytes = siteMaxBody
	pages.HSTS = &edgesite.HSTS{MaxAgeSeconds: 31536000, IncludeSubdomains: true}
	upload := makeSite(siteUp, "upload.example.test", 1)
	upload.Limits.MaxBodyBytes = siteMaxBody
	c1 := makeSite(siteC1, "conn1.example.test", 1)
	c1.Limits.Connections = &edgesite.Connections{SubscriptionID: subA, Max: connMax}
	c2 := makeSite(siteC2, "conn2.example.test", 1)
	c2.Limits.Connections = &edgesite.Connections{SubscriptionID: subA, Max: connMax}
	c0 := makeSite(siteC0, "conn0.example.test", 1)
	c0.Limits.Connections = &edgesite.Connections{SubscriptionID: subZero, Max: 0}
	bw := makeSite(siteBw, "bw.example.test", 1)
	bw.Limits.Connections = &edgesite.Connections{SubscriptionID: subB, Max: -1, BandwidthBPS: bandwidthBPS}
	sites := []edgesite.Site{pages, makeSite(siteNo, "nopages.example.test", 1), upload, c1, c2, c0,
		makeSite(siteTx, "traffic.example.test", 1), bw}
	for _, market := range marketSites {
		site := makeSite(market.id, market.host, 1)
		site.Limits.Connections = market.connections()
		sites = append(sites, site)
	}
	return sites
}

func (n *node) installCertificate() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	names := []string{"pages.example.test", "nopages.example.test", "upload.example.test", "conn1.example.test",
		"conn2.example.test", "conn0.example.test", "traffic.example.test", "bw.example.test"}
	for _, market := range marketSites {
		names = append(names, market.host)
	}
	names = append(names, shareHost, respHost)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := n.pool.PutCertificate(certVer, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		panic(err)
	}
}

// ------------------------------------------------------------ clients

// exchange is a normalized raw HTTP/1.1 exchange (PoC §4 norm()): status,
// framing, headers without the volatile ones, body.
type exchange struct {
	Status  int               `json:"status"`
	Framing string            `json:"framing"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Err     string            `json:"err,omitempty"`
}

func raw(port int, method, host, path string, headers map[string]string, body string) exchange {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return exchange{Err: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&request, "%s: %s\r\n", name, headers[name])
	}
	if body != "" {
		fmt.Fprintf(&request, "Content-Length: %d\r\n", len(body))
	}
	request.WriteString("Connection: close\r\n\r\n" + body)
	if _, err := io.WriteString(conn, request.String()); err != nil {
		return exchange{Err: err.Error()}
	}
	all, _ := io.ReadAll(conn)
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(all)), &http.Request{Method: method})
	if err != nil {
		return exchange{Err: "unparsable: " + err.Error()}
	}
	content, bodyErr := io.ReadAll(response.Body)
	result := exchange{Status: response.StatusCode, Headers: map[string]string{}}
	switch {
	case bodyErr != nil:
		result.Framing = "truncated"
	case len(response.TransferEncoding) > 0:
		result.Framing = "chunked"
	case response.ContentLength >= 0:
		result.Framing = "length"
	default:
		result.Framing = "close"
	}
	if response.Header.Get("Content-Encoding") == "gzip" {
		result.Body = fmt.Sprintf("(gzip %d bytes)", len(content))
	} else {
		result.Body = string(content)
	}
	for name, values := range response.Header {
		switch strings.ToLower(name) {
		case "date", "server", "connection", "keep-alive":
			continue
		}
		result.Headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return result
}

func (e exchange) String() string {
	encoded, _ := json.Marshal(e)
	return string(encoded)
}

type probeResult struct {
	Status  int               `json:"status"`
	Proto   string            `json:"proto"`
	Headers map[string]string `json:"headers"`
	BodyLen int               `json:"body_len"`
	BodySHA string            `json:"body_sha"`
	Body    string            `json:"body"`
	Reset   bool              `json:"reset"`
	Err     string            `json:"err"`
}

func probe(proto, host, path string, args ...string) probeResult {
	command := append([]string{"-proto", proto, "-url", fmt.Sprintf("https://127.0.0.1:%d%s", secure, path), "-host", host}, args...)
	output, err := exec.Command(*probeBin, command...).Output()
	var result probeResult
	if err != nil || json.Unmarshal(bytes.TrimSpace(output), &result) != nil {
		return probeResult{Err: fmt.Sprintf("%v %s", err, output)}
	}
	return result
}

// ------------------------------------------------------------ checks

var fixtures = []string{"/ok", "/404", "/404empty", "/404chunked", "/404gzip", "/404partial", "/404chunkcut", "/403", "/500",
	"/502", "/503", "/410", "/200partial", "/dead", "/slow"}

func checkErrorPages(n *node) {
	fmt.Println("== errorpage: missing asset falls back to the built-in page")
	// the activator refuses an object whose references are missing, so the
	// asset disappears after activation (damaged or removed under the node)
	if err := n.objects.Remove(digestOf(pageBodies["origin_response|500"])); err != nil {
		check("remove-asset", false, "%v", err)
		return
	}
	missing := raw(plain, "GET", "pages.example.test", "/500", nil, "")
	check("missing-asset-fallback", missing.Status == 500 && missing.Body == "Service temporarily unavailable.\n" &&
		missing.Headers["content-type"] == "text/plain; charset=utf-8", "%s", missing)
	n.putObject([]byte(pageBodies["origin_response|500"]))
	// the worker LRU keeps "missing" for the digest only while unread: a
	// fresh worker read finds the object again

	fmt.Println("== errorpage: filter vs v7 (raw HTTP/1.1)")
	known := 0
	for _, path := range fixtures {
		for _, method := range []string{"GET", "HEAD"} {
			for _, encoding := range []string{"", "gzip"} {
				headers := map[string]string{"X-Test-Site": sitePg}
				if encoding != "" {
					headers["Accept-Encoding"] = encoding
				}
				v7 := raw(v7Port, method, "pages.example.test", path, headers, "")
				dyn := raw(plain, method, "pages.example.test", path, headers, "")
				name := fmt.Sprintf("eq%s-%s-%s", strings.ReplaceAll(path, "/", "-"), method, map[string]string{"": "plain", "gzip": "gzip"}[encoding])
				delete(dyn.Headers, "strict-transport-security") // HTTPS only; plain port never sends it
				if v7.String() == dyn.String() {
					check(name, true, "%d %s %q", dyn.Status, dyn.Framing, short(dyn.Body))
					continue
				}
				// PoC §4 known difference: a replaced page answering HEAD with
				// Accept-Encoding: gzip (v7 keeps Content-Length, the filter
				// path gzips as for the GET).
				if method == "HEAD" && encoding == "gzip" && dyn.Headers["content-encoding"] == "gzip" && v7.Headers["content-length"] != "" {
					a, b := v7, dyn
					a.Headers, b.Headers = clone(v7.Headers), clone(dyn.Headers)
					delete(a.Headers, "content-length")
					delete(b.Headers, "content-encoding")
					delete(b.Headers, "vary")
					a.Framing, b.Framing, b.Body = "", "", a.Body // no body either way
					if a.String() == b.String() {
						known++
						fmt.Printf("KNOWN %s HEAD+gzip: v7 Content-Length %s, filter Content-Encoding gzip\n", name, v7.Headers["content-length"])
						continue
					}
				}
				check(name, false, "\n  v7 : %s\n  dyn: %s", v7, dyn)
			}
		}
	}
	fmt.Printf("known HEAD+gzip differences: %d\n", known)

	fmt.Println("== errorpage: edge refusals")
	for _, status := range []string{"403", "503", "404", "429"} {
		headers := map[string]string{"X-Test-Site": sitePg, "X-Test-Edge-Exit": status}
		v7 := raw(v7Port, "GET", "pages.example.test", "/ok", headers, "")
		dyn := raw(plain, "GET", "pages.example.test", "/ok", headers, "")
		check("edge-exit-"+status, v7.String() == dyn.String(), "v7 %d %q / dyn %d %q", v7.Status, short(v7.Body), dyn.Status, short(dyn.Body))
	}
	headers := map[string]string{"X-Test-Site": sitePg, "X-Test-Module-Page": "1"}
	v7 := raw(v7Port, "GET", "pages.example.test", "/ok", headers, "")
	dyn := raw(plain, "GET", "pages.example.test", "/ok", headers, "")
	check("module-page-kept", v7.String() == dyn.String() && strings.Contains(dyn.Body, "Request blocked"),
		"a module's own page is never replaced (v7 error_page did not see it): %d %q", dyn.Status, short(dyn.Body))
	dyn = raw(plain, "GET", "pages.example.test", "/ok", map[string]string{"X-Test-Server-Exit": "1"}, "")
	check("server-rewrite-exit-kept", dyn.Status == 429 && strings.Contains(dyn.Body, "429 Too Many Requests"),
		"an exit before location selection keeps nginx's page: %d %q", dyn.Status, short(dyn.Body))
	// sec-followup P13: the node's own blocks get the branded pages, also a
	// CC 429 decided in server_rewrite, and keep Retry-After
	dyn = raw(plain, "GET", "pages.example.test", "/ok", map[string]string{"X-Test-Server-Block": "1"}, "")
	check("block-429-theme-page", dyn.Status == 429 && dyn.Body == themeBlock429 && dyn.Headers["retry-after"] == "7",
		"a CC block before routed() gets the theme block page: %s", dyn)
	dyn = raw(plain, "GET", "pages.example.test", "/ok", map[string]string{"X-Test-Block-Exit": "1"}, "")
	check("block-403-site-page", dyn.Status == 403 && dyn.Body == pageBodies["edge_route|403"] && dyn.Headers["retry-after"] == "3",
		"a WAF/ACL block gets the site's edge_route 403 page: %s", dyn)
	v7 = raw(v7Port, "POST", "pages.example.test", "/ok", map[string]string{"X-Test-Site": sitePg}, strings.Repeat("x", siteMaxBody+1))
	dyn = raw(plain, "POST", "pages.example.test", "/ok", nil, strings.Repeat("x", siteMaxBody+1))
	check("413-replaced", v7.String() == dyn.String() && dyn.Body == pageBodies["edge_route|413"], "v7 %s / dyn %s", v7, dyn)

	fmt.Println("== errorpage: page content")
	dyn = raw(plain, "GET", "pages.example.test", "/404", nil, "")
	check("theme-csp", dyn.Headers["content-security-policy"] ==
		"default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox; style-src '"+errorpagestyle.SourceHash(themeStyle)+"'",
		"%s", dyn.Headers["content-security-policy"])
	check("no-origin-leak", dyn.Headers["set-cookie"] == "" && dyn.Headers["etag"] == "" && dyn.Headers["x-origin-header"] == "",
		"%v", dyn.Headers)
	dyn = raw(plain, "GET", "nopages.example.test", "/404", nil, "")
	check("no-pages-passthrough", dyn.Status == 404 && dyn.Body == "origin-404-body\n" && dyn.Headers["set-cookie"] == "origin=1; Path=/", "%s", dyn)
	dyn = raw(plain, "GET", "pages.example.test", "/410", nil, "")
	check("unlisted-status-passthrough", dyn.Body == "origin-410-body-passthrough\n", "%s", dyn)

	fmt.Println("== errorpage: HTTP/2 and HTTP/3")
	for _, proto := range []string{"h2", "h3"} {
		for _, path := range []string{"/404", "/404chunked", "/404partial", "/404chunkcut", "/200partial", "/dead", "/410", "/503"} {
			for _, method := range []string{"GET", "HEAD"} {
				result := probe(proto, "pages.example.test", path, "-method", method)
				want := expectedH(path, method)
				got := fmt.Sprintf("%d len=%d sha=%s reset=%v", result.Status, result.BodyLen, result.BodySHA[:min(12, len(result.BodySHA))], result.Reset)
				if want == "truncated" {
					// An unpaged origin response cut short: the stream is reset
					// (h2 after the 10 bytes, h3 may refuse it before the
					// client sees the headers); never a completed answer.
					got = map[bool]string{true: "truncated", false: got}[result.Reset || result.Err != ""]
				} else if result.Err != "" {
					got = result.Err
				}
				check(fmt.Sprintf("%s%s-%s", proto, strings.ReplaceAll(path, "/", "-"), method), got == want, "got %s want %s", got, want)
			}
		}
	}

}

// expectedH: what h2/h3 must show for a fixture (the v7 behaviour PoC §4
// recorded on h2: replaced pages complete with their length, an unpaged
// partial 200 is reset, statuses without a page pass the origin through).
func expectedH(path, method string) string {
	page := func(key string) string {
		body := pageBodies[key]
		if method == "HEAD" {
			body = ""
		}
		sum := sha256.Sum256([]byte(body))
		return fmt.Sprintf("len=%d sha=%s reset=false", len(body), hex.EncodeToString(sum[:])[:12])
	}
	switch path {
	case "/404", "/404chunked", "/404partial", "/404chunkcut":
		return "404 " + page("origin_response|404")
	case "/503":
		return "503 " + page("origin_response|503")
	case "/dead":
		return "502 " + page("edge_connect|502")
	case "/410":
		body := "origin-410-body-passthrough\n"
		if method == "HEAD" {
			body = ""
		}
		sum := sha256.Sum256([]byte(body))
		return fmt.Sprintf("410 len=%d sha=%s reset=false", len(body), hex.EncodeToString(sum[:])[:12])
	case "/200partial":
		if method == "HEAD" {
			sum := sha256.Sum256(nil)
			return fmt.Sprintf("200 len=0 sha=%s reset=false", hex.EncodeToString(sum[:])[:12])
		}
		return "truncated"
	}
	return "?"
}

func checkOrder() {
	fmt.Println("== header_filter order")
	extra := []string{"-header", "X-Test-Policy-Header:policy", "-header", "X-Test-Cache-Status:HIT"}
	result := probe("h2", "pages.example.test", "/ok", extra...)
	h := result.Headers
	check("normal-all-slots", result.Status == 200 && h["x-policy"] == "policy" && h["x-cdn-cache"] == "HIT" &&
		h["strict-transport-security"] == "max-age=31536000; includeSubDomains" && h["alt-svc"] == `h3=":18443"; ma=86400`,
		"%d %v", result.Status, h)
	result = probe("h2", "pages.example.test", "/404", extra...)
	h = result.Headers
	check("replaced-page-slots", result.Status == 404 && h["x-policy"] == "" && h["x-cdn-cache"] == "HIT" &&
		h["strict-transport-security"] != "" && h["alt-svc"] != "" && h["cache-control"] == "no-store, max-age=0",
		"policy headers skipped, node headers kept: %v", h)
	result = probe("h3", "pages.example.test", "/ok")
	check("h3-hsts-alt-svc", result.Status == 200 && result.Proto == "HTTP/3.0" && result.Headers["strict-transport-security"] != "" &&
		result.Headers["alt-svc"] != "", "%s %v", result.Proto, result.Headers)
	plainAnswer := raw(plain, "GET", "pages.example.test", "/ok", nil, "")
	check("no-hsts-on-plain", plainAnswer.Headers["strict-transport-security"] == "" && plainAnswer.Headers["alt-svc"] == "",
		"RFC 6797 §7.2: %v", plainAnswer.Headers)
	result = probe("h2", "nopages.example.test", "/ok")
	check("no-hsts-without-setting", result.Headers["strict-transport-security"] == "", "%v", result.Headers)
}

func checkUpload() {
	fmt.Println("== upload limit (native patch 23, $cdnca_site_max_body)")
	for _, test := range []struct {
		host  string
		limit int
	}{{"upload.example.test", siteMaxBody}, {"nopages.example.test", systemMaxBody}} {
		for _, proto := range []string{"h1", "h2", "h3"} {
			for _, stream := range []bool{false, true} {
				for _, size := range []int{test.limit, test.limit + 1} {
					want := 200
					if size > test.limit {
						want = 413
					}
					got := 0
					if proto == "h1" {
						got = h1Upload(test.host, size, stream)
					} else {
						args := []string{"-method", "POST", "-body-bytes", strconv.Itoa(size)}
						if stream {
							args = append(args, "-stream")
						}
						got = probe(proto, test.host, "/up", args...).Status
					}
					mode := map[bool]string{false: "len", true: "stream"}[stream]
					check(fmt.Sprintf("upload-%s-%s-%s-%d", strings.Split(test.host, ".")[0], proto, mode, size), got == want, "got %d want %d", got, want)
				}
			}
		}
	}
}

// h1Upload posts size bytes over TLS HTTP/1.1, chunked when stream.
func h1Upload(host string, size int, stream bool) int {
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", secure), &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) // test certificate
	if err != nil {
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	body := strings.Repeat("x", size)
	if stream {
		fmt.Fprintf(conn, "POST /up HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", host, size, body)
	} else {
		fmt.Fprintf(conn, "POST /up HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", host, size, body)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0
	}
	return response.StatusCode
}

func checkConnections() {
	fmt.Println("== package connections")
	for round := 0; round < 3; round++ {
		const total = 20
		var wait sync.WaitGroup
		statuses := make([]int, total)
		for index := range statuses {
			wait.Add(1)
			go func() {
				defer wait.Done()
				host := "conn1.example.test"
				if index%2 == 1 {
					host = "conn2.example.test" // the same subscription, another site
				}
				statuses[index] = raw(plain, "GET", host, "/ok", map[string]string{"X-Test-Hold-Ms": "800"}, "").Status
			}()
		}
		wait.Wait()
		counts := map[int]int{}
		for _, status := range statuses {
			counts[status]++
		}
		check(fmt.Sprintf("conn-shared-round%d", round), counts[200] == connMax && counts[503] == total-connMax,
			"%d concurrent over two sites of one subscription (max %d): %v", total, connMax, counts)
		time.Sleep(100 * time.Millisecond)
		left := strings.TrimSpace(raw(plain, "GET", "conn1.example.test", "/__inflight?sub="+subA, nil, "").Body)
		check(fmt.Sprintf("conn-released-round%d", round), left == "0", "in flight after the round: %s", left)
	}
	exec := raw(plain, "GET", "conn1.example.test", "/__exec?sub="+subA, nil, "")
	check("conn-exec-once", exec.Status == 200 && strings.TrimSpace(exec.Body) == "in-flight 1", "%s", exec)
	zero := raw(plain, "GET", "conn0.example.test", "/ok", nil, "")
	check("conn-zero-503", zero.Status == 503 && strings.Contains(zero.Body, "连接数超出限制"), "%s", zero)
	free := raw(plain, "GET", "nopages.example.test", "/ok", nil, "")
	check("conn-unlimited", free.Status == 200, "%s", free)

	fmt.Println("== package bandwidth (budget split between responses in flight)")
	timed := func(host string) (time.Duration, int) {
		started := time.Now()
		answer := raw(plain, "GET", host, "/big", nil, "")
		return time.Since(started), len(answer.Body)
	}
	alone, size := timed("bw.example.test")
	free2, _ := timed("nopages.example.test")
	// 400 KB at 100 000 B/s: 3-4 s (nginx limit_rate lets the first
	// second's worth through at once: limit = rate*(t+1) - sent); unlimited < 1 s.
	check("bw-single", size == bigBody && alone > 2500*time.Millisecond && alone < 6*time.Second && free2 < time.Second,
		"%d bytes in %s (unlimited site %s)", size, alone.Round(time.Millisecond), free2.Round(time.Millisecond))
	var wait sync.WaitGroup
	durations := make([]time.Duration, 2)
	for index := range durations {
		wait.Add(1)
		go func() { defer wait.Done(); durations[index], _ = timed("bw.example.test") }()
		time.Sleep(50 * time.Millisecond)
	}
	wait.Wait()
	// two in flight: the second starts at half the budget (v7 rounding), the
	// first keeps the rate it started with.
	check("bw-shared", durations[0] < 6*time.Second && durations[1] > 7*time.Second, "first %s, second %s", durations[0].Round(time.Millisecond), durations[1].Round(time.Millisecond))
	left := strings.TrimSpace(raw(plain, "GET", "bw.example.test", "/__inflight_bw?sub="+subB, nil, "").Body)
	// the probe request is a response of the subscription too: itself only
	check("bw-released", left == "1", "responses counted after both finished (the probe itself): %s", left)
}

// ------------------------------------------------------------ market limits

// keepConn is one client TCP connection kept open between requests.
type keepConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dialKeep() (*keepConn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", plain), 3*time.Second)
	if err != nil {
		return nil, err
	}
	return &keepConn{conn: conn, reader: bufio.NewReader(conn)}, nil
}

// get sends one keep-alive request; 0 = the connection failed or closed.
func (k *keepConn) get(host string) (int, http.Header) {
	_ = k.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(k.conn, "GET /ok HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		return 0, nil
	}
	response, err := http.ReadResponse(k.reader, &http.Request{Method: "GET"})
	if err != nil {
		return 0, nil
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode, response.Header
}

func marketSiteOf(metric, action string) marketSite {
	for _, site := range marketSites {
		if site.metric == metric && site.action == action {
			return site
		}
	}
	panic(metric + " " + action)
}

func tcpCount(sub string) string {
	return strings.TrimSpace(raw(plain, "GET", "nopages.example.test", "/__tcp?sub="+sub, nil, "").Body)
}

// burst sends total requests at once, each on its own connection.
func burst(host string, total int) (map[int]int, int) {
	var wait sync.WaitGroup
	var mu sync.Mutex
	counts, retry := map[int]int{}, 0
	for range total {
		wait.Add(1)
		go func() {
			defer wait.Done()
			answer := raw(plain, "GET", host, "/ok", nil, "")
			mu.Lock()
			counts[answer.Status]++
			if answer.Status == 503 && answer.Headers["retry-after"] == "1" {
				retry++
			}
			mu.Unlock()
		}()
	}
	wait.Wait()
	return counts, retry
}

// startOfSecond waits until 50 ms into the next wall clock second (the
// node's new connection window is per second).
func startOfSecond() {
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second + 50*time.Millisecond).Sub(now))
}

func checkMarket() {
	fmt.Println("== market supply limits (ADR 0012 ML-07): throttle / pause enforce on the node, stop refuses")
	// stop: every metric's stopped subscription answers 503 for every request
	for _, metric := range []string{"conn", "new", "qps"} {
		site := marketSiteOf(metric, "stop")
		counts, _ := burst(site.host, 5)
		h2 := probe("h2", site.host, "/ok")
		h3 := probe("h3", site.host, "/ok")
		check("market-"+metric+"-stop", counts[503] == 5 && h2.Status == 503 && h3.Status == 503,
			"h1 %v, h2 %d, h3 %d", counts, h2.Status, h3.Status)
	}
	for _, action := range []string{"throttle", "pause"} {
		// TCP connections: 3 kept-alive connections fit, a 4th is refused,
		// requests on the counted ones keep passing; closing one frees a slot.
		site := marketSiteOf("conn", action)
		var open []*keepConn
		var statuses []int
		for range marketConns {
			conn, err := dialKeep()
			if err != nil {
				check("market-conn-"+action+"-dial", false, "%v", err)
				return
			}
			open = append(open, conn)
			status, _ := conn.get(site.host)
			statuses = append(statuses, status)
		}
		again, _ := open[0].get(site.host)
		extra, _ := dialKeep()
		refused, _ := extra.get(site.host)
		extra.conn.Close()
		counted := tcpCount(site.sub)
		check("market-conn-"+action+"-limit", fmt.Sprint(statuses) == "[200 200 200]" && again == 200 && refused == 503 && counted == "3",
			"first %v, again on a counted connection %d, a 4th connection %d, counted %s", statuses, again, refused, counted)
		if action == "throttle" {
			// the same subscription's other site shares the connections;
			// another subscription with the same limit does not
			other, _ := dialKeep()
			shared, _ := other.get(marketSiteOf("conn", "throttle").host)
			other.conn.Close()
			second := raw(plain, "GET", "conn-throttle2.market.test", "/ok", nil, "")
			isolated := raw(plain, "GET", "conn-other.market.test", "/ok", nil, "")
			check("market-conn-isolation", shared == 503 && second.Status == 503 && isolated.Status == 200,
				"same subscription new connection %d, its second site %d, another subscription %d", shared, second.Status, isolated.Status)
		}
		open[0].conn.Close()
		time.Sleep(1500 * time.Millisecond)
		released := tcpCount(site.sub)
		fresh, _ := dialKeep()
		after, _ := fresh.get(site.host)
		fresh.conn.Close()
		for _, conn := range open[1:] {
			conn.conn.Close()
		}
		time.Sleep(1500 * time.Millisecond)
		check("market-conn-"+action+"-release", released == "2" && after == 200 && tcpCount(site.sub) == "0",
			"after closing one: counted %s, a new connection %d; all closed: %s", released, after, tcpCount(site.sub))

		// new connections per second: 5 of 12 within one second
		site = marketSiteOf("new", action)
		startOfSecond()
		counts, _ := burst(site.host, 12)
		time.Sleep(1100 * time.Millisecond)
		next := raw(plain, "GET", site.host, "/ok", nil, "")
		check("market-new-"+action, counts[200] == marketNew && counts[503] == 12-marketNew && next.Status == 200,
			"12 new connections in one second (limit %d): %v; next second %d", marketNew, counts, next.Status)

		// QPS: a burst of one second's share, then 503 + Retry-After: 1
		site = marketSiteOf("qps", action)
		counts, retry := burst(site.host, 30)
		check("market-qps-"+action, counts[200] >= marketQPS && counts[200] <= marketQPS+2 && counts[503] == 30-counts[200] &&
			retry == counts[503], "30 requests at once (qps %d): %v, Retry-After: 1 on %d", marketQPS, counts, retry)
		time.Sleep(1100 * time.Millisecond)
		again2 := raw(plain, "GET", site.host, "/ok", nil, "")
		check("market-qps-"+action+"-refill", again2.Status == 200, "a second later: %s", again2)
	}
	// h3 has no TCP connection: a conn-limited subscription with every slot
	// taken still serves QUIC
	site := marketSiteOf("conn", "throttle")
	var held []*keepConn
	for range marketConns {
		conn, _ := dialKeep()
		conn.get(site.host)
		held = append(held, conn)
	}
	h3 := probe("h3", site.host, "/ok")
	h2 := probe("h2", site.host, "/ok")
	for _, conn := range held {
		conn.conn.Close()
	}
	check("market-conn-quic", h3.Status == 200 && h2.Status == 503, "slots full: h3 %d, h2 (a TCP connection) %d", h3.Status, h2.Status)

	fmt.Println("== market per subscription minute statistics")
	// the finished minute is handed out once the minute is over
	now := time.Now()
	time.Sleep(now.Truncate(time.Minute).Add(time.Minute + 500*time.Millisecond).Sub(now))
	var records []map[string]any
	if *recordsOut != "" {
		records = agentMinutes()
	} else {
		records = subscriptionMinutes()
	}
	stats := map[string]map[string]float64{}
	for _, record := range records {
		sub, _ := record["subscription_id"].(string)
		// the checks above span several minutes: the maxima over them
		if stats[sub] == nil {
			stats[sub] = map[string]float64{}
		}
		for key, value := range record {
			if number, ok := value.(float64); ok && key != "minute" {
				if key == "bytes_out" {
					stats[sub][key] += number
				} else {
					stats[sub][key] = max(stats[sub][key], number)
				}
			}
		}
	}
	conn := stats[marketSiteOf("conn", "throttle").sub]
	newer := stats[marketSiteOf("new", "throttle").sub]
	qps := stats[marketSiteOf("qps", "throttle").sub]
	check("market-minutes", conn != nil && conn["max_connections"] == marketConns && conn["bytes_out"] > 0 && conn["peak_bps"] > 0 &&
		conn["max_requests"] >= 1 && newer != nil && newer["max_new_cps"] == marketNew && qps != nil && qps["max_qps"] >= marketQPS,
		"conn %v, new %v, qps %v (%d records)", conn, newer, qps, len(records))
	check("market-minutes-once", len(subscriptionMinutes()) == 0, "a second read is empty")
}

func subscriptionMinutes() []map[string]any {
	client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(*stateRoot, "run", "cdnca-site-admin.sock"))
		}}}
	response, err := client.Get("http://control/subscription-minutes")
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	var body struct {
		Minutes []map[string]any `json:"minutes"`
	}
	_ = json.NewDecoder(response.Body).Decode(&body)
	return body.Minutes
}

func checkTraffic(n *node) {
	fmt.Println("== traffic limit page (site.traffic_limit, ge-analytics)")
	page := "<!DOCTYPE html><html><body><h1>traffic.example.test over</h1></body></html>\n"
	sites := baseSites(n)
	for index := range sites {
		sites[index].Revision = 3
	}
	sites[6].TrafficLimit = &edgesite.TrafficLimit{Period: edgeconfig.SiteTrafficLimitMonthly, NoticeHTML: page}
	if err := n.activate(sites); err != nil {
		check("activate-traffic", false, "%v", err)
		return
	}
	// v7 (edgeconfig.SiteTrafficLimitDirectives): 509, the page printed by
	// content_by_lua (chunked), Cache-Control no-store, every method.
	for _, method := range []string{"GET", "POST"} {
		answer := raw(plain, method, "traffic.example.test", "/ok", nil, map[string]string{"GET": "", "POST": "a=1"}[method])
		check("traffic-page-"+method, answer.Status == 509 && answer.Body == page && answer.Framing == "chunked" &&
			answer.Headers["cache-control"] == "no-store" && answer.Headers["content-type"] == "text/html; charset=utf-8", "%s", answer)
	}
	answer := raw(plain, "GET", "traffic.example.test", "/.well-known/acme-challenge/token", nil, "")
	check("traffic-acme-exempt", answer.Status == 200 && strings.HasPrefix(answer.Body, "origin traffic.example.test"), "%s", answer)
	h2 := probe("h2", "traffic.example.test", "/ok")
	check("traffic-h2", h2.Status == 509 && h2.Body == page, "%d %q", h2.Status, h2.Body)
	sites[6].TrafficLimit = &edgesite.TrafficLimit{Period: edgeconfig.SiteTrafficLimitTotal}
	for index := range sites {
		sites[index].Revision = 4
	}
	if err := n.activate(sites); err != nil {
		check("activate-traffic-default", false, "%v", err)
		return
	}
	answer = raw(plain, "GET", "traffic.example.test", "/ok", nil, "")
	check("traffic-default-page", answer.Status == 509 && strings.Contains(answer.Body, "网站流量已超出限制") && strings.Contains(answer.Body, "错误代码 509"), "%s", answer)
	sites[6].TrafficLimit = nil
	for index := range sites {
		sites[index].Revision = 5
	}
	if err := n.activate(sites); err != nil {
		check("activate-traffic-cleared", false, "%v", err)
		return
	}
	answer = raw(plain, "GET", "traffic.example.test", "/ok", nil, "")
	check("traffic-cleared", answer.Status == 200, "a republication without the limit serves again, no reload: %s", answer)
}

func checkLog() {
	data, _ := os.ReadFile(filepath.Join(*stateRoot, "nginx", "logs", "error.log"))
	var bad []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "[alert]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[emerg]") ||
			strings.Contains(line, "[error]") && strings.Contains(line, "lua") && !strings.Contains(line, "cdnca_filters: error page") {
			bad = append(bad, line)
		}
	}
	check("error-log", len(bad) == 0, "%d lines %v", len(bad), bad[:min(3, len(bad))])
}

func short(text string) string {
	if len(text) > 60 {
		return text[:60] + "..."
	}
	return text
}

func clone(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func main() {
	flag.Parse()
	selected := map[string]bool{}
	for _, name := range strings.Split(*only, ",") {
		if name != "" {
			selected[name] = true
		}
	}
	want := func(name string) bool { return len(selected) == 0 || selected[name] }
	startOrigin()
	n, err := newNode()
	if err != nil {
		check("start", false, "%v", err)
		fmt.Printf("RESULT failures=%d\n", failures)
		os.Exit(1)
	}
	n.installCertificate()
	if err := n.activate(baseSites(n)); err != nil {
		check("activate", false, "%v", err)
	} else {
		if want("order") {
			checkOrder()
		}
		if want("upload") {
			checkUpload()
		}
		if want("connections") {
			checkConnections()
		}
		if want("market") {
			checkMarket()
		}
		if want("share") {
			checkShare(n)
		}
		if want("traffic") {
			checkTraffic(n)
		}
		if want("response") {
			checkResponseRules(n)
		}
		if want("errorpage") {
			checkErrorPages(n)
		}
		checkLog()
	}
	n.stop()
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}
