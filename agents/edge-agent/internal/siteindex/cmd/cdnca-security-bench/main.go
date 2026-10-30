// Command cdnca-security-bench measures what dynamic routing security (D7,
// edge/openresty/dynroute/cdnca_security.lua) adds to a request: N sites,
// each with its own CC policy, ACL + WAF rules, HTTP policy and firewall
// action (all distinct objects), activated through the site index activator
// into one OpenResty with the shared-server shape of the dynroute contract.
// Run inside the node runtime image (tests/dynroute-security/bench.sh).
//
// Two measurements, both on the same routed sites:
//   - in process: a location replays each phase function of cdnca_security
//     for a random site under CLOCK_MONOTONIC, warm (derived objects cached)
//     and cold (first request of a site in the worker);
//   - end to end: sequential requests to random sites against a port whose
//     sites carry the full security set and a port whose sites carry none
//     (same selection, same origin stand-in); the difference is the cost.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
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

	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

var (
	luaRoot   = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	stateRoot = flag.String("state", "/tmp/d7bench", "state root")
	sites     = flag.Int("sites", 10000, "sites per port")
	requests  = flag.Int("requests", 20000, "end-to-end requests per port")
)

const (
	scope       = "0d7a0000-0000-4000-8000-000000000001"
	tenant      = "0d7a0000-0000-4000-8000-000000000002"
	portSecure  = 18180
	portPlain   = 18181
	originPort  = 18190
	controlSock = "run/cdnca-site-admin.sock"
)

func uuidN(prefix string, n int) string { return fmt.Sprintf("%s-0000-4000-8000-%012d", prefix, n) }

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// secureSite: CC (fixed window, never reached by the benchmark), an ACL
// policy (3 CIDR rules), a WAF policy (method, path, header rules), an HTTP
// policy (request/response headers, a rewrite, a redirect) and a firewall
// action whose networks the benchmark client is outside of.
func secureSite(index int) (edgesite.Site, map[string][]byte) {
	siteID := uuidN("0d7a1000", index)
	referenced := map[string][]byte{}
	cc := edgeconfig.CCV2Policy{SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: scope, SiteID: siteID,
		PolicyID: uuidN("0d7a2000", index), PolicyVersion: 1, BindingID: uuidN("0d7a3000", index), BindingRevision: 1,
		PublicationID: uuidN("0d7a4000", index), Enabled: true, TrustedProxies: []string{}, Allowlist: []string{},
		Rules: []edgeconfig.CCV2Rule{{RuleID: uuidN("0d7a5000", index), Priority: 10, Flow: edgeconfig.CCV2FlowStop,
			Match:     edgeconfig.CCV2Match{Path: &edgeconfig.CCV2PathMatch{Kind: edgeconfig.CCV2PathPrefix, Value: "/"}},
			Dimension: edgeconfig.CCV2DimensionClientIP,
			Limit:     edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow, Requests: 1000000, WindowSeconds: 1},
			Action:    edgeconfig.CCV2Action{Kind: edgeconfig.CCV2ActionReject429}}}}
	ccRaw, err := edgeconfig.CanonicalCCV2Policy(cc)
	must(err)
	referenced[digest(ccRaw)] = ccRaw
	http := map[string]any{"site_id": siteID, "max_upload_bytes": 1 << 20,
		"request_headers":  []any{map[string]any{"kind": "set", "name": "x-edge-site", "values": []string{strconv.Itoa(index)}}},
		"response_headers": []any{map[string]any{"kind": "add", "name": "x-edge", "values": []string{"yes"}}},
		"rewrites": []any{map[string]any{"rule_id": "rw", "priority": 10, "match_kind": "exact", "match_path": "/old",
			"target_path": "/new", "preserve_query": true, "preserve_cookie": true}},
		"redirect_allowed_hosts": []string{"bench.test"}, "redirects": []any{map[string]any{"rule_id": "rd", "priority": 10, "match_kind": "exact",
			"match_path": "/moved", "status": 301, "target_url": "https://bench.test/new", "preserve_query": false, "preserve_path": false}},
		"cors": nil}
	httpRaw, err := json.Marshal(http)
	must(err)
	referenced[digest(httpRaw)] = httpRaw
	firewall := map[string]any{"schema_version": "cdnca.edge.firewall-action/v1", "policy_version": 1, "tenant_id": tenant,
		"site_id": siteID, "policy_id": uuidN("0d7a6000", index), "expected_active_policy_version": 0,
		"normal_action": "return_page", "escalated_action": "nftables", "engage_threshold": 100000000, "recover_threshold": 0,
		"recovery_windows": 2, "block_networks": []string{"198.51.100.0/24"}, "trusted_proxies": []string{},
		"trusted_crawlers": []any{}, "return_page": map[string]any{"status": 429, "content_type": "text/plain; charset=utf-8", "body": "limited"}}
	firewallRaw, err := json.Marshal(firewall)
	must(err)
	referenced[digest(firewallRaw)] = firewallRaw
	rule := func(n int, match edgeconfig.WAFMatch, action edgeconfig.WAFAction) edgeconfig.WAFRule {
		return edgeconfig.WAFRule{RuleID: uuidN(fmt.Sprintf("0d7a7%03d", n), index), Match: match, Action: action, Control: edgeconfig.WAFStop}
	}
	site := plainSite(index, siteID, portSecure)
	site.Security = edgesite.Security{
		Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{
			{Kind: edgeconfig.SecurityACL, PolicyID: uuidN("0d7a8000", index), PolicyVersion: 1, BindingRevision: 1,
				RuntimeSHA256: strings.Repeat("ab", 32), Enabled: true, DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{
					rule(1, edgeconfig.WAFMatch{SourceCIDR: "203.0.113.0/24"}, edgeconfig.WAFBlock),
					rule(2, edgeconfig.WAFMatch{SourceCIDR: "2001:db8::/32"}, edgeconfig.WAFBlock),
					rule(3, edgeconfig.WAFMatch{SourceCIDR: "192.0.2.0/24", Path: &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathPrefix, Value: "/admin"}}, edgeconfig.WAFBlock),
				}},
			{Kind: edgeconfig.SecurityWAF, PolicyID: uuidN("0d7a9000", index), PolicyVersion: 1, BindingRevision: 1,
				RuntimeSHA256: strings.Repeat("cd", 32), Enabled: true, DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{
					rule(4, edgeconfig.WAFMatch{Method: "DELETE"}, edgeconfig.WAFBlock),
					rule(5, edgeconfig.WAFMatch{Path: &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathExact, Value: "/wp-login.php"}}, edgeconfig.WAFBlock),
					rule(6, edgeconfig.WAFMatch{Header: &edgeconfig.WAFHeaderMatch{Name: "x-attack", Kind: edgeconfig.WAFHeaderExists}}, edgeconfig.WAFBlock),
				}},
		}},
		CC: []edgesite.CCBinding{{Ports: []int{portSecure}, SourceSHA256: strings.Repeat("ef", 32),
			Policy: edgesite.Ref{Kind: edgesite.RefCCPolicy, ID: cc.PolicyID, Revision: 1, SHA256: digest(ccRaw)}}},
		FirewallAction: &edgesite.Ref{Kind: edgesite.RefFirewallAction, ID: uuidN("0d7a6000", index), Revision: 1, SHA256: digest(firewallRaw)},
	}
	site.HTTP = &edgesite.Ref{Kind: edgesite.RefHTTPPolicy, ID: uuidN("0d7aa000", index), Revision: 1, SHA256: digest(httpRaw)}
	site.Limits.MaxBodyBytes = 1 << 20
	return site, referenced
}

func plainSite(index int, siteID string, port int) edgesite.Site {
	return edgesite.Site{Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID, Revision: 1,
		Hosts:     edgesite.Hosts{Primary: fmt.Sprintf("s%d.p%d.bench.test", index, port), Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: port, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: originPort, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 1000, ReadTimeoutMS: 1000, TotalBudgetMS: 2000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}},
			CC: []edgesite.CCBinding{}},
		Errors: []edgesite.ErrorPage{},
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL", err)
		os.Exit(1)
	}
}

func object(site edgesite.Site, referenced map[string][]byte) siteindex.Object {
	raw, err := edgesite.Encode(site)
	must(err)
	value, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
	must(err)
	value.Referenced = referenced
	return value
}

func openresty(args ...string) error {
	output, err := exec.Command("openresty", append([]string{"-p", filepath.Join(*stateRoot, "nginx") + "/", "-c", "nginx.conf"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(float64(len(sorted))*p))]
}

func endToEnd(port int, count int) (p50, p99, mean float64, statuses map[int]int) {
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}, Timeout: 5 * time.Second}
	rng := rand.New(rand.NewPCG(uint64(port), 7))
	latencies := make([]float64, 0, count)
	statuses = map[int]int{}
	sum := 0.0
	for range count {
		host := fmt.Sprintf("s%d.p%d.bench.test", rng.IntN(*sites), port)
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/item?x=1", port), nil)
		request.Host = host
		started := time.Now()
		response, err := client.Do(request)
		elapsed := float64(time.Since(started).Microseconds())
		if err != nil {
			statuses[-1]++
			continue
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		statuses[response.StatusCode]++
		latencies = append(latencies, elapsed)
		sum += elapsed
	}
	sort.Float64s(latencies)
	return percentile(latencies, 0.5), percentile(latencies, 0.99), sum / float64(len(latencies)), statuses
}

func main() {
	flag.Parse()
	_ = os.RemoveAll(*stateRoot)
	for _, dir := range []string{"nginx/logs", "run", "site-index", "site-objects"} {
		must(os.MkdirAll(filepath.Join(*stateRoot, dir), 0o755))
	}
	go serveOrigin()
	conf := strings.NewReplacer("__LUA__", *luaRoot, "__STATE__", *stateRoot, "__SECURE__", strconv.Itoa(portSecure),
		"__PLAIN__", strconv.Itoa(portPlain), "__ORIGIN__", strconv.Itoa(originPort), "__N__", strconv.Itoa(*sites)).Replace(nginxConf)
	must(os.WriteFile(filepath.Join(*stateRoot, "nginx", "nginx.conf"), []byte(conf), 0o644))
	must(openresty())
	defer func() { _ = openresty("-s", "stop") }()

	started := time.Now()
	var objects []siteindex.Object
	referencedBytes, siteBytes := 0, 0
	for index := range *sites {
		site, referenced := secureSite(index)
		value := object(site, referenced)
		siteBytes += len(value.Raw)
		for _, content := range referenced {
			referencedBytes += len(content)
		}
		objects = append(objects, value)
		plain := object(plainSite(index, uuidN("0d7ab000", index), portPlain), map[string][]byte{})
		siteBytes += len(plain.Raw)
		objects = append(objects, plain)
	}
	generated := time.Since(started)
	control := siteindex.NewControl(filepath.Join(*stateRoot, controlSock))
	activator := &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(*stateRoot, "site-index"), Access: siteindex.Access{GID: workerGID()}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*stateRoot, "site-objects"), Access: siteindex.Access{GID: workerGID()}}}
	ctx := context.Background()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := control.Status(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			must(err)
		}
	}
	started = time.Now()
	activation, err := activator.Activate(ctx, objects)
	must(err)
	must(activator.WaitGeneration(ctx, activation.Generation))
	activated := time.Since(started)
	fmt.Printf("BENCH sites=%d per port, objects: site %d B total, referenced %d B total (%d per secure site); generate %s, first activation %s\n",
		*sites, siteBytes, referencedBytes, 3, generated.Round(time.Millisecond), activated.Round(time.Millisecond))

	// Correctness on the measured sites before timing anything.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, check := range []struct {
		port   int
		path   string
		header string
		want   int
	}{{portSecure, "/item", "", 200}, {portSecure, "/wp-login.php", "", 403}, {portSecure, "/moved", "", 301},
		{portSecure, "/item", "x-attack", 403}, {portPlain, "/wp-login.php", "", 200}} {
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", check.port, check.path), nil)
		request.Host = fmt.Sprintf("s7.p%d.bench.test", check.port)
		if check.header != "" {
			request.Header.Set(check.header, "1")
		}
		response, err := noRedirect.Do(request)
		must(err)
		response.Body.Close()
		if response.StatusCode != check.want || check.port == portSecure && check.want == 200 && response.Header.Get("X-Edge") != "yes" {
			must(fmt.Errorf("port %d %s %s: status %d X-Edge %q, want %d", check.port, check.path, check.header,
				response.StatusCode, response.Header.Get("X-Edge"), check.want))
		}
	}
	fmt.Println("BENCH checks: allowed 200 with HTTP policy header, WAF path 403, redirect 301, header rule 403, plain site unaffected")

	stats := func() string {
		response, err := http.Get("http://127.0.0.1:18182/__stats")
		must(err)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		return strings.TrimSpace(string(body))
	}
	stats()
	// Cold: every secure site's first request in the worker (its CC entry,
	// rule program, HTTP policy entry and firewall matcher are built).
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}, Timeout: 5 * time.Second}
	for index := range *sites {
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/item", portSecure), nil)
		request.Host = fmt.Sprintf("s%d.p%d.bench.test", index, portSecure)
		response, err := client.Do(request)
		must(err)
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	fmt.Printf("BENCH security phases, cold (first request of each of %d sites): %s\n", *sites, stats())
	_, _, _, _ = endToEnd(portSecure, *requests)
	fmt.Printf("BENCH security phases, warm (%d requests, random sites): %s\n", *requests, stats())
	for round := range 2 {
		sp50, sp99, smean, sstatus := endToEnd(portSecure, *requests)
		stats()
		pp50, pp99, pmean, pstatus := endToEnd(portPlain, *requests)
		fmt.Printf("BENCH end-to-end round %d: secure p50 %.0fus p99 %.0fus mean %.0fus %v | plain p50 %.0fus p99 %.0fus mean %.0fus %v | added p50 %.0fus mean %.0fus\n",
			round+1, sp50, sp99, smean, sstatus, pp50, pp99, pmean, pstatus, sp50-pp50, smean-pmean)
	}
	raw, _ := os.ReadFile(filepath.Join(*stateRoot, "nginx", "logs", "error.log"))
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	bad := 0
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "[error]") || strings.Contains(scanner.Text(), "[alert]") || strings.Contains(scanner.Text(), "[crit]") {
			bad++
			if bad <= 5 {
				fmt.Println("ERRLOG", scanner.Text())
			}
		}
	}
	fmt.Printf("BENCH error.log error/alert/crit lines: %d\n", bad)
	if bad != 0 {
		os.Exit(1)
	}
}

func serveOrigin() {
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(originPort))
	must(err)
	must(http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("ok"))
	})))
}
