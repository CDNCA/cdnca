package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
)

// Node-level locations (D13-c0 ② ⑤): the ACME HTTP-01 overlay on every
// server, the market probe and benchmark object for an unknown Host only
// (a configured site's Host is proxied to its origin), and port 80 served
// for the probe without a site there.
func checkNodeLocations(h *harness, config dynroute.Config, previous *dynroute.Runtime) *dynroute.Runtime {
	ctx := h.ctx
	before := objectsSites(h.input.Objects)
	_ = previous.Stop(ctx)
	acmeRoot := filepath.Join(*state, "acme")
	nodeConfig := config
	nodeConfig.ACMEOverlayRoot, nodeConfig.MarketProbe, nodeConfig.MarketBenchmark = acmeRoot, true, true
	runtime, err := dynroute.New(nodeConfig)
	if err == nil {
		err = runtime.Recover(ctx)
	}
	check("node-locations-runtime", err == nil, "%v", err)
	if err != nil {
		return previous
	}
	h.runtime = runtime
	shop := makeSite(1, "shop.d13.test", 1, portPlain)
	h.apply("node-locations-apply", shop)

	// the overlay the agent's acmehttp01 activates: current/<host>/<token>
	token := "tokenAAAAAAAAAAAAAAAAAAAAAA"
	current := edgeconfig.ACMEHTTP01OverlayRoot(acmeRoot)
	err = os.MkdirAll(filepath.Join(current, "shop.d13.test"), 0o755)
	if err == nil {
		err = os.WriteFile(filepath.Join(current, "shop.d13.test", token), []byte(token+".thumbprint"), 0o644)
	}
	if err == nil {
		err = chmodTree(acmeRoot)
	}
	check("acme-overlay-written", err == nil, "%v", err)
	a := get(portPlain, "shop.d13.test", "/.well-known/acme-challenge/"+token)
	check("acme-site-host", a.status == 200 && a.body == token+".thumbprint", "%d %q %s", a.status, a.body, a.err)
	a = get(portPlain, "shop.d13.test", "/.well-known/acme-challenge/tokenBBBBBBBBBBBBBBBBBBBBBB")
	check("acme-missing-404", a.status == 404, "%d", a.status)
	a = get(portPlain, "shop.d13.test", "/.well-known/acme-challenge/short")
	check("acme-short-token-to-origin", a.status == 200 && strings.HasPrefix(a.body, "origin shop.d13.test"), "%d %.40q", a.status, a.body)
	a = get(portPlain, "unknown.d13.test", "/.well-known/acme-challenge/"+token)
	check("acme-unknown-host-421", a.status == 421, "%d", a.status)
	conf, _ := os.ReadFile(filepath.Join(config.SharedRoot, "nginx.conf"))
	check("acme-ready-marker", strings.Contains(string(conf), edgeconfig.ACMEHTTP01RouteMarker) &&
		strings.Contains(string(conf), "root "+current+";"), "nginx.conf lacks the overlay route acmehttp01 checks")

	// market probe: unknown Host -> node, site Host -> its origin
	a = get(portPlain, "unknown.d13.test", marketprobe.Path)
	check("probe-unknown-204", a.status == 204, "%d %s", a.status, a.err)
	a = get(portPlain, "shop.d13.test", marketprobe.Path)
	check("probe-site-host-to-origin", a.status == 200 && strings.HasPrefix(a.body, "origin shop.d13.test "+marketprobe.Path), "%d %.60q", a.status, a.body)
	a = request(http.MethodPost, portPlain, "unknown.d13.test", marketprobe.Path)
	check("probe-post-421", a.status == 421, "%d", a.status)
	a = get(portPlain, "unknown.d13.test", marketprobe.BenchmarkPath)
	check("benchmark-unknown", a.status == 200 && len(a.body) == marketprobe.BenchmarkBytes, "%d %d bytes %s", a.status, len(a.body), a.err)
	a = get(portPlain, "shop.d13.test", marketprobe.BenchmarkPath)
	check("benchmark-site-host-to-origin", a.status == 200 && strings.HasPrefix(a.body, "origin shop.d13.test "+marketprobe.BenchmarkPath), "%d %.60q", a.status, a.body)
	// port 80 has no site: the probe server
	a = get(80, "anything.example", marketprobe.Path)
	check("probe-port-80", a.status == 204, "%d %s", a.status, a.err)
	a = get(80, "anything.example", "/")
	check("probe-port-80-other-421", a.status == 421, "%d %s", a.status, a.err)
	// (before the benchmark limit below uses up the client's burst)
	checkProbeDefaultSite(h, shop, before)
	limited := 0
	for range 60 {
		if b := request(http.MethodHead, 80, "anything.example", marketprobe.BenchmarkPath); b.status == 429 {
			limited++
		}
	}
	check("benchmark-rate-limited", limited > 0, "429 x %d of 60", limited)
	return runtime
}

// checkProbeDefaultSite: the market probe
// addresses a node by IP, so on a port with a default site (默认站点) the
// Host is no site's name and the default site answers it as its own. The
// probe paths stay the node's there (contract §1.1: only a configured
// name takes them back): 204 and the benchmark object, never the default
// site's CC (live: banned 360 s) or origin, and not counted by its CC. Any
// other path of such a Host, and the default site's own name on the probe
// path, are still the site's, CC included. The default site's generation
// also carries the sites of before (the generation ahead of this check):
// the certificates the next checks serve stay within the runtime's
// retention (active and previous generation).
func checkProbeDefaultSite(h *harness, shop edgesite.Site, before []edgesite.Site) {
	fallback := makeSite(60, "default.d13.test", 1, portPlain)
	fallback.Default = true
	binding, policy, err := ccRejectPolicy(fallback, portPlain, 3)
	check("probe-default-site-cc", err == nil, "%v", err)
	if err != nil {
		return
	}
	fallback.Security.CC = []edgesite.CCBinding{binding}
	if err := siteObjects.Put(binding.Policy.SHA256, policy); err != nil {
		check("probe-default-site-cc-object", false, "%v", err)
		return
	}
	sites := []edgesite.Site{shop, fallback}
	for _, site := range before {
		if site.SiteID != shop.SiteID && site.SiteID != fallback.SiteID {
			sites = append(sites, site)
		}
	}
	h.input.Objects = objects(sites...)
	for index := range h.input.Objects {
		if h.input.Objects[index].Site.SiteID == fallback.SiteID {
			h.input.Objects[index].Referenced = map[string][]byte{binding.Policy.SHA256: policy}
		}
	}
	result, err := h.runtime.Apply(h.ctx, h.input)
	check("probe-default-site-apply", err == nil, "generation %d %v", result.Activation.Generation, err)
	if err != nil {
		return
	}
	// the default site's CC counts 1 of its 3
	a := get(portPlain, "127.0.0.1", "/")
	check("probe-default-site-serves-ip-host", a.status == 200 && strings.HasPrefix(a.body, "origin "), "%d %.60q %s", a.status, a.body, a.err)
	statuses := make([]int, 0, 6)
	for range 6 {
		statuses = append(statuses, get(portPlain, "127.0.0.1", marketprobe.Path).status)
	}
	check("probe-ip-host-default-site-204", slices.Equal(statuses, []int{204, 204, 204, 204, 204, 204}), "%v", statuses)
	a = get(portPlain, "nope.d13.test", marketprobe.Path)
	check("probe-unknown-host-default-site-204", a.status == 204, "%d %.60q", a.status, a.body)
	b := request(http.MethodHead, portPlain, "127.0.0.1", marketprobe.BenchmarkPath)
	check("benchmark-ip-host-default-site", b.status == 200, "%d %s", b.status, b.err)
	b = request(http.MethodPost, portPlain, "127.0.0.1", marketprobe.Path)
	check("probe-ip-host-default-site-post-421", b.status == 421, "%d %s", b.status, b.err)
	// the probes were not the site's requests: 2 more of its 3 pass, then CC
	second, third, fourth := get(portPlain, "127.0.0.1", "/a"), get(portPlain, "127.0.0.1", "/b"), get(portPlain, "127.0.0.1", "/c")
	check("probe-not-counted-by-default-site-cc", second.status == 200 && third.status == 200 && fourth.status == 429,
		"%d %d %d", second.status, third.status, fourth.status)
	// the default site's own name keeps the probe path (and its CC)
	a = get(portPlain, "default.d13.test", marketprobe.Path)
	check("probe-default-site-name-is-site", a.status == 429, "%d %.60q", a.status, a.body)
	a = get(portPlain, "127.0.0.1", marketprobe.Path)
	check("probe-ip-host-while-site-cc-limited-204", a.status == 204, "%d %.60q", a.status, a.body)
	// the later checks carry h.input.Objects on: without the default site
	h.apply("probe-default-site-removed", shop)
}

// ccRejectPolicy is a CC policy of one rule: requests per client over
// 60 s, the next refused with 429.
func ccRejectPolicy(site edgesite.Site, port int, requests uint32) (edgesite.CCBinding, []byte, error) {
	id := site.SiteID
	policy := edgeconfig.CCV2Policy{SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: site.ConfigurationScopeID,
		SiteID: site.SiteID, PolicyID: id, PolicyVersion: 1, BindingID: id, BindingRevision: 1, PublicationID: id,
		Enabled: true, TrustedProxies: []string{}, Allowlist: []string{},
		Rules: []edgeconfig.CCV2Rule{{RuleID: "0d130000-0000-4000-8000-0000000003c1", Priority: 10, Flow: edgeconfig.CCV2FlowStop,
			Match:     edgeconfig.CCV2Match{Path: &edgeconfig.CCV2PathMatch{Kind: edgeconfig.CCV2PathPrefix, Value: "/"}},
			Dimension: edgeconfig.CCV2DimensionClientIP,
			Limit:     edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow, Requests: requests, WindowSeconds: 60},
			Action:    edgeconfig.CCV2Action{Kind: edgeconfig.CCV2ActionReject429}}}}
	canonical, err := edgeconfig.CanonicalCCV2Policy(policy)
	if err != nil {
		return edgesite.CCBinding{}, nil, err
	}
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	return edgesite.CCBinding{Ports: []int{port}, SourceSHA256: digest,
		Policy: edgesite.Ref{Kind: edgesite.RefCCPolicy, ID: id, Revision: 1, SHA256: digest}}, canonical, nil
}

func request(method string, port int, host, path string) answer {
	built, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	built.Host = host
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(built)
	if err != nil {
		return answer{err: err.Error()}
	}
	_ = response.Body.Close()
	return answer{status: response.StatusCode}
}

// chmodTree makes the overlay worker readable (acmehttp01 does so with its
// release modes).
func chmodTree(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o644)
	})
}
