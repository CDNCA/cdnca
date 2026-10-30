package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
)

// Node-level locations (D13-c0 ② ⑤): the ACME HTTP-01 overlay on every
// server, the market probe and benchmark object for an unknown Host only
// (a configured site's Host is proxied to its origin), and port 80 served
// for the probe without a site there.
func checkNodeLocations(h *harness, config dynroute.Config, previous *dynroute.Runtime) *dynroute.Runtime {
	ctx := h.ctx
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
	limited := 0
	for range 60 {
		if b := request(http.MethodHead, 80, "anything.example", marketprobe.BenchmarkPath); b.status == 429 {
			limited++
		}
	}
	check("benchmark-rate-limited", limited > 0, "429 x %d of 60", limited)
	return runtime
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
