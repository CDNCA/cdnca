package marketprobe

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// hostTarget is a MARKET_PROBE v2 third-party access name target.
func hostTarget(id, host, serverName, path string, expect uint32) *agentv1.MarketProbeTarget {
	return &agentv1.MarketProbeTarget{TaskId: id, Host: host, Port: 443, ServerName: serverName, Path: path,
		ExpectStatus: expect}
}

// tlsExecutor resolves every host to addresses, routes every dial to the
// TLS server and trusts its certificate (httptest certificates cover
// example.com).
func tlsExecutor(t *testing.T, server *httptest.Server, addresses ...string) (*Executor, *atomic.Value) {
	t.Helper()
	e := executor(t, nil, Limits{})
	local := server.Listener.Addr().String()
	dialed := &atomic.Value{}
	e.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Store(address)
		return (&net.Dialer{}).DialContext(ctx, network, local)
	}
	e.resolve = func(context.Context, string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, address := range addresses {
			out = append(out, netip.MustParseAddr(address))
		}
		return out, nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	e.roots = roots
	return e, dialed
}

func TestHostProbeSendsBusinessHostAndSNI(t *testing.T) {
	var gotHost, gotPath, gotSNI atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		gotPath.Store(r.URL.RequestURI())
		gotSNI.Store(r.TLS.ServerName)
		w.WriteHeader(http.StatusOK)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	e, dialed := tlsExecutor(t, server, "10.0.0.1", publicV6, publicV4)
	r := run(t, e, command(hostTarget("a", "edge.cdn.example.net", "example.com", "/healthz?x=1", 200)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	if gotHost.Load() != "example.com" || gotSNI.Load() != "example.com" || gotPath.Load() != "/healthz?x=1" {
		t.Fatalf("host=%v sni=%v path=%v", gotHost.Load(), gotSNI.Load(), gotPath.Load())
	}
	// The private answer is skipped and IPv4 is preferred.
	if dialed.Load() != publicV4+":443" {
		t.Fatalf("dialed %v", dialed.Load())
	}
}

func TestHostProbeStatusMustMatch(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	e, _ := tlsExecutor(t, server, publicV4)
	r := run(t, e, command(hostTarget("a", "edge.cdn.example.net", "example.com", "/", 200),
		hostTarget("b", "edge.cdn.example.net", "example.com", "/", 302)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "status")
	expect(t, r[1], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
}

func TestHostProbeVerifiesCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	e, _ := tlsExecutor(t, server, publicV4)
	r := run(t, e, command(hostTarget("a", "edge.cdn.example.net", "not-covered.invalid-site.org", "/", 200)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "tls")
	e.roots = x509.NewCertPool() // an untrusted issuer
	r = run(t, e, command(hostTarget("b", "edge.cdn.example.net", "example.com", "/", 200)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "tls")
}

func TestHostProbeResolution(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	e, dialed := tlsExecutor(t, server, "127.0.0.1", "192.168.1.1", "fd00::1")
	r := run(t, e, command(hostTarget("a", "edge.cdn.example.net", "example.com", "/", 200)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rejected_address")
	if dialed.Load() != nil {
		t.Fatalf("dialed %v for a non-public answer", dialed.Load())
	}
	e.resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, &net.DNSError{IsNotFound: true} }
	r = run(t, e, command(hostTarget("b", "edge.cdn.example.net", "example.com", "/", 200)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "resolve")
}

func TestHostTargetValidation(t *testing.T) {
	e := executor(t, nil, Limits{})
	cases := []*agentv1.MarketProbeTarget{
		{TaskId: "ip-and-host", Ip: publicV4, Host: "edge.cdn.example.net", Port: 443, ServerName: "example.com", Path: "/", ExpectStatus: 200},
		hostTarget("port", "edge.cdn.example.net", "example.com", "/", 200),
		hostTarget("literal-host", "8.8.8.8", "example.com", "/", 200),
		hostTarget("bad-host", "edge..example.net", "example.com", "/", 200),
		hostTarget("bad-sni", "edge.cdn.example.net", "exa mple.com", "/", 200),
		hostTarget("no-sni", "edge.cdn.example.net", "", "/", 200),
		hostTarget("bad-path", "edge.cdn.example.net", "example.com", "healthz", 200),
		hostTarget("ctl-path", "edge.cdn.example.net", "example.com", "/a\nb", 200),
		hostTarget("status", "edge.cdn.example.net", "example.com", "/", 99),
		hostTarget("status-high", "edge.cdn.example.net", "example.com", "/", 600),
	}
	cases[1].Port = 80
	r := run(t, e, command(cases...))
	for _, result := range r {
		expect(t, result, agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
	}
	benchmark := benchmarkCommand(2, hostTarget("bench", "edge.cdn.example.net", "example.com", "/", 200))
	r = run(t, executor(t, nil, Limits{Benchmark: true}), benchmark)
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
}

// AGGREGATED_EDGE_PROBE v1 (fix-aephase1): a host target may be probed with
// HEAD and extra headers; Host and hop-by-hop headers, duplicates, control
// characters and method/headers on non-host targets are refused.
func TestHostProbeMethodAndHeaders(t *testing.T) {
	var gotMethod, gotToken, gotHost atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod.Store(r.Method)
		gotToken.Store(r.Header.Get("X-Probe-Token"))
		gotHost.Store(r.Host)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	e, _ := tlsExecutor(t, server, publicV4)
	target := hostTarget("a", "edge.cdn.example.net", "example.com", "/healthz", 204)
	target.Method = http.MethodHead
	target.Headers = []*agentv1.MarketProbeHeader{{Name: "X-Probe-Token", Value: "abc"}}
	r := run(t, e, command(target))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	if gotMethod.Load() != http.MethodHead || gotToken.Load() != "abc" || gotHost.Load() != "example.com" {
		t.Fatalf("method=%v token=%v host=%v", gotMethod.Load(), gotToken.Load(), gotHost.Load())
	}
	for name, bad := range map[string]*agentv1.MarketProbeTarget{
		"POST":         {Method: http.MethodPost},
		"Host header":  {Headers: []*agentv1.MarketProbeHeader{{Name: "Host", Value: "evil.example"}}},
		"duplicate":    {Headers: []*agentv1.MarketProbeHeader{{Name: "X-A", Value: "1"}, {Name: "x-a", Value: "2"}}},
		"control char": {Headers: []*agentv1.MarketProbeHeader{{Name: "X-A", Value: "1\r\nX-B: 2"}}},
		"bad name":     {Headers: []*agentv1.MarketProbeHeader{{Name: "X A", Value: "1"}}},
	} {
		target := hostTarget("b", "edge.cdn.example.net", "example.com", "/", 200)
		target.Method, target.Headers = bad.Method, bad.Headers
		expect(t, run(t, e, command(target))[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
		_ = name
	}
	nine := make([]*agentv1.MarketProbeHeader, MaxHeaders+1)
	for i := range nine {
		nine[i] = &agentv1.MarketProbeHeader{Name: "X-H" + string(rune('a'+i)), Value: "v"}
	}
	tooMany := hostTarget("c", "edge.cdn.example.net", "example.com", "/", 200)
	tooMany.Headers = nine
	expect(t, run(t, e, command(tooMany))[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
	// A market probe path target (IP literal) takes no method.
	plain := &agentv1.MarketProbeTarget{TaskId: "d", Ip: publicV4, Port: 80, Method: http.MethodHead}
	expect(t, run(t, e, command(plain))[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
}
