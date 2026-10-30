package marketprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// originTarget is a MARKET_PROBE v3 origin target.
func originTarget(id, scheme, host string, port uint32, hostHeader, serverName, path string, expect uint32,
	ca string,
) *agentv1.MarketProbeTarget {
	return &agentv1.MarketProbeTarget{TaskId: id, Scheme: scheme, Host: host, Port: port, HostHeader: hostHeader,
		ServerName: serverName, Path: path, ExpectStatus: expect, CaPem: ca}
}

// privateCA is a self-made CA and a TLS server whose certificate it issued
// for names; the server is not trusted by the system roots.
func privateCA(t *testing.T, handler http.Handler, names ...string) (*httptest.Server, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe-v3 test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

// routed: every admitted dial goes to server; dialed records the address
// the executor asked for.
func routed(t *testing.T, server *httptest.Server, answers ...string) (*Executor, *atomic.Value) {
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
		for _, answer := range answers {
			out = append(out, netip.MustParseAddr(answer))
		}
		return out, nil
	}
	return e, dialed
}

type seen struct{ host, sni, path atomic.Value }

func recordingHandler(record *seen, status *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record.host.Store(r.Host)
		record.path.Store(r.URL.RequestURI())
		if r.TLS != nil {
			record.sni.Store(r.TLS.ServerName)
		}
		w.WriteHeader(int(status.Load()))
	})
}

func TestOriginProbeCustomCAWithSeparateHostAndSNI(t *testing.T) {
	var record seen
	var status atomic.Int32
	status.Store(http.StatusOK)
	server, ca := privateCA(t, recordingHandler(&record, &status), "origin-tls.example.net")
	e, dialed := routed(t, server, publicV4)
	r := run(t, e, command(originTarget("a", "https", "origin.example.net", 8443, "www.example.com",
		"origin-tls.example.net", "/healthz?x=1", 0, ca)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	if record.host.Load() != "www.example.com" || record.sni.Load() != "origin-tls.example.net" ||
		record.path.Load() != "/healthz?x=1" || r[0].StatusCode != http.StatusOK {
		t.Fatalf("host=%v sni=%v path=%v status=%d", record.host.Load(), record.sni.Load(), record.path.Load(), r[0].StatusCode)
	}
	if dialed.Load() != publicV4+":8443" {
		t.Fatalf("dialed %v", dialed.Load())
	}
	// Without the CA the system roots do not trust it; the CA is not kept.
	r = run(t, e, command(originTarget("b", "https", "origin.example.net", 8443, "www.example.com",
		"origin-tls.example.net", "/", 0, "")))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "tls")
	if e.roots != nil {
		t.Fatal("a target's CA must not become the executor's roots")
	}
	// The CA does not cover another SNI.
	r = run(t, e, command(originTarget("c", "https", "origin.example.net", 8443, "www.example.com",
		"other.example.net", "/", 0, ca)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "tls")
}

func TestOriginProbeIPOriginOverHTTP(t *testing.T) {
	var record seen
	var status atomic.Int32
	status.Store(http.StatusNotFound)
	server := httptest.NewServer(recordingHandler(&record, &status))
	t.Cleanup(server.Close)
	e, dialed := routed(t, server)
	e.resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("an IP origin is not resolved")
		return nil, nil
	}
	// No expected status: an answer below 500 is up, and the status is reported.
	r := run(t, e, command(originTarget("a", "http", publicV4, 8080, "bucket.example.com:8080", "", "/", 0, "")))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	if r[0].StatusCode != http.StatusNotFound || record.host.Load() != "bucket.example.com:8080" ||
		dialed.Load() != publicV4+":8080" {
		t.Fatalf("status=%d host=%v dialed=%v", r[0].StatusCode, record.host.Load(), dialed.Load())
	}
	status.Store(http.StatusBadGateway)
	r = run(t, e, command(originTarget("b", "http", publicV6, 80, "["+publicV6+"]", "", "/", 0, "")))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "status")
	if r[0].StatusCode != http.StatusBadGateway || dialed.Load() != "["+publicV6+"]:80" {
		t.Fatalf("status=%d dialed=%v", r[0].StatusCode, dialed.Load())
	}
	// An expected status must match exactly.
	status.Store(http.StatusNoContent)
	r = run(t, e, command(originTarget("c", "http", publicV4, 80, publicV4, "", "/", 200, ""),
		originTarget("d", "http", publicV4, 80, publicV4, "", "/", 204, "")))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "status")
	expect(t, r[1], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
}

func TestOriginProbeRefusesInternalTargets(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	_, rawPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	// The real dialer: nothing is rerouted, so a refused target is never reached.
	e := executor(t, nil, Limits{})
	var targets []*agentv1.MarketProbeTarget
	for _, host := range []string{"127.0.0.1", "10.0.0.8", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1",
		"fd00::1", "fe80::1", "0.0.0.0", "::ffff:127.0.0.1"} {
		targets = append(targets, originTarget("ip-"+host, "http", host, 80, "origin.example.com", "", "/", 0, ""))
	}
	targets = append(targets, originTarget("loopback-port", "http", "127.0.0.1", 0, "origin.example.com", "", "/", 0, ""))
	targets[len(targets)-1].Port = uint32(mustAtoi(t, rawPort))
	r := run(t, e, command(targets...))
	for _, result := range r {
		expect(t, result, agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rejected_address")
	}
	// A name answering only internal addresses is refused too, before any dial.
	e.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("fd00::2")}, nil
	}
	r = run(t, e, command(originTarget("name", "http", "internal.example.com", uint32(mustAtoi(t, rawPort)),
		"internal.example.com", "", "/", 0, "")))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rejected_address")
	if hits.Load() != 0 {
		t.Fatalf("an internal target was reached %d times", hits.Load())
	}
}

func TestOriginTargetValidation(t *testing.T) {
	_, ca := privateCA(t, http.NotFoundHandler(), "ca.example.net")
	leafOnly := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	cases := []*agentv1.MarketProbeTarget{
		originTarget("scheme", "ftp", "origin.example.com", 21, "origin.example.com", "", "/", 0, ""),
		originTarget("port-0", "http", "origin.example.com", 0, "origin.example.com", "", "/", 0, ""),
		originTarget("port-high", "http", "origin.example.com", 65_536, "origin.example.com", "", "/", 0, ""),
		originTarget("no-host-header", "http", "origin.example.com", 80, "", "", "/", 0, ""),
		originTarget("bad-host-header", "http", "origin.example.com", 80, "a b.example.com", "", "/", 0, ""),
		originTarget("host-header-port", "http", "origin.example.com", 80, "origin.example.com:0", "", "/", 0, ""),
		originTarget("bad-host", "http", "origin..example.com", 80, "origin.example.com", "", "/", 0, ""),
		originTarget("bad-path", "http", "origin.example.com", 80, "origin.example.com", "", "health", 0, ""),
		originTarget("status", "http", "origin.example.com", 80, "origin.example.com", "", "/", 99, ""),
		originTarget("http-sni", "http", "origin.example.com", 80, "origin.example.com", "origin.example.com", "/", 0, ""),
		originTarget("http-ca", "http", "origin.example.com", 80, "origin.example.com", "", "/", 0, ca),
		originTarget("https-no-sni", "https", "origin.example.com", 443, "origin.example.com", "", "/", 0, ""),
		originTarget("bad-ca", "https", "origin.example.com", 443, "origin.example.com", "origin.example.com", "/", 0, leafOnly),
		originTarget("big-ca", "https", "origin.example.com", 443, "origin.example.com", "origin.example.com", "/", 0,
			strings.Repeat(ca, 16<<10/len(ca)+1)),
		{TaskId: "ip-and-scheme", Scheme: "http", Ip: publicV4, Host: "origin.example.com", Port: 80, HostHeader: "origin.example.com", Path: "/"},
		// v2 host targets do not take v3 fields.
		{TaskId: "v2-host-header", Host: "edge.cdn.example.net", Port: 443, ServerName: "example.com", Path: "/", ExpectStatus: 200,
			HostHeader: "other.example.com"},
	}
	r := run(t, executor(t, nil, Limits{}), command(cases...))
	for _, result := range r {
		expect(t, result, agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
	}
	benchmark := benchmarkCommand(2, originTarget("bench", "http", publicV4, 80, publicV4, "", "/", 0, ""))
	r = run(t, executor(t, nil, Limits{Benchmark: true}), benchmark)
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	port, err := net.LookupPort("tcp", value)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
