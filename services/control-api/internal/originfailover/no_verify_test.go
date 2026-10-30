package originfailover

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
)

// fix-originnoverify: a pool that does not verify the origin certificate
// (tls_trust none) is probed the way the edge reaches it: the control plane
// accepts a self-signed origin. Neither a node (MARKET_PROBE v3 always
// verifies) nor dnspup can express that, so the target is the control
// plane's only; otherwise a healthy self-signed origin would be voted down.
func TestNoVerifyPoolIsProbedWithoutVerification(t *testing.T) {
	pool := Pool{Domain: "www.example.com", HealthCheckPath: "/", Scheme: "https", RequestHostMode: "visitor", Trust: "none"}
	target := TargetOf(pool, Origin{Host: "origin.example.net", Port: 443})
	if !target.HTTPS || !target.NoVerify || target.CAPEM != "" {
		t.Fatalf("target %+v", target)
	}
	if peerEligible(target) {
		t.Fatal("a node would verify the certificate")
	}
	if _, ok := dnspupprobe.HTTPURL(dnspupTarget(target)); ok {
		t.Fatal("dnspup would verify the certificate")
	}
	if system := TargetOf(Pool{Domain: "www.example.com", HealthCheckPath: "/", Scheme: "https", RequestHostMode: "visitor",
		Trust: "system"}, Origin{Host: "origin.example.net", Port: 443}); system.NoVerify {
		t.Fatal("system trust verifies")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	_, rawPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	prober := NewControllerProber(func(netip.Addr) bool { return false })
	selfSigned := Target{Host: "127.0.0.1", Port: port, HTTPS: true, HostHeader: "www.example.com", ServerName: "www.example.com", Path: "/"}
	if outcome := prober.Probe(context.Background(), selfSigned); outcome.OK || outcome.Reason != "tls" {
		t.Fatalf("verified probe of a self-signed origin %+v", outcome)
	}
	selfSigned.NoVerify = true
	if outcome := prober.Probe(context.Background(), selfSigned); !outcome.OK || !outcome.Voted {
		t.Fatalf("no-verify probe %+v", outcome)
	}
}
