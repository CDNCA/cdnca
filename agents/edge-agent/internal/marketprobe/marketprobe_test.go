package marketprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	nodeID   = "8f3c2d1e-0000-4000-8000-000000000001"
	publicV4 = "8.8.8.8"
	publicV6 = "2606:4700::1111"
)

func command(targets ...*agentv1.MarketProbeTarget) *agentv1.MarketProbeCommand {
	return &agentv1.MarketProbeCommand{Event: &commonv1.EventMetadata{EventId: "e1"}, NodeId: nodeID,
		Targets: targets, TimeoutMillis: 2000, ExpireTime: timestamppb.New(time.Now().Add(time.Minute))}
}

func target(id, ip string, port uint32) *agentv1.MarketProbeTarget {
	return &agentv1.MarketProbeTarget{TaskId: id, Ip: ip, Port: port}
}

// executor routes every dial to server, whatever public address was admitted.
func executor(t *testing.T, server *httptest.Server, limits Limits) *Executor {
	t.Helper()
	e, err := New(nodeID, limits, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if server != nil {
		local := server.Listener.Addr().String()
		e.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, local)
		}
	}
	return e
}

func run(t *testing.T, e *Executor, c *agentv1.MarketProbeCommand) []*agentv1.MarketProbeTargetResult {
	t.Helper()
	results, err := e.Execute(context.Background(), c)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(results) != len(c.Targets) {
		t.Fatalf("results %d for %d targets", len(results), len(c.Targets))
	}
	return results
}

func expect(t *testing.T, r *agentv1.MarketProbeTargetResult, outcome agentv1.MarketProbeOutcome, code string) {
	t.Helper()
	if r.Outcome != outcome || r.ErrorCode != code {
		t.Fatalf("task %s: got %s/%q, want %s/%q", r.TaskId, r.Outcome, r.ErrorCode, outcome, code)
	}
}

func probeServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func TestProbeOK(t *testing.T) {
	var gotPath, gotHost, gotMethod atomic.Value
	server := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		gotHost.Store(r.Host)
		gotMethod.Store(r.Method)
		w.WriteHeader(http.StatusNoContent)
	})
	r := run(t, executor(t, server, Limits{}), command(target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	if gotPath.Load() != Path || gotHost.Load() != publicV4 || gotMethod.Load() != http.MethodGet {
		t.Fatalf("request %v %v %v", gotMethod.Load(), gotHost.Load(), gotPath.Load())
	}
}

func TestProbeHTTPSIgnoresCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	r := run(t, executor(t, server, Limits{}), command(target("a", publicV6, 443)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
}

func TestNon2xxFails(t *testing.T) {
	server := probeServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMisdirectedRequest) })
	r := run(t, executor(t, server, Limits{}), command(target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "status")
}

func TestRedirectNotFollowed(t *testing.T) {
	var followed atomic.Bool
	server := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			followed.Store(true)
		}
		http.Redirect(w, r, "http://127.0.0.1/elsewhere", http.StatusFound)
	})
	r := run(t, executor(t, server, Limits{}), command(target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "status")
	if followed.Load() {
		t.Fatal("redirect was followed")
	}
}

func TestTimeout(t *testing.T) {
	server := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})
	c := command(target("a", publicV4, 80))
	c.TimeoutMillis = 200
	started := time.Now()
	r := run(t, executor(t, server, Limits{}), c)
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "timeout")
	if time.Since(started) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestBodyReadIsBounded(t *testing.T) {
	server := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("x", 4096))
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	started := time.Now()
	r := run(t, executor(t, server, Limits{}), command(target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	if time.Since(started) > time.Second {
		t.Fatal("endless body was read past the bound")
	}
}

func TestRejectedAddresses(t *testing.T) {
	var hits atomic.Int32
	server := probeServer(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	for _, ip := range []string{
		"10.1.2.3", "172.16.0.1", "192.168.1.1", // private
		"127.0.0.1", "::1", // loopback
		"169.254.1.1", "fe80::1", // link-local
		"100.64.0.1", "100.127.255.254", // CGNAT
		"224.0.0.1", "ff02::1", // multicast
		"0.0.0.0", "::", "0.1.2.3", // unspecified / this network
		"240.0.0.1", "255.255.255.255", // reserved / broadcast
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", // documentation
		"198.18.0.1", "192.0.0.8", // benchmarking / IETF
		"fc00::1", "fd12::1", // unique local
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", // mapped private
		"64:ff9b:1::1", "2002:a00:1::1", "100::1", "3fff::1", // NAT64 local / 6to4 / discard / doc
		"fe80::1%eth0", "not-an-ip", "", "8.8.8.8:80",
	} {
		r := run(t, executor(t, server, Limits{}), command(target("a", ip, 80)))
		expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rejected_address")
	}
	if hits.Load() != 0 {
		t.Fatalf("rejected addresses were dialled %d times", hits.Load())
	}
	for _, ip := range []string{publicV4, publicV6, "1.1.1.1", "::ffff:8.8.8.8"} {
		if !Public(netip.MustParseAddr(ip)) {
			t.Fatalf("%s should be public", ip)
		}
	}
}

func TestRejectedPorts(t *testing.T) {
	for _, port := range []uint32{0, 22, 8080, 8443, 65535, 70000} {
		r := run(t, executor(t, nil, Limits{}), command(target("a", publicV4, port)))
		expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rejected_port")
	}
}

func TestInvalidAndDuplicateTargets(t *testing.T) {
	server := probeServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r := run(t, executor(t, server, Limits{}), command(target("a", publicV4, 80), target("a", publicV4, 80),
		target("", publicV4, 80), target(strings.Repeat("t", 129), publicV4, 80), nil))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	for _, result := range r[1:] {
		expect(t, result, agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_target")
	}
}

func TestExpiredTargetsSkipped(t *testing.T) {
	c := command(target("a", publicV4, 80))
	c.ExpireTime = timestamppb.New(time.Now().Add(-time.Second))
	r := run(t, executor(t, nil, Limits{}), c)
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "expired")
}

func TestRateLimit(t *testing.T) {
	server := probeServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	now := time.Now()
	e := executor(t, server, Limits{PerMinute: 2})
	e.now = func() time.Time { return now }
	c := command(target("a", publicV4, 80), target("b", publicV4, 80), target("c", publicV4, 80))
	r := run(t, e, c)
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	expect(t, r[1], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	expect(t, r[2], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rate_limited")
	now = now.Add(61 * time.Second)
	next := command(target("d", publicV4, 80))
	next.ExpireTime = timestamppb.New(now.Add(time.Minute))
	r = run(t, e, next)
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
}

func TestConcurrencyBound(t *testing.T) {
	var inFlight, peak atomic.Int32
	server := probeServer(t, func(w http.ResponseWriter, _ *http.Request) {
		current := inFlight.Add(1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	})
	targets := make([]*agentv1.MarketProbeTarget, 6)
	for i := range targets {
		targets[i] = target(string(rune('a'+i)), publicV4, 80)
	}
	run(t, executor(t, server, Limits{Concurrency: 2}), command(targets...))
	if peak.Load() > 2 {
		t.Fatalf("peak concurrency %d > 2", peak.Load())
	}
}

func TestInvalidCommands(t *testing.T) {
	e := executor(t, nil, Limits{})
	many := make([]*agentv1.MarketProbeTarget, MaxTargets+1)
	for i := range many {
		many[i] = target("t", publicV4, 80)
	}
	for name, mutate := range map[string]func(*agentv1.MarketProbeCommand){
		"other node":      func(c *agentv1.MarketProbeCommand) { c.NodeId = "8f3c2d1e-0000-4000-8000-000000000002" },
		"no event":        func(c *agentv1.MarketProbeCommand) { c.Event = nil },
		"no targets":      func(c *agentv1.MarketProbeCommand) { c.Targets = nil },
		"too many":        func(c *agentv1.MarketProbeCommand) { c.Targets = many },
		"timeout too big": func(c *agentv1.MarketProbeCommand) { c.TimeoutMillis = 10_001 },
		"timeout tiny":    func(c *agentv1.MarketProbeCommand) { c.TimeoutMillis = 99 },
		"no expiry":       func(c *agentv1.MarketProbeCommand) { c.ExpireTime = nil },
	} {
		c := command(target("a", publicV4, 80))
		mutate(c)
		if _, err := e.Execute(context.Background(), c); err != ErrInvalidCommand {
			t.Fatalf("%s: err %v", name, err)
		}
	}
	if _, err := e.Execute(context.Background(), nil); err != ErrInvalidCommand {
		t.Fatal("nil command accepted")
	}
}

func TestDialOnlyAdmittedAddress(t *testing.T) {
	e := executor(t, nil, Limits{})
	var dialled []string
	e.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		dialled = append(dialled, address)
		return nil, net.ErrClosed
	}
	r := run(t, e, command(target("a", publicV6, 443)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "connect")
	if len(dialled) != 1 || dialled[0] != "["+publicV6+"]:443" {
		t.Fatalf("dialled %v", dialled)
	}
}
