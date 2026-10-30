package gatewayclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type recordingDialer struct {
	name  string
	fail  bool
	calls *[]string
}

func (d recordingDialer) Dial(context.Context) (Connection, error) {
	*d.calls = append(*d.calls, d.name)
	if d.fail {
		return nil, errors.New(d.name + " down")
	}
	return fakeConnection{}, nil
}

type fakeConnection struct{}

func (fakeConnection) Client() agentv1.AgentGatewayServiceClient { return nil }
func (fakeConnection) Close() error                              { return nil }

func newTestFailover(calls *[]string, down map[string]bool, base MTLSDialerConfig, extra ...GatewayEndpoint) *FailoverDialer {
	return &FailoverDialer{primary: recordingDialer{name: "primary/" + base.Transport, fail: down["primary/"+base.Transport], calls: calls}, base: base, extra: extra,
		newMTLS: func(config MTLSDialerConfig) (Dialer, error) {
			name := config.Address + "/" + config.Transport
			if config.Address == base.Address {
				name = "primary/" + config.Transport
			}
			return recordingDialer{name: name, fail: down[name], calls: calls}, nil
		}}
}

func TestFailoverDialerMovesToNextEndpointAndWraps(t *testing.T) {
	var calls []string
	base := MTLSDialerConfig{Address: "gw-a:21444", Transport: "ws", TunnelAudience: "aud"}
	dialer := newTestFailover(&calls, map[string]bool{"primary/ws": true}, base, GatewayEndpoint{Address: "gw-b:21444", ServerName: "gw", Transport: "grpc"})
	if _, err := dialer.Dial(context.Background()); err == nil {
		t.Fatal("down primary returned a connection")
	}
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatalf("second endpoint: %v", err)
	}
	// A healthy endpoint stays selected.
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"primary/ws", "gw-b:21444/grpc", "gw-b:21444/grpc"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls = %v, want %v", calls, want)
		}
	}
	// Second endpoint fails too: the list wraps to the primary.
	calls = nil
	dialer.newMTLS = func(config MTLSDialerConfig) (Dialer, error) {
		return recordingDialer{name: config.Address + "/" + config.Transport, fail: true, calls: &calls}, nil
	}
	_, _ = dialer.Dial(context.Background())
	_, _ = dialer.Dial(context.Background())
	if calls[len(calls)-1] != "primary/ws" {
		t.Fatalf("list did not wrap: %v", calls)
	}
}

func TestFailoverDialerRetriesGRPCAsTunnelOnSameAddress(t *testing.T) {
	var calls []string
	base := MTLSDialerConfig{Address: "gw-a:21444", Transport: "grpc", TunnelAudience: "aud"}
	dialer := newTestFailover(&calls, map[string]bool{"primary/grpc": true}, base)
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatalf("ws retry on the same address: %v", err)
	}
	if len(calls) != 2 || calls[0] != "primary/grpc" || calls[1] != "primary/ws" {
		t.Fatalf("calls = %v", calls)
	}
	// ws never falls back to grpc.
	calls = nil
	ws := newTestFailover(&calls, map[string]bool{"primary/ws": true}, MTLSDialerConfig{Address: "gw-a:443", Transport: "ws", TunnelAudience: "aud"})
	_, _ = ws.Dial(context.Background())
	if len(calls) != 1 {
		t.Fatalf("ws entry retried: %v", calls)
	}
}

// Without alternatives the dialer only ever uses the primary (the control
// plane may still publish a list later, so the wrapper always exists).
func TestNewFailoverDialerWithoutAlternativesDialsPrimaryOnly(t *testing.T) {
	var calls []string
	primary := recordingDialer{name: "p", fail: true, calls: &calls}
	dialer, err := NewFailoverDialer(primary, MTLSDialerConfig{Transport: "ws", TunnelAudience: "aud"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = dialer.Dial(context.Background())
	_, _ = dialer.Dial(context.Background())
	if len(calls) != 2 || calls[0] != "p" || calls[1] != "p" {
		t.Fatalf("calls = %v", calls)
	}
}

func endpointV1(address, transport string) *agentv1.GatewayEndpointV1 {
	return &agentv1.GatewayEndpointV1{Address: address, ServerName: "gw.example.com", Transport: transport}
}

// GW-07: the GatewayHello list is appended after the configured entries,
// deduplicated, persisted and reloaded; an empty version keeps it.
func TestFailoverDialerLearnsPersistsAndReloadsThePublishedList(t *testing.T) {
	file := filepath.Join(t.TempDir(), "gateway-endpoints.json")
	base := MTLSDialerConfig{Address: "gw-a:21444", Transport: "grpc", TunnelAudience: "aud"}
	var calls []string
	configured := GatewayEndpoint{Address: "gw-c:21444", ServerName: "gw", Transport: "grpc"}
	open := func() *FailoverDialer {
		d := newTestFailover(&calls, nil, base, configured)
		d.loadLearned(file)
		return d
	}
	dialer := open()
	dialer.Learn([]*agentv1.GatewayEndpointV1{endpointV1("gw-a:21444", "grpc"), endpointV1("gw-c:21444", "grpc"),
		endpointV1("gw-b:21444", "grpc"), endpointV1("cdn.example.com:443", "ws"), endpointV1("", "grpc"), endpointV1("x:1", "tcp")}, "v1")
	if got := dialer.entries(); len(got) != 3 || got[1].Address != "gw-b:21444" || got[2].Address != "cdn.example.com:443" {
		t.Fatalf("entries = %+v", got)
	}
	dialer.Learn(nil, "")
	if len(dialer.entries()) != 3 {
		t.Fatal("empty version dropped the stored list")
	}
	if reloaded := open(); len(reloaded.entries()) != 3 || reloaded.learnedVersion != "v1" {
		t.Fatalf("reloaded = %+v", reloaded.entries())
	}
	// A new version replaces the learned part only.
	dialer.Learn([]*agentv1.GatewayEndpointV1{endpointV1("gw-d:21444", "grpc")}, "v2")
	if got := dialer.entries(); len(got) != 2 || got[0] != configured || got[1].Address != "gw-d:21444" {
		t.Fatalf("entries after v2 = %+v", got)
	}
	// A corrupt file is ignored.
	if err := os.WriteFile(file, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if broken := open(); len(broken.entries()) != 1 {
		t.Fatalf("corrupt file = %+v", broken.entries())
	}
}

// Failover reaches learned entries; once an earlier one answers again the
// probe moves the start of the next session back without dialing through
// the current session.
func TestFailoverDialerFallbackProbeReturnsToEarlierEndpoint(t *testing.T) {
	var calls []string
	down := map[string]bool{"primary/ws": true}
	base := MTLSDialerConfig{Address: "gw-a:443", Transport: "ws", TunnelAudience: "aud"}
	dialer := newTestFailover(&calls, down, base)
	dialer.Learn([]*agentv1.GatewayEndpointV1{endpointV1("gw-b:21444", "grpc")}, "v1")
	_, _ = dialer.Dial(context.Background())
	if _, err := dialer.Dial(context.Background()); err != nil || dialer.next != 1 {
		t.Fatalf("learned endpoint not used: %v next=%d", err, dialer.next)
	}
	dialer.probeEarlier(context.Background(), time.Second)
	if dialer.next != 1 {
		t.Fatal("probe moved back to a down endpoint")
	}
	dialer.primary = recordingDialer{name: "primary/ws", calls: &calls}
	dialer.probeEarlier(context.Background(), time.Second)
	if dialer.next != 0 {
		t.Fatal("probe did not move back to the recovered primary")
	}
	// Re-learning keeps pointing at the same endpoint.
	dialer.next = 1
	dialer.Learn([]*agentv1.GatewayEndpointV1{endpointV1("gw-z:21444", "grpc"), endpointV1("gw-b:21444", "grpc")}, "v2")
	if dialer.next != 2 {
		t.Fatalf("current endpoint lost after relearn: next=%d", dialer.next)
	}
}

// ADR 0013 §5.2: a disabled Gateway's migration moves the next session to the
// first reachable other endpoint; the fallback probe does not return to the
// disabled one until a new list names it again. The enrollment address of a
// published entry is kept for re-enrollment.
func TestFailoverDialerMigratesAwayFromDisabledGateway(t *testing.T) {
	file := filepath.Join(t.TempDir(), "gateway-endpoints.json")
	var calls []string
	down := map[string]bool{"gw-b:21444/grpc": true, "gw-b:21444/ws": true}
	base := MTLSDialerConfig{Address: "gw-a:21444", Transport: "grpc", TunnelAudience: "aud"}
	dialer := newTestFailover(&calls, down, base)
	dialer.learnedFile = file
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, c := endpointV1("gw-b:21444", "grpc"), endpointV1("gw-c:21444", "grpc")
	b.EnrollmentAddress, c.EnrollmentAddress = "gw-b:21443", "gw-c:21443"
	calls = nil
	if !dialer.Migrate(context.Background(), []*agentv1.GatewayEndpointV1{b, c}, "v2", time.Second) {
		t.Fatal("no endpoint chosen")
	}
	// gw-b is down (and also tried as ws on the same port), gw-c answers.
	if dialer.next != 2 || len(calls) == 0 || calls[len(calls)-1] != "gw-c:21444/grpc" {
		t.Fatalf("next=%d calls=%v", dialer.next, calls)
	}
	if got := dialer.entries(); len(got) != 2 || got[1].EnrollmentAddress != "gw-c:21443" {
		t.Fatalf("entries = %+v", got)
	}
	reloaded := newTestFailover(&calls, nil, base)
	reloaded.loadLearned(file)
	if got := reloaded.entries(); len(got) != 2 || got[0].EnrollmentAddress != "gw-b:21443" {
		t.Fatalf("enrollment address not persisted: %+v", got)
	}
	// The disabled primary answers TLS but is avoided by the fallback probe.
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	dialer.probeEarlier(context.Background(), time.Second)
	if dialer.next != 2 {
		t.Fatalf("probe returned to the disabled gateway: next=%d", dialer.next)
	}
	// A new list naming it again (re-enabled) lifts the avoidance.
	dialer.Learn([]*agentv1.GatewayEndpointV1{endpointV1("gw-a:21444", "grpc"), c}, "v3")
	dialer.probeEarlier(context.Background(), time.Second)
	if dialer.next != 0 {
		t.Fatalf("re-enabled gateway still avoided: next=%d", dialer.next)
	}
}

// Nothing else answers: stay (the Gateway closes the session later).
func TestFailoverDialerMigrateWithoutReachableEndpointStays(t *testing.T) {
	var calls []string
	base := MTLSDialerConfig{Address: "gw-a:21444", Transport: "grpc", TunnelAudience: "aud"}
	dialer := newTestFailover(&calls, map[string]bool{"gw-b:21444/grpc": true, "gw-b:21444/ws": true}, base)
	if dialer.Migrate(context.Background(), []*agentv1.GatewayEndpointV1{endpointV1("gw-b:21444", "grpc")}, "v2", time.Second) || dialer.next != 0 {
		t.Fatalf("moved to an unreachable endpoint: next=%d", dialer.next)
	}
}

// A connected dial whose session is refused before the GatewayHello (a
// disabled Gateway still completes TLS) moves on to the next entry.
func TestFailoverDialerSessionRefusedMovesToNextEntry(t *testing.T) {
	var calls []string
	base := MTLSDialerConfig{Address: "gw-a:21444", Transport: "grpc", TunnelAudience: "aud"}
	dialer := newTestFailover(&calls, nil, base, GatewayEndpoint{Address: "gw-b:21444", ServerName: "gw", Transport: "grpc"})
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	dialer.SessionRefused()
	if _, err := dialer.Dial(context.Background()); err != nil || calls[len(calls)-1] != "gw-b:21444/grpc" {
		t.Fatalf("calls = %v, %v", calls, err)
	}
	dialer.SessionRefused()
	_, _ = dialer.Dial(context.Background())
	if calls[len(calls)-1] != "primary/grpc" {
		t.Fatalf("list did not wrap: %v", calls)
	}
}
