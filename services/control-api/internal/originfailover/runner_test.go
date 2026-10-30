package originfailover

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestTargetOfFollowsTheEdgeOriginRequest(t *testing.T) {
	pool := Pool{Domain: "www.example.com", HealthCheckPath: "/health?x=1", Scheme: "https", RequestHostMode: "visitor", Trust: "system"}
	target := TargetOf(pool, Origin{Host: "origin.example.net", Port: 443})
	if !target.HTTPS || target.HostHeader != "www.example.com" || target.ServerName != "www.example.com" || target.Path != "/health?x=1" {
		t.Fatalf("visitor https %+v", target)
	}
	if !peerEligible(target) {
		t.Fatal("HTTPS 443 host target with SNI = Host is for the tenant's node")
	}
	// MARKET_PROBE v3: Host != SNI, custom CA, IP origins, http and any port
	// are all for the tenant's node.
	pool.RequestHostMode, pool.SNI, pool.Trust, pool.CAPEM = "origin", "sni.example.com", "custom", "PEM"
	target = TargetOf(pool, Origin{Host: "origin.example.net", Port: 8443})
	if target.HostHeader != "origin.example.net" || target.ServerName != "sni.example.com" || target.CAPEM != "PEM" ||
		!peerEligible(target) {
		t.Fatalf("origin host %+v", target)
	}
	pool = Pool{Domain: "a.test", HealthCheckPath: "/", Scheme: "follow", RequestHostMode: "custom", RequestHost: "bucket.test"}
	target = TargetOf(pool, Origin{Host: "192.0.2.1", Port: 8080})
	if target.HTTPS || target.HostHeader != "bucket.test" || !peerEligible(target) {
		t.Fatalf("follow/custom %+v", target)
	}
	// A wildcard site's visitor Host is not a name a node can send.
	pool = Pool{Domain: "*.example.com", HealthCheckPath: "/", Scheme: "https", RequestHostMode: "visitor", Trust: "system"}
	if target = TargetOf(pool, Origin{Host: "origin.example.net", Port: 443}); peerEligible(target) {
		t.Fatalf("wildcard %+v", target)
	}
}

func TestControllerProberOutcomes(t *testing.T) {
	var gotHost, gotPath string
	status := http.StatusNoContent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.RequestURI()
		w.WriteHeader(status)
	}))
	defer server.Close()
	_, rawPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	allowAll := NewControllerProber(func(netip.Addr) bool { return false })
	target := Target{Host: "127.0.0.1", Port: port, HostHeader: "www.example.com", Path: "/health?x=1"}
	if outcome := allowAll.Probe(context.Background(), target); !outcome.OK || !outcome.Voted ||
		gotHost != "www.example.com" || gotPath != "/health?x=1" {
		t.Fatalf("ok %+v host=%s path=%s", outcome, gotHost, gotPath)
	}
	status = http.StatusNotFound // below 500: the origin answers
	if outcome := allowAll.Probe(context.Background(), target); !outcome.OK {
		t.Fatalf("404 %+v", outcome)
	}
	status = http.StatusBadGateway
	if outcome := allowAll.Probe(context.Background(), target); outcome.OK || !outcome.Voted || outcome.Reason != "status_5xx" {
		t.Fatalf("502 %+v", outcome)
	}
	server.Close()
	if outcome := allowAll.Probe(context.Background(), target); outcome.OK || !outcome.Voted || outcome.Reason != "connect" {
		t.Fatalf("refused %+v", outcome)
	}
	// the default policy refuses loopback: not probed, not a vote
	if outcome := NewControllerProber(nil).Probe(context.Background(), target); outcome.Voted || outcome.Reason != "blocked_address" {
		t.Fatalf("blocked %+v", outcome)
	}
}

func TestTallyNeedsTwoVotesAndAMajority(t *testing.T) {
	up, down := &Outcome{OK: true, Voted: true}, &Outcome{Voted: true, Reason: "timeout"}
	refused := &Outcome{Voted: true, Reason: "connect"}
	got := Tally([][]*Outcome{
		{up, up, down, up, nil, down},
		{up, down, down, nil, nil, refused},
		{nil, nil, refused, nil, nil, refused},
	})
	want := []*Outcome{up, nil, {Voted: true, Reason: "timeout"}, nil, nil, {Voted: true, Reason: "connect"}}
	for index := range want {
		if (got[index] == nil) != (want[index] == nil) || got[index] != nil && *got[index] != *want[index] {
			t.Fatalf("target %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

func TestOriginProbeTargetCarriesV3Fields(t *testing.T) {
	item := OriginProbeTarget("of-0", Target{Host: "203.0.113.9", Port: 8443, HTTPS: true, HostHeader: "www.example.com",
		ServerName: "origin.example.net", Path: "/healthz", CAPEM: "PEM"})
	if item.Scheme != "https" || item.Host != "203.0.113.9" || item.Port != 8443 || item.HostHeader != "www.example.com" ||
		item.ServerName != "origin.example.net" || item.CaPem != "PEM" || item.ExpectStatus != 0 || item.Ip != "" {
		t.Fatalf("https %+v", item)
	}
	item = OriginProbeTarget("of-1", Target{Host: "origin.example.net", Port: 80, HostHeader: "a.test", Path: "/"})
	if item.Scheme != "http" || item.ServerName != "" || item.CaPem != "" {
		t.Fatalf("http %+v", item)
	}
}

// fakePeers answers per node; calls records who was asked.
type fakePeers struct {
	mu      sync.Mutex
	answers map[string][]*Outcome
	calls   []string
}

func (peers *fakePeers) Probe(_ context.Context, nodeID string, targets []Target) []*Outcome {
	peers.mu.Lock()
	defer peers.mu.Unlock()
	peers.calls = append(peers.calls, nodeID)
	out := make([]*Outcome, len(targets))
	copy(out, peers.answers[nodeID])
	return out
}

type fakeController struct{ probed []string }

func (controller *fakeController) Probe(_ context.Context, target Target) Outcome {
	controller.probed = append(controller.probed, target.Host)
	return Outcome{OK: true, Voted: true}
}

func TestRunnerPrefersNodesAndFallsBackToTheControlPlane(t *testing.T) {
	pool := Pool{Domain: "www.example.com", HealthCheckPath: "/", Scheme: "http", RequestHostMode: "visitor",
		Origins: []Origin{{Host: "203.0.113.1", Port: 8080, Enabled: true}, {Host: "203.0.113.2", Port: 80, Enabled: true, Level: 1},
			{Host: "203.0.113.3", Port: 80, Level: 2}}}
	down := &Outcome{Voted: true, Reason: "connect"}
	peers := &fakePeers{answers: map[string][]*Outcome{
		"n1": {down, {OK: true, Voted: true}}, "n2": {down, nil}, "n3": {down, nil}, "n4": {down, down}}}
	controller := &fakeController{}
	runner := NewRunner(nil, nil, controller, peers, nil)
	outcomes := runner.probe(context.Background(), pool, []string{"n1", "n2", "n3", "n4"}, nodeThenController, 1)
	if len(peers.calls) != PeerProbers {
		t.Fatalf("asked %v", peers.calls)
	}
	// Origin 1: every asked node says down. Origin 2: at most one or two
	// split votes, so the control plane decides. Origin 3 is disabled.
	if got := outcomes["203.0.113.1|8080"]; got.OK || !got.Voted || got.Reason != "connect" {
		t.Fatalf("origin 1 %+v", got)
	}
	if got := outcomes["203.0.113.2|80"]; !got.OK || len(controller.probed) != 1 || controller.probed[0] != "203.0.113.2" {
		t.Fatalf("origin 2 %+v, controller %v", got, controller.probed)
	}
	if _, probed := outcomes["203.0.113.3|80"]; probed {
		t.Fatal("a disabled origin was probed")
	}
	// One v3 node is not enough: the control plane probes everything.
	peers.calls, controller.probed = nil, nil
	outcomes = runner.probe(context.Background(), pool, []string{"n4"}, nodeThenController, 1)
	if len(peers.calls) != 0 || len(controller.probed) != 2 || !outcomes["203.0.113.1|8080"].OK {
		t.Fatalf("single node: asked %v, controller %v", peers.calls, controller.probed)
	}
}

var nodeThenController = dnspupprobe.Runtime{OriginSources: []string{dnspupprobe.SourceNode, dnspupprobe.SourceController}}

// fakeDNSPup answers per (site, origin key) with checkpoint results and
// records what was asked.
type fakeDNSPup struct {
	mu      sync.Mutex
	results map[string][]dnspupprobe.Result
	err     error
	asked   []dnspupprobe.ProbeRequest
	keys    []string
}

func (fake *fakeDNSPup) probe(_ context.Context, consumer, _, target string, _ int64, request dnspupprobe.ProbeRequest) ([]dnspupprobe.Result, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if consumer != dnspupprobe.ConsumerOrigin {
		return nil, errors.New("wrong consumer")
	}
	fake.asked, fake.keys = append(fake.asked, request), append(fake.keys, target)
	return fake.results[target], fake.err
}

func checkpoints(statuses ...int) []dnspupprobe.Result {
	var out []dnspupprobe.Result
	for index, status := range statuses {
		result := dnspupprobe.Result{NodeID: "cp" + strconv.Itoa(index), Region: "广东", ISP: "电信", Status: "ok", HTTPStatus: status}
		switch {
		case status == 0:
			result.Status = "bad"
		case status < 0:
			result.Status, result.HTTPStatus = "unavailable", 0
		}
		out = append(out, result)
	}
	return out
}

func TestDNSPupFillsUpNodeVotesBeforeTheControlPlane(t *testing.T) {
	pool := Pool{SiteID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), Domain: "www.example.com",
		HealthCheckPath: "/health", Scheme: "https", RequestHostMode: "origin", Trust: "system",
		Origins: []Origin{{Host: "origin.example.net", Port: 443, Enabled: true}, {Host: "203.0.113.2", Port: 443, Enabled: true, Level: 1}}}
	down := &Outcome{Voted: true, Reason: "connect"}
	peers := &fakePeers{answers: map[string][]*Outcome{"n1": {down, {OK: true, Voted: true}}}}
	controller := &fakeController{}
	dnspup := &fakeDNSPup{results: map[string][]dnspupprobe.Result{
		"origin.example.net|443": checkpoints(0, 503, -1), // 2 failures + 1 unavailable (no vote)
		"203.0.113.2|443":        checkpoints(-1, -1),     // no checkpoint answered
	}}
	plan := dnspupprobe.Runtime{OriginSources: dnspupprobe.DefaultOriginSources, Probe: dnspup.probe}
	runner := NewRunner(nil, nil, controller, peers, nil)

	outcomes := runner.probe(context.Background(), pool, []string{"n1"}, plan, 9)
	// Origin 1: node "down" + 2 dnspup failures = a verdict without the control plane.
	if got := outcomes["origin.example.net|443"]; got.OK || !got.Voted || got.Reason == "" {
		t.Fatalf("origin 1 %+v", got)
	}
	if len(peers.calls) != 1 || len(dnspup.asked) != 2 {
		t.Fatalf("asked peers %v dnspup %+v", peers.calls, dnspup.asked)
	}
	for _, request := range dnspup.asked {
		if request.Type != "http" || request.Method != "GET" ||
			request.Target != "https://origin.example.net/health" && request.Target != "https://203.0.113.2/health" {
			t.Fatalf("dnspup request %+v", request)
		}
	}
	// Origin 2: one node vote, dnspup none: the control plane decides.
	if got := outcomes["203.0.113.2|443"]; !got.OK || len(controller.probed) != 1 || controller.probed[0] != "203.0.113.2" {
		t.Fatalf("origin 2 %+v controller %v", got, controller.probed)
	}
}

func TestDNSPupSkipsTargetsItCannotExpress(t *testing.T) {
	// The edge connects to an IP with the visitor's Host: dnspup's http probe
	// cannot send a different Host, so it is not asked (no charge).
	pool := Pool{SiteID: uuid.MustParse("00000000-0000-4000-8000-000000000005"), Domain: "www.example.com", HealthCheckPath: "/",
		Scheme: "http", RequestHostMode: "visitor", Origins: []Origin{{Host: "203.0.113.7", Port: 80, Enabled: true}}}
	controller := &fakeController{}
	dnspup := &fakeDNSPup{}
	plan := dnspupprobe.Runtime{OriginSources: dnspupprobe.DefaultOriginSources, Probe: dnspup.probe}
	outcomes := NewRunner(nil, nil, controller, nil, nil).probe(context.Background(), pool, nil, plan, 1)
	if len(dnspup.asked) != 0 || len(controller.probed) != 1 || !outcomes["203.0.113.7|80"].OK {
		t.Fatalf("dnspup %v controller %v", dnspup.asked, controller.probed)
	}
}

func TestDNSPupAloneDecidesWithoutNodes(t *testing.T) {
	pool := Pool{SiteID: uuid.MustParse("00000000-0000-4000-8000-000000000002"), Domain: "a.example.com", HealthCheckPath: "/",
		Scheme: "http", RequestHostMode: "origin", Origins: []Origin{{Host: "origin.example.net", Port: 8080, Enabled: true}}}
	controller := &fakeController{}
	// 404 from dnspup is "bad" there but an answer below 500 here: up.
	dnspup := &fakeDNSPup{results: map[string][]dnspupprobe.Result{"origin.example.net|8080": checkpoints(200, 404, 0)}}
	plan := dnspupprobe.Runtime{OriginSources: dnspupprobe.DefaultOriginSources, Probe: dnspup.probe}
	outcomes := NewRunner(nil, nil, controller, nil, nil).probe(context.Background(), pool, nil, plan, 1)
	if got := outcomes["origin.example.net|8080"]; !got.OK || !got.Voted || len(controller.probed) != 0 ||
		dnspup.asked[0].Target != "http://origin.example.net:8080/" {
		t.Fatalf("got %+v controller %v asked %+v", got, controller.probed, dnspup.asked)
	}
}

func TestDNSPupDegradedFallsBackToTheControlPlane(t *testing.T) {
	pool := Pool{SiteID: uuid.MustParse("00000000-0000-4000-8000-000000000003"), Domain: "a.example.com", HealthCheckPath: "/",
		Scheme: "http", RequestHostMode: "origin", Origins: []Origin{{Host: "origin.example.net", Port: 80, Enabled: true}}}
	controller := &fakeController{}
	// quota_exceeded / rate_limited: the source returns an error, no votes.
	dnspup := &fakeDNSPup{err: &dnspupprobe.APIError{Status: 429, Code: "quota_exceeded"}}
	plan := dnspupprobe.Runtime{OriginSources: dnspupprobe.DefaultOriginSources, Probe: dnspup.probe}
	outcomes := NewRunner(nil, nil, controller, nil, nil).probe(context.Background(), pool, nil, plan, 1)
	if got := outcomes["origin.example.net|80"]; !got.OK || len(controller.probed) != 1 || len(dnspup.asked) != 1 {
		t.Fatalf("got %+v controller %v", got, controller.probed)
	}
	// Paused (Probe nil): dnspup is skipped entirely.
	controller.probed, dnspup.asked = nil, nil
	plan.Probe = nil
	NewRunner(nil, nil, controller, nil, nil).probe(context.Background(), pool, nil, plan, 1)
	if len(dnspup.asked) != 0 || len(controller.probed) != 1 {
		t.Fatalf("paused: dnspup %v controller %v", dnspup.asked, controller.probed)
	}
}

func TestSourceOrderWithoutControllerLeavesUndecided(t *testing.T) {
	pool := Pool{SiteID: uuid.MustParse("00000000-0000-4000-8000-000000000004"), Domain: "a.example.com", HealthCheckPath: "/",
		Scheme: "http", RequestHostMode: "origin", Origins: []Origin{{Host: "origin.example.net", Port: 80, Enabled: true}}}
	controller := &fakeController{}
	// dnspup first, a 1:1 split: no verdict, and no controller in the order.
	dnspup := &fakeDNSPup{results: map[string][]dnspupprobe.Result{"origin.example.net|80": checkpoints(200, 0)}}
	plan := dnspupprobe.Runtime{OriginSources: []string{dnspupprobe.SourceDNSPup, dnspupprobe.SourceNode}, Probe: dnspup.probe}
	outcomes := NewRunner(nil, nil, controller, nil, nil).probe(context.Background(), pool, nil, plan, 1)
	if _, decided := outcomes["origin.example.net|80"]; decided || len(controller.probed) != 0 {
		t.Fatalf("outcomes %+v controller %v", outcomes, controller.probed)
	}
}

func TestPickPeersSpreadsAndBounds(t *testing.T) {
	nodes := []string{"a", "b", "c", "d", "e"}
	site := uuid.MustParse("00000000-0000-4000-8000-000000000003")
	if got := pickPeers(site, nodes); len(got) != PeerProbers || got[0] != "d" || got[1] != "e" || got[2] != "a" {
		t.Fatalf("picked %v", got)
	}
	if got := pickPeers(site, nodes[:2]); len(got) != 2 {
		t.Fatalf("picked %v", got)
	}
}

// requesterFunc answers a MarketProbeCommand.
type requesterFunc func(ctx context.Context, nodeID string, command []byte) ([]byte, error)

func (f requesterFunc) Request(ctx context.Context, nodeID string, command []byte) ([]byte, error) {
	return f(ctx, nodeID, command)
}

func TestNodePeerProberSendsOriginTargetsAndMapsResults(t *testing.T) {
	var sent agentv1.MarketProbeCommand
	prober := NewNodePeerProber(requesterFunc(func(_ context.Context, nodeID string, payload []byte) ([]byte, error) {
		if err := proto.Unmarshal(payload, &sent); err != nil {
			return nil, err
		}
		outcomes := []agentv1.MarketProbeOutcome{agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
			agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED,
			agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED}
		codes := []string{"", "status", "resolve", "rejected_address"}
		result := &agentv1.MarketProbeResult{NodeId: nodeID, CommandEventId: sent.Event.EventId}
		for index, target := range sent.Targets {
			result.Results = append(result.Results, &agentv1.MarketProbeTargetResult{TaskId: target.TaskId,
				Outcome: outcomes[index], ErrorCode: codes[index]})
		}
		return proto.Marshal(result)
	}))
	targets := []Target{
		{Host: "203.0.113.1", Port: 8080, HostHeader: "a.test", Path: "/"},
		{Host: "origin.example.net", Port: 8443, HTTPS: true, HostHeader: "a.test", ServerName: "sni.test", Path: "/", CAPEM: "PEM"},
		{Host: "origin.example.net", Port: 80, HostHeader: "a.test", Path: "/"},
		{Host: "10.0.0.1", Port: 80, HostHeader: "a.test", Path: "/"},
	}
	got := prober.Probe(context.Background(), "node-1", targets)
	if sent.NodeId != "node-1" || len(sent.Targets) != 4 || sent.Targets[1].Scheme != "https" || sent.Targets[1].CaPem != "PEM" ||
		sent.Targets[1].Port != 8443 || sent.Targets[0].ExpectStatus != 0 {
		t.Fatalf("sent %+v", sent.Targets)
	}
	if got[0] == nil || !got[0].OK || got[1] == nil || got[1].Reason != "status_5xx" || got[2] == nil || got[2].Reason != "connect" ||
		got[3] != nil {
		t.Fatalf("results %+v %+v %+v %+v", got[0], got[1], got[2], got[3])
	}
}
