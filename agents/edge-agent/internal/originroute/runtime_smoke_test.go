package originroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type originRouteSmokeEvidence struct {
	ConditionalRoute        bool   `json:"conditional_route"`
	PriorityRoute           bool   `json:"priority_route"`
	ConnectFailover         bool   `json:"connect_failover"`
	ReadTimeoutFailover     bool   `json:"read_timeout_failover"`
	GETFailover             bool   `json:"get_failover"`
	HEADFailover            bool   `json:"head_failover"`
	POSTNotReplayed         bool   `json:"post_not_replayed"`
	TotalBudgetBounded      bool   `json:"total_budget_bounded"`
	L2Opened                bool   `json:"l2_opened"`
	L2ProbeRecovered        bool   `json:"l2_probe_recovered"`
	ForgedHopIgnored        bool   `json:"forged_hop_ignored"`
	RuntimeHopGenerated     bool   `json:"runtime_hop_generated"`
	ConnectFallbackHop      bool   `json:"connect_fallback_hop_zero"`
	ReadFallbackHop         bool   `json:"read_fallback_hop_zero"`
	HTTPFallbackHop         bool   `json:"http_502_fallback_hop_zero"`
	L2SuccessHop            bool   `json:"l2_success_hop_one"`
	InitialDirectHop        bool   `json:"initial_direct_hop_zero"`
	CircuitCapacityClosed   bool   `json:"circuit_capacity_fail_closed"`
	CircuitStateRecovered   bool   `json:"circuit_state_recovered"`
	MultiVersionExpired     bool   `json:"multi_version_state_expired"`
	CircuitRevisionIsolated bool   `json:"circuit_revision_isolated"`
	L2ProbeSingleOwner      bool   `json:"l2_probe_single_owner"`
	L2ProbeTokenFenced      bool   `json:"l2_probe_token_fenced"`
	L2ProbeCrashExpiry      bool   `json:"l2_probe_crash_expiry"`
	ProbeReleaseAtomic      bool   `json:"probe_release_atomic"`
	IPv4SourceBound         bool   `json:"ipv4_source_bound"`
	IPv6SourceBound         bool   `json:"ipv6_source_bound"`
	ConcurrentReload        bool   `json:"concurrent_reload"`
	ReloadGenerationDrain   bool   `json:"reload_generation_drain"`
	BadPolicyKeptVersion    string `json:"bad_policy_kept_version"`
	HealthRollbackVersion   string `json:"health_rollback_version"`
	InitialFailureStopped   bool   `json:"initial_failure_stopped"`
	CurrentMatchesLKG       bool   `json:"current_matches_lkg"`
	Adaptive                bool   `json:"adaptive_p2c_ewma"`
}

type originRouteSmokeOrigin struct {
	id       string
	server   *http.Server
	listener net.Listener
	fail     atomic.Bool
	delayNS  atomic.Int64
	requests atomic.Int64
}

func newOriginRouteSmokeOrigin(t *testing.T, network, address, id string, delay time.Duration) *originRouteSmokeOrigin {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	origin := &originRouteSmokeOrigin{id: id, listener: listener}
	origin.delayNS.Store(int64(delay))
	origin.server = &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(origin.handle)}
	go func() { _ = origin.server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = origin.server.Shutdown(ctx)
	})
	return origin
}

func (origin *originRouteSmokeOrigin) handle(writer http.ResponseWriter, request *http.Request) {
	origin.requests.Add(1)
	if delay := time.Duration(origin.delayNS.Load()); delay > 0 {
		time.Sleep(delay)
	}
	writer.Header().Set("X-Origin", origin.id)
	host, _, _ := net.SplitHostPort(request.RemoteAddr)
	writer.Header().Set("X-Remote-IP", host)
	writer.Header().Set("X-Seen-Hop", request.Header.Get("X-CDNCA-Origin-Hop"))
	if origin.fail.Load() {
		http.Error(writer, "unavailable", http.StatusBadGateway)
		return
	}
	_, _ = io.WriteString(writer, origin.id)
}

func (origin *originRouteSmokeOrigin) setDelay(delay time.Duration) {
	origin.delayNS.Store(int64(delay))
}

func (origin *originRouteSmokeOrigin) endpoint(t *testing.T, id string, kind PoolKind, nodeID string) Endpoint {
	t.Helper()
	host, rawPort, err := net.SplitHostPort(origin.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := Endpoint{ID: id, Host: host, Port: uint16(port), Weight: 1}
	if kind == PoolL2 {
		endpoint.NodeID = nodeID
	}
	return endpoint
}

type injectedOriginRouteHealth struct {
	base        Runtime
	failVersion string
}

func (runtime injectedOriginRouteHealth) Precheck(ctx context.Context, release string) error {
	return runtime.base.Precheck(ctx, release)
}

func (runtime injectedOriginRouteHealth) Reload(ctx context.Context, release string) error {
	return runtime.base.Reload(ctx, release)
}

func (runtime injectedOriginRouteHealth) Healthy(ctx context.Context, version string) error {
	if err := runtime.base.Healthy(ctx, version); err != nil {
		return err
	}
	if version == runtime.failVersion {
		return errors.New("injected health rejection")
	}
	return nil
}

func (runtime injectedOriginRouteHealth) Stop(ctx context.Context) error {
	return runtime.base.Stop(ctx)
}

type originRouteSmokeResponse struct {
	status  int
	headers http.Header
	body    string
	elapsed time.Duration
}

const originRouteStateMinFreeBytes = 16384

func TestOriginRouteOpenRestySmoke(t *testing.T) {
	if os.Getenv("CDNCA_ORIGINROUTE_SMOKE") != "1" {
		t.Skip("set CDNCA_ORIGINROUTE_SMOKE=1 in the isolated OpenResty container")
	}
	binary := os.Getenv("CDNCA_OPENRESTY_BIN")
	luaRoot := os.Getenv("CDNCA_ORIGINROUTE_LUA_ROOT")
	if binary == "" || luaRoot == "" {
		t.Fatal("OpenResty binary and Lua root are required")
	}

	directA := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "A", 0)
	directB := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "B", 0)
	direct6 := newOriginRouteSmokeOrigin(t, "tcp6", "[::1]:0", "V6", 0)
	slowA := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "SLOW-A", 300*time.Millisecond)
	slowB := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "SLOW-B", 300*time.Millisecond)
	circuit := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "L2", 0)
	postOnly := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "POST-L2", 0)
	circuit.fail.Store(true)
	postOnly.fail.Store(true)
	deadPort := reserveOriginRouteSmokePort(t)
	listenPort := reserveOriginRouteSmokePort(t)
	policy := originRouteSmokePolicy(t, listenPort, deadPort, directA, directB, direct6, slowA, slowB, circuit, postOnly)

	stateRoot := privateOriginRouteSmokeDir(t)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		content, _ := os.ReadFile(filepath.Join(stateRoot, "shared", "originroute-error.log"))
		if len(content) > 16384 {
			content = content[len(content)-16384:]
		}
		t.Logf("OpenResty error log:\n%s", content)
	})
	baseRuntime, err := NewOpenRestyRuntime(binary, stateRoot, originRouteHealthProbe(listenPort))
	if err != nil {
		t.Fatal(err)
	}
	runtime := injectedOriginRouteHealth{base: baseRuntime, failVersion: "route-v3-rejected"}
	publisher, err := NewPublisher(stateRoot, luaRoot, SystemAddressInspector{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = baseRuntime.Stop(ctx)
	})

	if _, err := publisher.Apply(originRouteSmokeContext(t), policyJSON(t, policy)); err != nil {
		t.Fatalf("apply route-v1: %v", err)
	}
	evidence := originRouteSmokeEvidence{}
	logCircuitRequest := func(name string, before int64, response originRouteSmokeResponse) {
		t.Logf("circuit request=%s status=%d body=%q l2_requests_before=%d l2_requests_after=%d origin_event=%q origin_reason=%q",
			name, response.status, response.body, before, circuit.requests.Load(),
			response.headers.Get("X-CDNCA-Origin-Event"), response.headers.Get("X-CDNCA-Origin-Reason"))
	}
	evidence.ConditionalRoute = originRouteSmokeRequest(t, listenPort, http.MethodGet, "/conditional/item", nil).body == "A"
	evidence.PriorityRoute = originRouteSmokeRequest(t, listenPort, http.MethodGet, "/priority/item", nil).body == "A"
	connectFallback := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/connect", nil)
	readFallback := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/slow", nil)
	httpFallbackBefore := circuit.requests.Load()
	httpFallback := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/circuit", nil)
	logCircuitRequest("circuit-failure-1", httpFallbackBefore, httpFallback)
	evidence.ConnectFailover = connectFallback.body == "B"
	evidence.ReadTimeoutFailover = readFallback.body == "B"
	evidence.GETFailover = httpFallback.body == "B"
	evidence.ConnectFallbackHop = connectFallback.headers.Get("X-Seen-Hop") == "0"
	evidence.ReadFallbackHop = readFallback.headers.Get("X-Seen-Hop") == "0"
	evidence.HTTPFallbackHop = httpFallback.headers.Get("X-Seen-Hop") == "0"
	evidence.HEADFailover = originRouteSmokeRequest(t, listenPort, http.MethodHead, "/connect", nil).headers.Get("X-Origin") == "B"

	directBefore := directB.requests.Load()
	postOnlyBefore := postOnly.requests.Load()
	post := originRouteSmokeRequest(t, listenPort, http.MethodPost, "/post-no-replay", strings.NewReader("body"))
	evidence.POSTNotReplayed = post.status >= 500 && postOnly.requests.Load() == postOnlyBefore+1 &&
		directB.requests.Load() == directBefore

	secondFailureBefore := circuit.requests.Load()
	secondFailure := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/circuit", nil)
	logCircuitRequest("circuit-failure-2", secondFailureBefore, secondFailure)
	thirdFailureBefore := circuit.requests.Load()
	thirdFailure := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/circuit", nil)
	logCircuitRequest("circuit-failure-3", thirdFailureBefore, thirdFailure)
	waitOriginRouteRequestCountStable(t, circuit, time.Second)
	circuitBefore := circuit.requests.Load()
	opened := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/circuit", nil)
	logCircuitRequest("open-check", circuitBefore, opened)
	evidence.L2Opened = httpFallback.body == "B" && secondFailure.body == "B" && thirdFailure.body == "B" &&
		secondFailureBefore == httpFallbackBefore+1 &&
		thirdFailureBefore == secondFailureBefore+1 && circuitBefore == thirdFailureBefore+1 &&
		opened.body == "B" && circuit.requests.Load() == circuitBefore

	time.Sleep(1050 * time.Millisecond)
	circuit.fail.Store(false)
	firstProbeBefore := circuit.requests.Load()
	firstProbe := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/circuit", nil)
	logCircuitRequest("recovery-probe-1", firstProbeBefore, firstProbe)
	secondProbeBefore := circuit.requests.Load()
	secondProbe := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/circuit", nil)
	logCircuitRequest("recovery-probe-2", secondProbeBefore, secondProbe)
	closedBefore := circuit.requests.Load()
	closed := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/circuit", nil)
	logCircuitRequest("closed-check", closedBefore, closed)
	evidence.L2ProbeRecovered = firstProbe.body == "L2" && secondProbe.body == "L2" && closed.body == "L2"
	budget := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/budget", nil)
	evidence.TotalBudgetBounded = budget.status >= 500 && budget.elapsed < 800*time.Millisecond

	forgedBefore := circuit.requests.Load()
	forgedL2 := originRouteSmokeRequestWithHeaders(t, listenPort, http.MethodGet, "/circuit", nil,
		map[string]string{"X-CDNCA-Origin-Hop": "255"})
	logCircuitRequest("forged-hop", forgedBefore, forgedL2)
	forgedDirect := originRouteSmokeRequestWithHeaders(t, listenPort, http.MethodGet, "/ipv4", nil,
		map[string]string{"X-CDNCA-Origin-Hop": "255"})
	evidence.ForgedHopIgnored = forgedL2.body == "L2" && circuit.requests.Load() == forgedBefore+1
	evidence.L2SuccessHop = forgedL2.headers.Get("X-Seen-Hop") == "1"
	evidence.InitialDirectHop = forgedDirect.headers.Get("X-Seen-Hop") == "0"
	evidence.RuntimeHopGenerated = evidence.L2SuccessHop && evidence.InitialDirectHop
	v4 := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/ipv4", nil)
	v6 := originRouteSmokeRequest(t, listenPort, http.MethodGet, "/ipv6", nil)
	evidence.IPv4SourceBound = v4.headers.Get("X-Remote-IP") == "127.0.0.1"
	evidence.IPv6SourceBound = v6.headers.Get("X-Remote-IP") == "::1"

	policyDrain := policy
	policyDrain.Revision = 2
	policyDrain.VersionID = "route-drain-ready"
	policyDrain.Retry.ReadTimeoutMS = 1000
	policyDrain.Retry.TotalBudgetMS = 1200
	if _, err := publisher.Apply(originRouteSmokeContext(t), policyJSON(t, policyDrain)); err != nil {
		t.Fatalf("apply drain-ready policy: %v", err)
	}
	policyV2 := policyDrain
	policyV2.Revision = 3
	policyV2.VersionID = "route-v2"
	policyV2.DefaultPoolID = "direct-a"
	evidence.ConcurrentReload, evidence.ReloadGenerationDrain = concurrentOriginRouteReload(
		t, publisher, baseRuntime, directA, listenPort, policyV2)

	policyV2JSON := policyJSON(t, policyV2)
	bad := append(policyV2JSON[:len(policyV2JSON)-1], []byte(`,"unknown":true}`)...)
	if _, err := publisher.Apply(originRouteSmokeContext(t), bad); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("bad policy error=%v", err)
	}
	evidence.BadPolicyKeptVersion = originRouteHealthVersion(t, listenPort)

	policyV3 := policyV2
	policyV3.Revision = 4
	policyV3.VersionID = runtime.failVersion
	if _, err := publisher.Apply(originRouteSmokeContext(t), policyJSON(t, policyV3)); !errors.Is(err, ErrHealth) {
		t.Fatalf("health rollback error=%v", err)
	}
	waitOriginRouteHealthVersion(t, listenPort, "route-v2")
	evidence.HealthRollbackVersion = "route-v2"
	current, err := publisher.pointer("current")
	if err != nil {
		t.Fatal(err)
	}
	lkg, err := publisher.pointer("lkg")
	if err != nil {
		t.Fatal(err)
	}
	evidence.CurrentMatchesLKG = current != "" && current == lkg
	var circuitCapacityClosed, circuitStateRecovered, multiVersionExpired, circuitRevisionIsolated bool
	var l2ProbeSingleOwner, l2ProbeTokenFenced, l2ProbeCrashExpiry, probeReleaseAtomic bool
	var initialFailureStopped, adaptive bool
	t.Run("isolated-runtime-checks", func(t *testing.T) {
		t.Run("circuit-state", func(t *testing.T) {
			circuitCapacityClosed, circuitStateRecovered, multiVersionExpired,
				circuitRevisionIsolated, l2ProbeSingleOwner, l2ProbeTokenFenced,
				l2ProbeCrashExpiry, probeReleaseAtomic =
				verifyOriginRouteCircuitStateBounds(t, binary, luaRoot, directB, circuit)
		})
		t.Run("initial-failure", func(t *testing.T) {
			initialFailureStopped = verifyOriginRouteInitialFailure(t, binary, luaRoot, policy)
		})
		t.Run("adaptive", func(t *testing.T) {
			adaptive = verifyAdaptiveOriginRouteSmoke(t, binary, luaRoot)
		})
	})
	evidence.CircuitCapacityClosed, evidence.CircuitStateRecovered, evidence.MultiVersionExpired =
		circuitCapacityClosed, circuitStateRecovered, multiVersionExpired
	evidence.CircuitRevisionIsolated, evidence.L2ProbeSingleOwner, evidence.L2ProbeTokenFenced =
		circuitRevisionIsolated, l2ProbeSingleOwner, l2ProbeTokenFenced
	evidence.L2ProbeCrashExpiry, evidence.ProbeReleaseAtomic = l2ProbeCrashExpiry, probeReleaseAtomic
	evidence.InitialFailureStopped, evidence.Adaptive = initialFailureStopped, adaptive

	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for name, passed := range map[string]bool{
		"conditional": evidence.ConditionalRoute, "priority": evidence.PriorityRoute,
		"connect": evidence.ConnectFailover, "read timeout": evidence.ReadTimeoutFailover,
		"GET": evidence.GETFailover, "HEAD": evidence.HEADFailover, "POST": evidence.POSTNotReplayed,
		"budget": evidence.TotalBudgetBounded, "L2 open": evidence.L2Opened,
		"L2 recovery": evidence.L2ProbeRecovered, "forged hop": evidence.ForgedHopIgnored,
		"runtime hop": evidence.RuntimeHopGenerated, "connect fallback hop": evidence.ConnectFallbackHop,
		"read fallback hop": evidence.ReadFallbackHop, "HTTP fallback hop": evidence.HTTPFallbackHop,
		"L2 success hop": evidence.L2SuccessHop, "initial direct hop": evidence.InitialDirectHop,
		"circuit capacity":    evidence.CircuitCapacityClosed,
		"circuit recovery":    evidence.CircuitStateRecovered,
		"multi-version state": evidence.MultiVersionExpired,
		"circuit revision":    evidence.CircuitRevisionIsolated,
		"L2 probe owner":      evidence.L2ProbeSingleOwner,
		"L2 probe fencing":    evidence.L2ProbeTokenFenced,
		"L2 probe expiry":     evidence.L2ProbeCrashExpiry,
		"probe release CAS":   evidence.ProbeReleaseAtomic,
		"IPv4 bind":           evidence.IPv4SourceBound, "IPv6 bind": evidence.IPv6SourceBound,
		"reload": evidence.ConcurrentReload, "reload generation": evidence.ReloadGenerationDrain,
		"initial stop": evidence.InitialFailureStopped,
		"LKG":          evidence.CurrentMatchesLKG,
		"adaptive":     evidence.Adaptive,
	} {
		if !passed {
			t.Fatalf("%s smoke check failed: %s", name, encoded)
		}
	}
	if evidence.BadPolicyKeptVersion != "route-v2" || evidence.HealthRollbackVersion != "route-v2" {
		t.Fatalf("version preservation failed: %s", encoded)
	}
	fmt.Printf("EDGE_ORIGIN_ROUTE_SMOKE_EVIDENCE=%s\n", encoded)
}

func TestOriginRouteLeaseRound8OpenResty(t *testing.T) {
	if os.Getenv("CDNCA_ORIGINROUTE_SMOKE") != "1" {
		t.Skip("set CDNCA_ORIGINROUTE_SMOKE=1 in the isolated OpenResty container")
	}
	binary := os.Getenv("CDNCA_OPENRESTY_BIN")
	luaRoot := os.Getenv("CDNCA_ORIGINROUTE_LUA_ROOT")
	if binary == "" || luaRoot == "" {
		t.Fatal("OpenResty binary and Lua root are required")
	}
	direct := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "DIRECT", 0)
	l2 := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "L2", 0)
	l2.fail.Store(true)
	root := privateOriginRouteSmokeDir(t)
	for _, path := range []string{
		"versions", "staging", "shared", "shared/client-body-temp", "shared/proxy-temp",
		"shared/fastcgi-temp", "shared/uwsgi-temp", "shared/scgi-temp",
	} {
		if err := ensurePrivateDirectory(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	port := reserveOriginRouteSmokePort(t)
	policy := Policy{
		Schema: SchemaV1, Revision: 8, TenantID: "tenant-round8", SiteID: "site-round8", VersionID: "lease-round8",
		Node:      Node{ID: "l1-round8", Region: "cn-east", Tier: TierL1},
		Listeners: []Listener{{ID: "http", Address: "127.0.0.1", Port: port}},
		Pools: []Pool{
			{ID: "direct", Kind: PoolOrigin, Endpoints: []Endpoint{direct.endpoint(t, "direct", PoolOrigin, "")}},
			{ID: "l2", Kind: PoolL2, Endpoints: []Endpoint{l2.endpoint(t, "l2", PoolL2, "l2-node")}},
		},
		DefaultPoolID: "direct",
		Routes: []Route{{
			ID: "state", Priority: 10, PathPrefix: "/state",
			PoolID: "l2", FallbackPoolID: "direct",
		}},
		Retry: RetryPolicy{
			Methods: []string{"GET", "HEAD"}, MaxAttempts: 2,
			ConnectTimeoutMS: 100, ReadTimeoutMS: 500, TotalBudgetMS: 700,
		},
		L2: L2Policy{FailureThreshold: 2, RecoveryThreshold: 2, ProbeIntervalMS: 300, MaxHops: 2},
	}
	runtime, err := NewOpenRestyRuntime(binary, root, originRouteHealthProbe(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Stop(ctx)
	})
	release := installOriginRouteStateTestRelease(t, root, luaRoot, policy)
	activateOriginRouteStateTestRelease(t, runtime, root, release, policy.VersionID, port)
	for request := 0; request < 2; request++ {
		failed := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
		if failed.body != direct.id {
			t.Fatalf("Round-8 focused failure %d status=%d body=%q", request, failed.status, failed.body)
		}
		time.Sleep(120 * time.Millisecond)
	}
	waitOriginRouteRequestCountStable(t, l2, time.Second)
	l2Before := l2.requests.Load()
	open := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
	if open.body != direct.id || l2.requests.Load() != l2Before {
		t.Fatalf("Round-8 focused circuit open status=%d body=%q requests=%d/%d",
			open.status, open.body, l2.requests.Load(), l2Before)
	}
	blocked := originRouteSmokeRequest(t, port, http.MethodPost, "/__originroute_test_block", nil)
	routed := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
	if blocked.status != http.StatusOK || routed.body != direct.id {
		t.Fatalf("Round-8 focused circuit state status=%d body=%q routed=%q",
			blocked.status, blocked.body, routed.body)
	}
	verifyOriginRouteLeaseRound8(t, port)
}

func originRouteSmokePolicy(
	t *testing.T, listenPort, deadPort uint16,
	directA, directB, direct6, slowA, slowB, circuit, postOnly *originRouteSmokeOrigin,
) Policy {
	t.Helper()
	directAPool := Pool{ID: "direct-a", Kind: PoolOrigin, Endpoints: []Endpoint{directA.endpoint(t, "direct-a-1", PoolOrigin, "")}}
	directBPool := Pool{ID: "direct-b", Kind: PoolOrigin, Endpoints: []Endpoint{directB.endpoint(t, "direct-b-1", PoolOrigin, "")}}
	direct6Pool := Pool{ID: "direct-v6", Kind: PoolOrigin, Endpoints: []Endpoint{direct6.endpoint(t, "direct-v6-1", PoolOrigin, "")}}
	return Policy{
		Schema: SchemaV1, Revision: 1, TenantID: "tenant-smoke", SiteID: "site-smoke", VersionID: "route-v1",
		Node: Node{ID: "l1-smoke", Region: "cn-east", Tier: TierL1},
		Listeners: []Listener{{
			ID: "http", Address: "127.0.0.1", Port: listenPort,
			IngressSourceIPv4: "127.0.0.1", IngressSourceIPv6: "::1",
		}},
		Pools: []Pool{
			directAPool, directBPool, direct6Pool,
			{ID: "connect-l2", Kind: PoolL2, Endpoints: []Endpoint{{
				ID: "connect-dead", Host: "127.0.0.1", Port: deadPort,
				NodeID: "l2-connect", Weight: 1,
			}}},
			{ID: "slow-l2", Kind: PoolL2, Endpoints: []Endpoint{slowA.endpoint(t, "slow-a", PoolL2, "l2-slow-a")}},
			{ID: "budget-l2", Kind: PoolL2, Endpoints: []Endpoint{
				slowA.endpoint(t, "budget-a", PoolL2, "l2-budget-a"),
				slowB.endpoint(t, "budget-b", PoolL2, "l2-budget-b"),
			}},
			{ID: "circuit-l2", Kind: PoolL2, Endpoints: []Endpoint{circuit.endpoint(t, "circuit-a", PoolL2, "l2-circuit")}},
			{ID: "post-l2", Kind: PoolL2, Endpoints: []Endpoint{postOnly.endpoint(t, "post-a", PoolL2, "l2-post")}},
		},
		DefaultPoolID: "direct-b",
		Routes: []Route{
			{ID: "conditional", Priority: 30, PathPrefix: "/conditional", NodeRegions: []string{"cn-east"}, ClientCIDRs: []string{"127.0.0.0/8"}, PoolID: "direct-a"},
			{ID: "priority-high", Priority: 20, PathPrefix: "/priority", PoolID: "direct-a"},
			{ID: "priority-low", Priority: 10, PathPrefix: "/priority", PoolID: "direct-b"},
			{ID: "connect", Priority: 20, PathPrefix: "/connect", PoolID: "connect-l2", FallbackPoolID: "direct-b"},
			{ID: "slow", Priority: 20, PathPrefix: "/slow", PoolID: "slow-l2", FallbackPoolID: "direct-b"},
			{ID: "budget", Priority: 20, PathPrefix: "/budget", PoolID: "budget-l2", FallbackPoolID: "direct-b"},
			{ID: "circuit", Priority: 20, PathPrefix: "/circuit", PoolID: "circuit-l2", FallbackPoolID: "direct-b"},
			{ID: "post-no-replay", Priority: 20, PathPrefix: "/post-no-replay", PoolID: "post-l2", FallbackPoolID: "direct-b"},
			{ID: "ipv4", Priority: 20, PathPrefix: "/ipv4", PoolID: "direct-a"},
			{ID: "ipv6", Priority: 20, PathPrefix: "/ipv6", PoolID: "direct-v6"},
		},
		Retry: RetryPolicy{
			Methods: []string{"GET", "HEAD"}, MaxAttempts: 3,
			ConnectTimeoutMS: 100, ReadTimeoutMS: 250, TotalBudgetMS: 400,
		},
		L2: L2Policy{FailureThreshold: 3, RecoveryThreshold: 2, ProbeIntervalMS: 1000, MaxHops: 2},
	}
}

func originRouteSmokeRequest(t *testing.T, port uint16, method, path string, body io.Reader) originRouteSmokeResponse {
	t.Helper()
	return originRouteSmokeRequestWithHeaders(t, port, method, path, body, nil)
}

func originRouteSmokeRequestWithHeaders(
	t *testing.T, port uint16, method, path string, body io.Reader, headers map[string]string,
) originRouteSmokeResponse {
	t.Helper()
	response, err := doOriginRouteSmokeRequest(context.Background(), port, method, path, body, headers)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func doOriginRouteSmokeRequest(
	ctx context.Context, port uint16, method, path string, body io.Reader, headers map[string]string,
) (originRouteSmokeResponse, error) {
	return doOriginRouteSmokeRequestWithTimeout(ctx, port, method, path, body, headers, 30*time.Second)
}

func doOriginRouteSmokeRequestWithTimeout(
	ctx context.Context, port uint16, method, path string, body io.Reader,
	headers map[string]string, timeout time.Duration,
) (originRouteSmokeResponse, error) {
	request, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), body)
	if err != nil {
		return originRouteSmokeResponse{}, err
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return originRouteSmokeResponse{}, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return originRouteSmokeResponse{}, err
	}
	return originRouteSmokeResponse{
		status: response.StatusCode, headers: response.Header.Clone(),
		body: strings.TrimSpace(string(content)), elapsed: time.Since(started),
	}, nil
}

func originRouteSmokeRequestWithTimeout(
	t *testing.T, port uint16, method, path string, timeout time.Duration,
) originRouteSmokeResponse {
	t.Helper()
	response, err := doOriginRouteSmokeRequestWithTimeout(
		context.Background(), port, method, path, nil, nil, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func waitOriginRouteRequestCountStable(t *testing.T, origin *originRouteSmokeOrigin, maxWindow time.Duration) {
	t.Helper()
	deadline := time.Now().Add(maxWindow)
	last := origin.requests.Load()
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		current := origin.requests.Load()
		if current != last {
			last = current
			stableSince = time.Now()
		} else if time.Since(stableSince) >= 100*time.Millisecond {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func originRouteHealthProbe(port uint16) HealthProbe {
	return func(ctx context.Context, version string) error {
		client := &http.Client{Transport: &http.Transport{
			DisableKeepAlives:     true,
			DialContext:           (&net.Dialer{Timeout: time.Second}).DialContext,
			ResponseHeaderTimeout: time.Second,
		}}
		url := fmt.Sprintf("http://127.0.0.1:%d/__cdnca_originroute_health", port)
		for {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			response, err := client.Do(request)
			if err == nil {
				content, readErr := io.ReadAll(io.LimitReader(response.Body, 256))
				_ = response.Body.Close()
				if readErr == nil && response.StatusCode == http.StatusOK &&
					response.Header.Get("X-CDNCA-Origin-Version") == version &&
					strings.TrimSpace(string(content)) == "ok:"+version+":ready" {
					return nil
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
}

func originRouteHealthVersion(t *testing.T, port uint16) string {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet, "/__cdnca_originroute_health", nil)
	return response.headers.Get("X-CDNCA-Origin-Version")
}

func waitOriginRouteHealthVersion(t *testing.T, port uint16, expected string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	consecutive := 0
	for time.Now().Before(deadline) {
		if originRouteHealthVersion(t, port) == expected {
			consecutive++
			if consecutive == 3 {
				return
			}
		} else {
			consecutive = 0
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("origin route health version did not stabilize at %q", expected)
}

func concurrentOriginRouteReload(
	t *testing.T, publisher *Publisher, runtime *OpenRestyRuntime,
	drainingOrigin *originRouteSmokeOrigin, port uint16, policy Policy,
) (bool, bool) {
	t.Helper()
	masterPID, running, err := runningProcessID(runtime.pidFile)
	if err != nil || !running {
		t.Fatalf("reload master pid=%d running=%t err=%v", masterPID, running, err)
	}
	oldWorkers, err := openRestyWorkerProcessIDs(masterPID)
	if err != nil || len(oldWorkers) == 0 {
		t.Fatalf("reload old workers=%v err=%v", oldWorkers, err)
	}
	drainingOrigin.setDelay(500 * time.Millisecond)
	drainingBefore := drainingOrigin.requests.Load()
	drainingResult := make(chan error, 1)
	go func() {
		response, requestErr := doOriginRouteSmokeRequest(
			context.Background(), port, http.MethodGet, "/priority/held", nil, nil)
		if requestErr == nil && (response.status != http.StatusOK || response.body != drainingOrigin.id) {
			requestErr = fmt.Errorf("draining response status=%d body=%q", response.status, response.body)
		}
		drainingResult <- requestErr
	}()
	waitOriginRouteRequestCount(t, drainingOrigin, drainingBefore+1)
	drainingOrigin.setDelay(0)
	reloadStarted := time.Now()
	const workers = 2
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	stop := make(chan struct{})
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
				if err != nil {
					errorsFound <- err
					return
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					errorsFound <- fmt.Errorf("status %d", response.StatusCode)
					return
				}
			}
		}()
	}
	_, applyErr := publisher.Apply(originRouteSmokeContext(t), policyJSON(t, policy))
	reloadElapsed := time.Since(reloadStarted)
	close(stop)
	group.Wait()
	close(errorsFound)
	if applyErr != nil {
		t.Fatalf("concurrent reload: %v", applyErr)
	}
	if err := <-drainingResult; err != nil {
		t.Fatal(err)
	}
	newWorkers, err := openRestyWorkerProcessIDs(masterPID)
	if err != nil {
		t.Fatalf("reload new workers: %v", err)
	}
	newWorker := false
	for pid := range newWorkers {
		if _, existed := oldWorkers[pid]; !existed {
			newWorker = true
		}
	}
	oldWorkersExited := true
	for pid := range oldWorkers {
		workerRunning, workerErr := processRunning(pid)
		if workerErr != nil || workerRunning {
			oldWorkersExited = false
		}
	}
	generationDrained := newWorker && oldWorkersExited && reloadElapsed >= 300*time.Millisecond
	for err := range errorsFound {
		t.Logf("request during reload: %v", err)
		return false, generationDrained
	}
	waitOriginRouteHealthVersion(t, port, policy.VersionID)
	return true, generationDrained
}

func verifyOriginRouteCircuitStateBounds(
	t *testing.T, binary, luaRoot string,
	direct, l2 *originRouteSmokeOrigin,
) (bool, bool, bool, bool, bool, bool, bool, bool) {
	t.Helper()
	root := privateOriginRouteSmokeDir(t)
	for _, path := range []string{
		"versions", "staging", "shared", "shared/client-body-temp", "shared/proxy-temp",
		"shared/fastcgi-temp", "shared/uwsgi-temp", "shared/scgi-temp",
	} {
		if err := ensurePrivateDirectory(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	port := reserveOriginRouteSmokePort(t)
	policy := Policy{
		Schema: SchemaV1, Revision: 1, TenantID: "tenant-state", SiteID: "site-state", VersionID: "state-v1",
		Node:      Node{ID: "l1-state", Region: "cn-east", Tier: TierL1},
		Listeners: []Listener{{ID: "http", Address: "127.0.0.1", Port: port}},
		Pools: []Pool{
			{ID: "direct", Kind: PoolOrigin, Endpoints: []Endpoint{direct.endpoint(t, "state-direct", PoolOrigin, "")}},
			{ID: "l2", Kind: PoolL2, Endpoints: []Endpoint{l2.endpoint(t, "state-l2", PoolL2, "state-l2-node")}},
		},
		DefaultPoolID: "direct",
		Routes: []Route{{
			ID: "state", Priority: 10, PathPrefix: "/state",
			PoolID: "l2", FallbackPoolID: "direct",
		}},
		Retry: RetryPolicy{
			Methods: []string{"GET", "HEAD"}, MaxAttempts: 2,
			ConnectTimeoutMS: 100, ReadTimeoutMS: 500, TotalBudgetMS: 700,
		},
		L2: L2Policy{FailureThreshold: 2, RecoveryThreshold: 2, ProbeIntervalMS: 300, MaxHops: 2},
	}
	runtime, err := NewOpenRestyRuntime(binary, root, originRouteHealthProbe(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Stop(ctx)
	})

	first := installOriginRouteStateTestRelease(t, root, luaRoot, policy)
	activateOriginRouteStateTestRelease(t, runtime, root, first, policy.VersionID, port)
	if response := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil); response.body != l2.id {
		t.Fatalf("state v1 did not use L2: status=%d body=%q", response.status, response.body)
	}
	blocked := originRouteSmokeRequest(t, port, http.MethodPost, "/__originroute_test_block", nil)
	if blocked.status != http.StatusOK {
		t.Fatalf("state v1 circuit block status=%d body=%q", blocked.status, blocked.body)
	}
	l2BeforeOpenCheck := l2.requests.Load()
	opened := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
	if opened.body != direct.id || l2.requests.Load() != l2BeforeOpenCheck {
		t.Fatalf("state v1 circuit did not open: status=%d body=%q", opened.status, opened.body)
	}
	firstKeys := originRouteStateKeyCount(t, port)

	policy.Revision = 2
	second := installOriginRouteStateTestRelease(t, root, luaRoot, policy)
	activateOriginRouteStateTestRelease(t, runtime, root, second, policy.VersionID, port)
	revisionResponse := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
	revisionIsolated := revisionResponse.body == l2.id && l2.requests.Load() == l2BeforeOpenCheck+1
	keysAcrossVersions := originRouteStateKeyCount(t, port)
	var expiredKeys int
	probeSeconds := float64(policy.L2.ProbeIntervalMS) / 1000
	stateTTLSeconds := math.Max(1, math.Min(300, probeSeconds*10))
	metadataTTLSeconds := stateTTLSeconds + math.Max(0.1, math.Min(stateTTLSeconds, 1))
	deadline := time.Now().Add(time.Duration((metadataTTLSeconds + 0.25) * float64(time.Second)))
	for time.Now().Before(deadline) {
		expiredKeys = originRouteStateKeyCount(t, port)
		if expiredKeys == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	multiVersionExpired := firstKeys >= 1 && keysAcrossVersions >= 2 && expiredKeys == 0

	fill := originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_fill", nil)
	if fill.status != http.StatusOK {
		t.Fatalf("fill shared dict status=%d body=%q", fill.status, fill.body)
	}
	filled, fillErr := strconv.Atoi(fill.headers.Get("X-CDNCA-Test-Pressure-Entries"))
	if fillErr != nil || filled < 1 {
		t.Fatalf("fill shared dict entries=%q err=%v", fill.headers.Get("X-CDNCA-Test-Pressure-Entries"), fillErr)
	}
	freeBytes, freeErr := strconv.Atoi(fill.headers.Get("X-CDNCA-Test-Pressure-Free-Bytes"))
	if freeErr != nil || freeBytes >= originRouteStateMinFreeBytes {
		t.Fatalf("fill shared dict free bytes=%q err=%v, want <%d",
			fill.headers.Get("X-CDNCA-Test-Pressure-Free-Bytes"), freeErr, originRouteStateMinFreeBytes)
	}
	l2Before := l2.requests.Load()
	underPressure := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
	waitOriginRouteRequestCountStable(t, l2, time.Second)
	l2AfterPressure := l2.requests.Load()
	capacityFailClosed := l2AfterPressure == l2Before &&
		(underPressure.status == http.StatusServiceUnavailable ||
			(underPressure.body == direct.id &&
				underPressure.headers.Get("X-CDNCA-Origin-Event") == "circuit_state_unavailable"))
	if !capacityFailClosed {
		t.Logf("circuit capacity response=%d/%q l2_requests=%d/%d event=%q",
			underPressure.status, underPressure.body, l2AfterPressure, l2Before,
			underPressure.headers.Get("X-CDNCA-Origin-Event"))
	}
	time.Sleep(1200 * time.Millisecond)
	recovered := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
	stateRecovered := recovered.body == l2.id && l2.requests.Load() == l2Before+1

	policy.Revision = 3
	policy.Retry.ReadTimeoutMS = 800
	policy.Retry.TotalBudgetMS = 900
	policy.L2.ProbeIntervalMS = 3000
	third := installOriginRouteStateTestRelease(t, root, luaRoot, policy)
	activateOriginRouteStateTestRelease(t, runtime, root, third, policy.VersionID, port)
	masterPID, running, processErr := runningProcessID(runtime.pidFile)
	if processErr != nil || !running {
		t.Fatalf("state CAS master pid=%d running=%t err=%v", masterPID, running, processErr)
	}
	workers, workerErr := openRestyWorkerProcessIDs(masterPID)
	if workerErr != nil || len(workers) != 2 {
		t.Fatalf("state CAS workers=%v err=%v, expected exactly two workers", workers, workerErr)
	}
	l2.setDelay(400 * time.Millisecond)
	t.Cleanup(func() { l2.setDelay(0) })

	originRouteSmokeRequest(t, port, http.MethodPost, "/__originroute_test_open", nil)
	leaseBefore := l2.requests.Load()
	leaseResult := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := doOriginRouteSmokeRequest(
			context.Background(), port, http.MethodGet, "/state", nil, nil)
		if requestErr != nil {
			leaseResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		leaseResult <- response
	}()
	waitOriginRouteRequestCount(t, l2, leaseBefore+1)
	originRouteSmokeRequest(t, port, http.MethodPost, "/__originroute_test_drop_open", nil)
	time.Sleep(150 * time.Millisecond)
	secondDuringProbe := originRouteSmokeRequest(t, port, http.MethodGet, "/state", nil)
	firstProbe := <-leaseResult
	probeSingleOwner := firstProbe.body == l2.id && secondDuringProbe.body == direct.id &&
		l2.requests.Load() == leaseBefore+1

	originRouteSmokeRequest(t, port, http.MethodPost, "/__originroute_test_open", nil)
	fenceBefore := l2.requests.Load()
	fenceResult := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := doOriginRouteSmokeRequest(
			context.Background(), port, http.MethodGet, "/state", nil, nil)
		if requestErr != nil {
			fenceResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		fenceResult <- response
	}()
	waitOriginRouteRequestCount(t, l2, fenceBefore+1)
	replacement := originRouteSmokeRequest(t, port, http.MethodPost, "/__originroute_test_replace_probe", nil)
	fencedProbe := <-fenceResult
	probeValue := originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_probe", nil)
	probeFenced := replacement.status == http.StatusOK && fencedProbe.body == l2.id && probeValue.body == "replacement"
	probeExpired := false
	expiryDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(expiryDeadline) {
		if originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_probe", nil).body == "missing" {
			probeExpired = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	verifyOriginRouteProbeReleaseCAS(t, port)
	verifyOriginRouteProbeWriteCAS(t, port)
	verifyOriginRouteCircuitStateWriteCAS(t, port)
	verifyOriginRouteProbeGenerationReuse(t, port)
	verifyOriginRouteCircuitStateGenerationReuse(t, port)
	verifyOriginRouteProbeCleanupGenerationReuse(t, port)
	verifyOriginRouteCircuitCleanupGenerationReuse(t, port)
	verifyOriginRouteProbeHistoryBound(t, port)
	verifyOriginRouteLeaseRound7(t, port)
	verifyOriginRouteLeaseRound8(t, port)
	return capacityFailClosed, stateRecovered, multiVersionExpired, revisionIsolated,
		probeSingleOwner, probeFenced, probeExpired, true
}

func originRouteHistoryCounts(t *testing.T, port uint16, path string) []int {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet, path, nil)
	parts := strings.Split(response.body, ",")
	if response.status != http.StatusOK || len(parts) != 5 {
		t.Fatalf("history counts status=%d body=%q", response.status, response.body)
	}
	counts := make([]int, len(parts))
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			t.Fatalf("history count %q: %v", response.body, err)
		}
		counts[index] = value
	}
	return counts
}

func verifyOriginRouteProbeCleanupGenerationReuse(t *testing.T, port uint16) {
	t.Helper()
	clients := originRouteSmokeDistinctWorkerClients(t, port)
	for _, test := range []struct {
		kind     string
		released bool
		want     []int
	}{
		{kind: "circuit", want: []int{1, 1, 0, 0, 1}},
		{kind: "adaptive", released: true, want: []int{1, 1, 1, 0, 1}},
	} {
		reset := originRouteSmokeRequest(t, port, http.MethodPost,
			fmt.Sprintf("/__originroute_test_cas_reset?kind=%s", test.kind), nil)
		if reset.status != http.StatusOK {
			t.Fatalf("%s cleanup reuse reset: status=%d body=%q", test.kind, reset.status, reset.body)
		}
		seed := originRouteSmokeRequest(t, port, http.MethodPost,
			fmt.Sprintf("/__originroute_test_cas_write?kind=%s&owner=round6-seed&round5=1", test.kind), nil)
		if seed.status != http.StatusOK {
			t.Fatalf("%s cleanup reuse seed: status=%d body=%q", test.kind, seed.status, seed.body)
		}
		stalledResult := make(chan originRouteSmokeResponse, 1)
		go func() {
			response, requestErr := adaptiveOriginRouteClientRequest(
				context.Background(), clients[0], port,
				fmt.Sprintf("/__originroute_test_cas_write?kind=%s&owner=round6-stalled-cleanup&round5=1", test.kind), "")
			if requestErr != nil {
				stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
				return
			}
			stalledResult <- response
		}()
		deadline := time.Now().Add(10 * time.Second)
		barrier := originRouteSmokeResponse{body: "waiting"}
		for time.Now().Before(deadline) {
			barrier = originRouteSmokeRequest(t, port, http.MethodGet,
				fmt.Sprintf("/__originroute_test_cas_write_read?kind=%s&phase=cleanup", test.kind), nil)
			if barrier.body != "waiting" {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if barrier.body == "waiting" {
			select {
			case stalled := <-stalledResult:
				t.Fatalf("%s cleanup reuse did not reach the captured-slot barrier: stalled=%d/%q",
					test.kind, stalled.status, stalled.body)
			default:
				t.Fatalf("%s cleanup reuse did not reach the captured-slot barrier: writer still running", test.kind)
			}
		}
		time.Sleep(450 * time.Millisecond)
		release := "0"
		if test.released {
			release = "1"
		}
		successor, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), clients[1], port,
			fmt.Sprintf("/__originroute_test_cas_write?kind=%s&owner=round6-successor&round5=1&release=%s",
				test.kind, release), "")
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		<-stalledResult
		counts := originRouteHistoryCounts(t, port,
			fmt.Sprintf("/__originroute_test_history_counts?kind=%s", test.kind))
		value := originRouteSmokeRequest(t, port, http.MethodGet,
			fmt.Sprintf("/__originroute_test_cas_value?kind=%s", test.kind), nil)
		wantValue := "round6-successor"
		if test.released {
			wantValue = "missing"
		}
		if successor.status != http.StatusOK ||
			mustOriginRouteGeneration(t, successor.headers.Get("X-CDNCA-Test-Generation")) <= 1 ||
			!slices.Equal(counts, test.want) || value.body != wantValue {
			t.Fatalf("%s cleanup reuse successor=%d/%q generation=%q counts=%v want=%v value=%q",
				test.kind, successor.status, successor.body,
				successor.headers.Get("X-CDNCA-Test-Generation"), counts, test.want, value.body)
		}
	}
}

func verifyOriginRouteCircuitCleanupGenerationReuse(t *testing.T, port uint16) {
	t.Helper()
	clients := originRouteSmokeDistinctWorkerClients(t, port)
	reset := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__originroute_test_state_reset", nil)
	if reset.status != http.StatusOK {
		t.Fatalf("circuit cleanup reuse reset: status=%d body=%q", reset.status, reset.body)
	}
	seed := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__originroute_test_state_write?owner=round6-seed", nil)
	if seed.status != http.StatusOK {
		t.Fatalf("circuit cleanup reuse seed: status=%d body=%q", seed.status, seed.body)
	}
	stalledResult := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), clients[0], port,
			"/__originroute_test_state_write?owner=round6-stalled-cleanup", "")
		if requestErr != nil {
			stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		stalledResult <- response
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ready := originRouteSmokeRequest(t, port, http.MethodGet,
			"/__originroute_test_state_cleanup_ready", nil)
		if ready.body != "waiting" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ready := originRouteSmokeRequest(t, port, http.MethodGet,
		"/__originroute_test_state_cleanup_ready", nil); ready.body == "waiting" {
		t.Fatal("circuit cleanup reuse did not reach the captured-slot barrier")
	}
	time.Sleep(1050 * time.Millisecond)
	successor, requestErr := adaptiveOriginRouteClientRequest(
		context.Background(), clients[1], port,
		"/__originroute_test_state_write?owner=round6-successor", "")
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	<-stalledResult
	counts := originRouteHistoryCounts(t, port, "/__originroute_test_state_history_counts")
	value := originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_state_value", nil)
	if successor.status != http.StatusOK ||
		mustOriginRouteGeneration(t, successor.headers.Get("X-CDNCA-Test-Generation")) <= 1 ||
		!slices.Equal(counts, []int{0, 1, 0, 1, 1}) || value.body != "666" {
		t.Fatalf("circuit cleanup reuse successor=%d/%q generation=%q counts=%v value=%q",
			successor.status, successor.body,
			successor.headers.Get("X-CDNCA-Test-Generation"), counts, value.body)
	}
}

func verifyOriginRouteProbeHistoryBound(t *testing.T, port uint16) {
	t.Helper()
	response := originRouteSmokeRequestWithTimeout(t, port, http.MethodPost,
		"/__originroute_test_history_bound?iterations=96", 10*time.Second)
	counts := originRouteHistoryCounts(t, port, "/__originroute_test_history_bound_counts")
	if response.status != http.StatusOK || !slices.Equal(counts, []int{1, 1, 1, 0, 1}) {
		t.Fatalf("probe history bound status=%d body=%q counts=%v", response.status, response.body, counts)
	}
}

func verifyOriginRouteLeaseRound7(t *testing.T, port uint16) {
	t.Helper()
	clients := originRouteSmokeDistinctWorkerClients(t, port)

	seed := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__originroute_test_round7_lock_seed?token=stale&ttl=0.05", nil)
	if seed.status != http.StatusOK {
		t.Fatalf("round7 stale mutation lock seed status=%d body=%q", seed.status, seed.body)
	}
	staleRelease := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := adaptiveOriginRouteClientRequest(context.Background(), clients[0], port,
			"/__originroute_test_round7_lock_release?token=stale", "")
		if requestErr != nil {
			staleRelease <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		staleRelease <- response
	}()
	waitOriginRouteRound7Barrier(t, port, "lock")
	time.Sleep(60 * time.Millisecond)
	successor := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__originroute_test_round7_lock_seed?token=successor&ttl=1", nil)
	stale := <-staleRelease
	lockValue := originRouteSmokeRequest(t, port, http.MethodGet,
		"/__originroute_test_round7_lock_value", nil)
	if successor.status != http.StatusOK || stale.status != http.StatusConflict ||
		stale.body != "not-owned" || lockValue.body != "successor" {
		t.Fatalf("round7 stale lock release successor=%d/%q stale=%d/%q value=%q",
			successor.status, successor.body, stale.status, stale.body, lockValue.body)
	}

	for _, test := range []struct {
		kind string
		want []int
	}{
		{kind: "probe", want: []int{64, 64, 64, 0, 64}},
		{kind: "state", want: []int{0, 64, 0, 64, 64}},
	} {
		response := originRouteSmokeRequestWithTimeout(t, port, http.MethodPost,
			"/__originroute_test_round7_history?kind="+test.kind+"&iterations=96", 10*time.Second)
		counts := originRouteHistoryCounts(t, port,
			"/__originroute_test_round7_history_counts?kind="+test.kind)
		if response.status != http.StatusOK || !slices.Equal(counts, test.want) {
			t.Fatalf("round7 %s interrupted history status=%d body=%q counts=%v want=%v",
				test.kind, response.status, response.body, counts, test.want)
		}
	}

	olderResult := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := adaptiveOriginRouteClientRequest(context.Background(), clients[0], port,
			"/__originroute_test_round7_late_write?value=round7-older", "")
		if requestErr != nil {
			olderResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		olderResult <- response
	}()
	barrier := waitOriginRouteRound7Barrier(t, port, "late")
	parts := strings.Split(barrier, ":")
	if len(parts) != 2 {
		t.Fatalf("round7 late commit barrier=%q", barrier)
	}
	olderGeneration := mustOriginRouteGeneration(t, parts[1])
	newer, requestErr := adaptiveOriginRouteClientRequest(context.Background(), clients[1], port,
		"/__originroute_test_round7_late_write?value=round7-newer", "")
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	older := <-olderResult
	visible := originRouteSmokeRequest(t, port, http.MethodGet,
		"/__originroute_test_round7_late_value", nil)
	if older.status != http.StatusOK || newer.status != http.StatusOK ||
		mustOriginRouteGeneration(t, newer.headers.Get("X-CDNCA-Test-Generation")) <= olderGeneration ||
		visible.body != "round7-newer" {
		t.Fatalf("round7 late commit older=%d/%q newer=%d/%q visible=%q",
			older.status, older.body, newer.status, newer.body, visible.body)
	}

	for _, kind := range []string{"counter-missing", "overflow", "restart-mismatch", "order-missing"} {
		response := originRouteSmokeRequest(t, port, http.MethodPost,
			"/__originroute_test_round7_fault?kind="+kind, nil)
		if response.status != http.StatusOK || response.body == "accepted" || response.body == "" {
			t.Fatalf("round7 %s fault did not fail closed: status=%d body=%q",
				kind, response.status, response.body)
		}
	}
}

func verifyOriginRouteLeaseRound8(t *testing.T, port uint16) {
	t.Helper()
	clients := originRouteSmokeDistinctWorkerClients(t, port)
	precommit, requestErr := adaptiveOriginRouteClientRequest(context.Background(), clients[0], port,
		"/__originroute_test_round8_precommit?failures=65", "")
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	visible, requestErr := adaptiveOriginRouteClientRequest(context.Background(), clients[1], port,
		"/__originroute_test_round8_value", "")
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	if precommit.status != http.StatusOK || precommit.body != "round8-seed" ||
		visible.status != http.StatusOK || visible.body != "round8-seed" {
		t.Fatalf("round8 precommit preservation status=%d body=%q visible=%d/%q",
			precommit.status, precommit.body, visible.status, visible.body)
	}

	metadata := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__originroute_test_round8_metadata?revisions=96", nil)
	if metadata.status != http.StatusOK || metadata.body != "96,0" {
		t.Fatalf("round8 metadata reclamation status=%d body=%q", metadata.status, metadata.body)
	}

	for _, test := range []struct {
		kind string
		want string
	}{
		{kind: "half-init", want: "recovered"},
		{kind: "allocation-pressure", want: "recovered"},
		{kind: "fallback-pressure", want: "recovered"},
		{kind: "global-loss", want: "rejected"},
		{kind: "local-restart", want: "restarted"},
	} {
		response, requestErr := adaptiveOriginRouteClientRequest(context.Background(), clients[1], port,
			"/__originroute_test_round8_fault?kind="+test.kind, "")
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if response.status != http.StatusOK || response.body != test.want {
			t.Fatalf("round8 %s status=%d body=%q want=%q",
				test.kind, response.status, response.body, test.want)
		}
	}
}

func waitOriginRouteRound7Barrier(t *testing.T, port uint16, kind string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response := originRouteSmokeRequest(t, port, http.MethodGet,
			"/__originroute_test_round7_barrier?kind="+kind, nil)
		if response.status == http.StatusOK && response.body != "waiting" {
			return response.body
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("round7 %s barrier was not reached", kind)
	return ""
}

func mustOriginRouteGeneration(t *testing.T, raw string) int {
	t.Helper()
	generation, err := strconv.Atoi(raw)
	if err != nil || generation < 1 {
		t.Fatalf("invalid origin route generation %q", raw)
	}
	return generation
}

func originRouteSmokeDistinctWorkerClients(t *testing.T, port uint16) []*http.Client {
	t.Helper()
	clients := make([]*http.Client, 0, 2)
	workers := make(map[string]struct{})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(clients) < 2 {
		transport := &http.Transport{MaxIdleConnsPerHost: 1}
		client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
		response, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), client, port, "/__originroute_test_worker", "")
		worker := response.headers.Get("X-CDNCA-Test-Worker")
		if requestErr != nil || response.status != http.StatusOK || worker == "" {
			transport.CloseIdleConnections()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if _, exists := workers[worker]; exists {
			transport.CloseIdleConnections()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		workers[worker] = struct{}{}
		clients = append(clients, client)
	}
	if len(clients) != 2 {
		t.Fatal("could not establish keepalive connections to both OpenResty workers")
	}
	t.Cleanup(func() {
		for _, client := range clients {
			client.Transport.(*http.Transport).CloseIdleConnections()
		}
	})
	return clients
}

func verifyOriginRouteProbeGenerationReuse(t *testing.T, port uint16) {
	t.Helper()
	clients := originRouteSmokeDistinctWorkerClients(t, port)
	for _, kind := range []string{"circuit", "adaptive"} {
		reset := originRouteSmokeRequest(t, port, http.MethodPost,
			fmt.Sprintf("/__originroute_test_cas_reset?kind=%s", kind), nil)
		if reset.status != http.StatusOK {
			t.Fatalf("%s generation reuse reset: status=%d body=%q", kind, reset.status, reset.body)
		}
		stalledResult := make(chan originRouteSmokeResponse, 1)
		go func() {
			response, requestErr := adaptiveOriginRouteClientRequest(
				context.Background(), clients[0], port,
				fmt.Sprintf("/__originroute_test_cas_write?kind=%s&owner=round5-stalled&round5=1", kind), "")
			if requestErr != nil {
				stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
				return
			}
			stalledResult <- response
		}()
		deadline := time.Now().Add(10 * time.Second)
		barrier := originRouteSmokeResponse{body: "waiting"}
		for time.Now().Before(deadline) {
			barrier = originRouteSmokeRequest(t, port, http.MethodGet,
				fmt.Sprintf("/__originroute_test_cas_write_read?kind=%s&phase=post-add", kind), nil)
			if barrier.body != "waiting" {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		parts := strings.Split(barrier.body, ":")
		if barrier.body == "waiting" || len(parts) != 2 {
			t.Fatalf("%s generation reuse did not reach the post-add barrier", kind)
		}
		stalledGeneration := mustOriginRouteGeneration(t, parts[1])
		time.Sleep(450 * time.Millisecond)
		replacement, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), clients[1], port,
			fmt.Sprintf("/__originroute_test_cas_write?kind=%s&owner=round5-replacement&round5=1", kind), "")
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		stalled := <-stalledResult
		value := originRouteSmokeRequest(t, port, http.MethodGet,
			fmt.Sprintf("/__originroute_test_cas_value?kind=%s", kind), nil)
		if replacement.status != http.StatusOK ||
			mustOriginRouteGeneration(t, replacement.headers.Get("X-CDNCA-Test-Generation")) <= stalledGeneration ||
			stalled.status == http.StatusOK || value.body != "round5-replacement" {
			t.Fatalf("%s generation reuse replacement=%d/%q generation=%q stalled=%d/%q value=%q",
				kind, replacement.status, replacement.body,
				replacement.headers.Get("X-CDNCA-Test-Generation"),
				stalled.status, stalled.body, value.body)
		}
	}
}

func verifyOriginRouteCircuitStateGenerationReuse(t *testing.T, port uint16) {
	t.Helper()
	clients := originRouteSmokeDistinctWorkerClients(t, port)
	reset := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__originroute_test_state_reset", nil)
	if reset.status != http.StatusOK {
		t.Fatalf("circuit generation reuse reset: status=%d body=%q", reset.status, reset.body)
	}
	stalledResult := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), clients[0], port,
			"/__originroute_test_state_write?owner=round5-stalled", "")
		if requestErr != nil {
			stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		stalledResult <- response
	}()
	deadline := time.Now().Add(10 * time.Second)
	barrier := originRouteSmokeResponse{body: "waiting"}
	for time.Now().Before(deadline) {
		barrier = originRouteSmokeRequest(t, port, http.MethodGet,
			"/__originroute_test_state_after_add_ready", nil)
		if barrier.body != "waiting" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	parts := strings.Split(barrier.body, ":")
	if barrier.body == "waiting" || len(parts) != 2 {
		t.Fatal("circuit generation reuse did not reach the post-add barrier")
	}
	stalledGeneration := mustOriginRouteGeneration(t, parts[1])
	time.Sleep(1050 * time.Millisecond)
	replacement, requestErr := adaptiveOriginRouteClientRequest(
		context.Background(), clients[1], port,
		"/__originroute_test_state_write?owner=round5-replacement", "")
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	stalled := <-stalledResult
	value := originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_state_value", nil)
	if replacement.status != http.StatusOK ||
		mustOriginRouteGeneration(t, replacement.headers.Get("X-CDNCA-Test-Generation")) <= stalledGeneration ||
		stalled.status == http.StatusOK || value.body != "444" {
		t.Fatalf("circuit generation reuse replacement=%d/%q generation=%q stalled=%d/%q value=%q",
			replacement.status, replacement.body,
			replacement.headers.Get("X-CDNCA-Test-Generation"), stalled.status, stalled.body, value.body)
	}
}

func verifyOriginRouteCircuitStateWriteCAS(t *testing.T, port uint16) {
	t.Helper()
	clients := make([]*http.Client, 0, 2)
	workers := make(map[string]struct{})
	for attempt := 0; attempt < 16 && len(clients) < 2; attempt++ {
		transport := &http.Transport{MaxIdleConnsPerHost: 1}
		client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
		response, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), client, port, "/__originroute_test_state_write?owner=seed", "")
		worker := response.headers.Get("X-CDNCA-Test-Worker")
		if requestErr != nil || response.status != http.StatusOK || worker == "" {
			transport.CloseIdleConnections()
			continue
		}
		if _, exists := workers[worker]; exists {
			transport.CloseIdleConnections()
			continue
		}
		workers[worker] = struct{}{}
		clients = append(clients, client)
	}
	if len(clients) != 2 {
		t.Fatal("could not establish circuit state connections to both OpenResty workers")
	}
	defer func() {
		for _, client := range clients {
			client.Transport.(*http.Transport).CloseIdleConnections()
		}
	}()
	stalledResult := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), clients[0], port, "/__originroute_test_state_write?owner=stalled", "")
		if requestErr != nil {
			stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		stalledResult <- response
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ready := originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_state_write_ready", nil)
		if ready.body != "waiting" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ready := originRouteSmokeRequest(t, port, http.MethodGet,
		"/__originroute_test_state_write_ready", nil); ready.body == "waiting" {
		t.Fatal("circuit state write never reached the final fenced-write barrier")
	}
	time.Sleep(600 * time.Millisecond)
	replacement, requestErr := adaptiveOriginRouteClientRequest(
		context.Background(), clients[1], port, "/__originroute_test_state_write?owner=replacement", "")
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	stalled := <-stalledResult
	value := originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_state_value", nil)
	if replacement.status != http.StatusOK || stalled.status == http.StatusOK || value.body != "222" {
		t.Fatalf("circuit state write replacement=%d/%q stalled=%d/%q value=%q",
			replacement.status, replacement.body, stalled.status, stalled.body, value.body)
	}
}

func verifyOriginRouteProbeReleaseCAS(t *testing.T, port uint16) {
	t.Helper()
	for _, kind := range []string{"circuit", "adaptive"} {
		for iteration := 0; iteration < 8; iteration++ {
			seed := originRouteSmokeRequest(t, port, http.MethodPost,
				fmt.Sprintf("/__originroute_test_cas_seed?kind=%s", kind), nil)
			if seed.status != http.StatusOK {
				t.Fatalf("%s CAS seed %d: status=%d body=%q", kind, iteration, seed.status, seed.body)
			}
			releaseResult := make(chan originRouteSmokeResponse, 1)
			go func() {
				response, requestErr := doOriginRouteSmokeRequest(context.Background(), port, http.MethodPost,
					fmt.Sprintf("/__originroute_test_cas_release?kind=%s", kind), nil, nil)
				if requestErr != nil {
					releaseResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
					return
				}
				releaseResult <- response
			}()
			deadline := time.Now().Add(10 * time.Second)
			var reader originRouteSmokeResponse
			for time.Now().Before(deadline) {
				reader = originRouteSmokeRequest(t, port, http.MethodGet,
					fmt.Sprintf("/__originroute_test_cas_read?kind=%s", kind), nil)
				if reader.body != "waiting" {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if reader.body == "waiting" {
				t.Fatalf("%s CAS release %d did not reach matched read", kind, iteration)
			}
			replacement := originRouteSmokeRequest(t, port, http.MethodPost,
				fmt.Sprintf("/__originroute_test_cas_replace?kind=%s", kind), nil)
			released := <-releaseResult
			value := originRouteSmokeRequest(t, port, http.MethodGet,
				fmt.Sprintf("/__originroute_test_cas_value?kind=%s", kind), nil)
			if replacement.status != http.StatusOK || released.status != http.StatusOK || value.body != "replacement" {
				t.Fatalf("%s CAS iteration %d replacement=%d/%q release=%d/%q value=%q",
					kind, iteration, replacement.status, replacement.body, released.status, released.body, value.body)
			}
		}
	}
}

func verifyOriginRouteProbeWriteCAS(t *testing.T, port uint16) {
	t.Helper()
	for _, kind := range []string{"circuit", "adaptive"} {
		for iteration := 0; iteration < 1; iteration++ {
			seed := originRouteSmokeRequest(t, port, http.MethodPost,
				fmt.Sprintf("/__originroute_test_cas_seed?kind=%s", kind), nil)
			if seed.status != http.StatusOK {
				t.Fatalf("%s write CAS seed %d: status=%d body=%q", kind, iteration, seed.status, seed.body)
			}
			stalledResult := make(chan originRouteSmokeResponse, 1)
			go func() {
				response, requestErr := doOriginRouteSmokeRequest(context.Background(), port, http.MethodPost,
					fmt.Sprintf("/__originroute_test_cas_write?kind=%s&owner=stalled-owner", kind), nil, nil)
				if requestErr != nil {
					stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
					return
				}
				stalledResult <- response
			}()
			deadline := time.Now().Add(10 * time.Second)
			var reader originRouteSmokeResponse
			for time.Now().Before(deadline) {
				reader = originRouteSmokeRequest(t, port, http.MethodGet,
					fmt.Sprintf("/__originroute_test_cas_write_read?kind=%s", kind), nil)
				if reader.body != "waiting" {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if reader.body == "waiting" {
				t.Fatalf("%s write CAS %d did not enter stalled publication", kind, iteration)
			}
			replacement := originRouteSmokeRequest(t, port, http.MethodPost,
				fmt.Sprintf("/__originroute_test_cas_write?kind=%s&owner=replacement", kind), nil)
			stalled := <-stalledResult
			value := originRouteSmokeRequest(t, port, http.MethodGet,
				fmt.Sprintf("/__originroute_test_cas_value?kind=%s", kind), nil)
			if replacement.status != http.StatusOK || stalled.status == http.StatusOK || value.body != "replacement" {
				t.Fatalf("%s write CAS iteration %d replacement=%d/%q stalled=%d/%q value=%q",
					kind, iteration, replacement.status, replacement.body, stalled.status, stalled.body, value.body)
			}
		}
	}
}

func installOriginRouteStateTestRelease(t *testing.T, root, luaRoot string, policy Policy) string {
	t.Helper()
	engine, err := os.ReadFile(filepath.Join(luaRoot, "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	instrumented := string(engine)
	if !strings.Contains(instrumented,
		"  -- CDNCA_TEST_PROBE_RELEASE_BARRIER\n  if before_delete then\n    before_delete()\n  end\n") {
		t.Fatal("probe release final mutation instrumentation point is missing")
	}
	lockReleaseInstrumented := strings.Replace(instrumented,
		"  -- CDNCA_TEST_PROBE_LOCK_RELEASE_BARRIER\n",
		"  if key == \"__cdnca_round7_mutation_lock\" and lock_token == \"stale\" then\n"+
			"    dictionary:set(\"__cdnca_test_round7_lock_release\", \"ready\", 2)\n"+
			"    ngx.sleep(0.2)\n"+
			"  end\n", 1)
	if lockReleaseInstrumented == instrumented {
		t.Fatal("mutation lock release instrumentation point is missing")
	}
	writeInstrumented := strings.Replace(lockReleaseInstrumented,
		"  -- CDNCA_TEST_PROBE_AFTER_MUTATION_ACQUIRE_BARRIER\n",
		"  if value == \"stalled-owner\" then\n"+
			"    dictionary:set(key .. \":test-write\", tostring(ngx.worker.pid()), 2)\n"+
			"    ngx.sleep(0.2)\n"+
			"  end\n", 1)
	if writeInstrumented == instrumented {
		t.Fatal("probe mutation acquisition instrumentation point is missing")
	}
	postAddInstrumented := strings.Replace(writeInstrumented,
		"  -- CDNCA_TEST_PROBE_WRITE_BARRIER\n",
		"  if value == \"round5-stalled\" then\n"+
			"    dictionary:set(key .. \":test-post-add\",\n"+
			"      tostring(ngx.worker.pid()) .. \":\" .. tostring(generation), 2)\n"+
			"    ngx.sleep(0.7)\n"+
			"  elseif value == \"round6-stalled-cleanup\" then\n"+
			"    dictionary:set(key .. \":test-cleanup-generation\", tostring(generation), 2)\n"+
			"  end\n", 1)
	if postAddInstrumented == writeInstrumented {
		t.Fatal("probe post-add instrumentation point is missing")
	}
	stateInstrumented := strings.Replace(postAddInstrumented,
		"  -- CDNCA_TEST_LEASE_STATE_WRITE_BARRIER\n",
		"  if string.find(base_key, \":circuit-snapshot\", 1, true) and\n"+
			"    string.sub(raw, -4) == \",111\" then\n"+
			"    dictionary:set(\"__cdnca_test_lease_state_write\", tostring(ngx.worker.pid()), 2)\n"+
			"    ngx.sleep(0.7)\n"+
			"  end\n", 1)
	if stateInstrumented == postAddInstrumented {
		t.Fatal("lease state write instrumentation point is missing")
	}
	statePostAddInstrumented := strings.Replace(stateInstrumented,
		"  -- CDNCA_TEST_LEASE_STATE_AFTER_ADD_BARRIER\n",
		"  if base_key == \"__cdnca_round7_late_state\" and raw == \"round7-older\" then\n"+
			"    dictionary:set(\"__cdnca_test_round7_late_commit\",\n"+
			"      tostring(ngx.worker.pid()) .. \":\" .. tostring(generation), 2)\n"+
			"    ngx.sleep(0.3)\n"+
			"  elseif string.find(base_key, \":circuit-snapshot\", 1, true) and\n"+
			"    string.sub(raw, -4) == \",333\" then\n"+
			"    dictionary:set(\"__cdnca_test_lease_state_after_add\",\n"+
			"      tostring(ngx.worker.pid()) .. \":\" .. tostring(generation), 3)\n"+
			"    ngx.sleep(1.3)\n"+
			"  elseif string.find(base_key, \":circuit-snapshot\", 1, true) and\n"+
			"    string.sub(raw, -4) == \",555\" then\n"+
			"    dictionary:set(\"__cdnca_test_lease_cleanup_generation\", tostring(generation), 3)\n"+
			"  end\n", 1)
	if statePostAddInstrumented == stateInstrumented {
		t.Fatal("lease state post-add instrumentation point is missing")
	}
	cleanupInstrumented := strings.Replace(statePostAddInstrumented,
		"  -- CDNCA_TEST_LEASE_CLEANUP_CAPTURE_BARRIER\n",
		"  if dictionary:get(key .. ':test-cleanup-generation') == tostring(generation) then\n"+
			"    dictionary:set(key .. ':test-cleanup-capture', tostring(ngx.worker.pid()), 2)\n"+
			"    ngx.sleep(0.7)\n"+
			"  elseif dictionary:get('__cdnca_test_lease_cleanup_generation') == tostring(generation) and\n"+
			"    string.find(key, ':circuit-snapshot', 1, true) then\n"+
			"    dictionary:set('__cdnca_test_lease_cleanup_capture', tostring(ngx.worker.pid()), 3)\n"+
			"    ngx.sleep(1.3)\n"+
			"  end\n", 1)
	if cleanupInstrumented == statePostAddInstrumented {
		t.Fatal("lease cleanup captured-slot instrumentation point is missing")
	}
	instrumented = cleanupInstrumented
	instrumentedRoot := filepath.Join(root, fmt.Sprintf("probe-race-lua-%d", policy.Revision))
	if err := os.Mkdir(instrumentedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(instrumentedRoot, "engine.lua"), []byte(instrumented), 0o400); err != nil {
		t.Fatal(err)
	}
	artifact, err := Compile(policy, root, instrumentedRoot)
	if err != nil {
		t.Fatal(err)
	}
	config := strings.Replace(string(artifact.Nginx),
		"lua_shared_dict cdnca_originroute_state 1m;",
		"lua_shared_dict cdnca_originroute_state 256k;", 1)
	config = strings.Replace(config, "worker_processes 1;", "worker_processes 2;", 1)
	circuitKeyPrefix := fmt.Sprintf("c1:v1|tenant=%s|site=%s|version=%s:%d", policy.TenantID, policy.SiteID, policy.VersionID, policy.Revision)
	probeKey := circuitKeyPrefix + ":l2:probe"
	openKey := circuitKeyPrefix + ":l2:open"
	casCircuitKey := circuitKeyPrefix + ":cas:probe"
	casAdaptiveKey := fmt.Sprintf("a1:%s:%d:cas:endpoint:probe", policy.VersionID, policy.Revision)
	circuitSnapshotKey := circuitKeyPrefix + ":l2:circuit-snapshot"
	circuitStateLockKey := circuitKeyPrefix + ":l2:state-lock"
	historyBoundKey := fmt.Sprintf("v1:%s:%d:history-bound", policy.VersionID, policy.Revision)
	leaseSeconds := float64(policy.Retry.TotalBudgetMS)/1000 + 1
	locations := fmt.Sprintf(`    location = /__originroute_test_fill {
	      content_by_lua_block {
	        local dictionary = ngx.shared.cdnca_originroute_state
		        local minimum = %d
		        local sizes = {1, 8, 24, 56, 120, 248, 504, 1016, 2040, 4088, 8184}
		        local filled = 0
		        local index = 0
		        while dictionary:free_space() >= minimum and index < 8192 do
		          index = index + 1
		          local wrote = false
		          for _, size in ipairs(sizes) do
	            local ok = dictionary:safe_set(
	              "pressure:" .. size .. ":" .. index, string.rep("x", size), 1)
	            if ok then
	              filled = filled + 1
	              wrote = true
	            end
		          end
		          if not wrote then break end
		        end
		        local free = dictionary:free_space()
		        ngx.header["X-CDNCA-Test-Pressure-Entries"] = tostring(filled)
		        ngx.header["X-CDNCA-Test-Pressure-Free-Bytes"] = tostring(free)
		        if free >= minimum then ngx.status = 500 end
	        ngx.say(free)
      }
    }
    location = /__originroute_test_keys {
      content_by_lua_block {
        local dictionary = ngx.shared.cdnca_originroute_state
        dictionary:flush_expired(0)
        local count = 0
        for _, key in ipairs(dictionary:get_keys(0)) do
	          if string.sub(key, 1, 3) == "c1:" then count = count + 1 end
        end
        ngx.say(count)
      }
    }
	    location = /__originroute_test_worker {
	      content_by_lua_block {
	        ngx.header["X-CDNCA-Test-Worker"] = tostring(ngx.worker.pid())
	        ngx.say("ok")
	      }
	    }
	    location = /__originroute_test_open {
	      content_by_lua_block {
	        local dictionary = ngx.shared.cdnca_originroute_state
	        dictionary:delete(%q)
	        dictionary:delete(%q)
	        local ok, err = require("engine").test_circuit_state_write("l2", 0, ngx.now() - 1)
	        if not ok then ngx.status = 500 end
	        ngx.say(ok and "open" or err)
	      }
	    }
    location = /__originroute_test_block {
      content_by_lua_block {
	        local dictionary = ngx.shared.cdnca_originroute_state
	        dictionary:delete(%q)
	        dictionary:delete(%q)
	        local ok, err = require("engine").test_circuit_state_write("l2", 0, ngx.now() + 5)
	        if not ok then ngx.status = 500 end
	        ngx.say(ok and "blocked" or err)
      }
    }
	    location = /__originroute_test_drop_open {
	      content_by_lua_block {
	        ngx.shared.cdnca_originroute_state:delete(%q)
	        local ok, err = require("engine").test_circuit_state_write("l2", 0, 0)
	        if not ok then ngx.status = 500 end
	        ngx.say(ok and "dropped" or err)
      }
    }
    location = /__originroute_test_replace_probe {
      content_by_lua_block {
        local ok, err = require("engine").test_probe_replace(
          "cdnca_originroute_state", %q, "replacement", %.3f)
        if not ok then ngx.status = 500 end
        ngx.say(ok and "replacement" or err)
      }
    }
    location = /__originroute_test_probe {
      content_by_lua_block {
        local value = require("engine").test_probe_value(
          "cdnca_originroute_state", %q)
        ngx.say(value or "missing")
      }
    }
    location = /__originroute_test_cas_seed {
      content_by_lua_block {
        local key = ngx.var.arg_kind == "adaptive" and %q or %q
        ngx.shared.cdnca_originroute_state:delete(key .. ":test-write")
	        ngx.shared.cdnca_originroute_state:delete(key .. ":test-post-add")
        local ok, err = require("engine").test_probe_seed(
          "cdnca_originroute_state", key, "old-owner", 2)
        if not ok then ngx.status = 500 end
        ngx.say(ok and "ok" or err)
      }
    }
	    location = /__originroute_test_cas_reset {
	      content_by_lua_block {
	        local key = ngx.var.arg_kind == "adaptive" and %q or %q
	        local ok, err = require("engine").test_probe_clear(
	          "cdnca_originroute_state", key)
	        if not ok then ngx.status = 500 end
	        ngx.say(ok and "ok" or err)
	      }
	    }
    location = /__originroute_test_cas_release {
      content_by_lua_block {
        local key = ngx.var.arg_kind == "adaptive" and %q or %q
        local _, worker = require("engine").test_probe_release(
          "cdnca_originroute_state", key, "old-owner")
        ngx.say(worker)
      }
    }
    location = /__originroute_test_cas_read {
      content_by_lua_block {
        local key = ngx.var.arg_kind == "adaptive" and %q or %q
        ngx.say(ngx.shared.cdnca_originroute_state:get(key .. ":test-read") or "waiting")
      }
    }
    location = /__originroute_test_cas_replace {
      content_by_lua_block {
        local key = ngx.var.arg_kind == "adaptive" and %q or %q
        local ok, worker = require("engine").test_probe_replace(
          "cdnca_originroute_state", key, "replacement", 2)
        if not ok then ngx.status = 500 end
        ngx.say(ok and worker or "failed")
      }
    }
    location = /__originroute_test_cas_value {
      content_by_lua_block {
        local key = ngx.var.arg_kind == "adaptive" and %q or %q
        ngx.say(require("engine").test_probe_value(
          "cdnca_originroute_state", key) or "missing")
      }
    }
    location = /__originroute_test_cas_write_read {
      content_by_lua_block {
        local key = ngx.var.arg_kind == "adaptive" and %q or %q
	        local suffix = ngx.var.arg_phase == "post-add" and ":test-post-add" or
	          ngx.var.arg_phase == "cleanup" and ":test-cleanup-capture" or ":test-write"
	        ngx.say(ngx.shared.cdnca_originroute_state:get(key .. suffix) or "waiting")
      }
    }
	    location = /__originroute_test_cas_write {
      content_by_lua_block {
        local key = ngx.var.arg_kind == "adaptive" and %q or %q
        local owner = ngx.var.arg_owner
	        if owner ~= "stalled-owner" and owner ~= "replacement" and
	          owner ~= "round5-stalled" and owner ~= "round5-replacement" and
	          owner ~= "round6-seed" and owner ~= "round6-stalled-cleanup" and
	          owner ~= "round6-successor" then
	          ngx.status = 400; return
	        end
	        local stalled = owner == "round5-stalled" or owner == "round6-stalled-cleanup"
	        local ttl = ngx.var.arg_round5 == "1" and stalled and 0.4 or 30
	        local engine = require("engine")
		        local ok, err, generation = engine.test_probe_replace(
		          "cdnca_originroute_state", key, owner, ttl)
	        if ok and ngx.var.arg_release == "1" then
	          local released, release_err = engine.test_probe_release(
	            "cdnca_originroute_state", key, owner)
	          if not released then ok = nil; err = release_err end
	        end
        if not ok then ngx.status = 500 end
		        ngx.header["X-CDNCA-Test-Generation"] = tostring(generation or "")
        ngx.say(ok and "ok" or err)
	      }
	    }
	    location = /__originroute_test_state_write {
	      content_by_lua_block {
	        ngx.header["X-CDNCA-Test-Worker"] = tostring(ngx.worker.pid())
	        local owner = ngx.var.arg_owner
	        local marker = owner == "stalled" and 111 or owner == "replacement" and 222 or
	          owner == "round5-stalled" and 333 or owner == "round5-replacement" and 444 or
	          owner == "round6-seed" and 4 or owner == "round6-stalled-cleanup" and 555 or
	          owner == "round6-successor" and 666 or
	          owner == "seed" and 1
	        if not marker then ngx.status = 400; return end
		        local ok, err, generation = require("engine").test_circuit_state_write("l2", marker)
		        if not ok then ngx.status = 500 end
		        ngx.header["X-CDNCA-Test-Generation"] = tostring(generation or "")
	        ngx.say(ok and "ok" or err)
	      }
	    }
	    location = /__originroute_test_state_reset {
	      content_by_lua_block {
	        local engine = require("engine")
	        local state_ok, state_err = engine.test_lease_state_clear(
	          "cdnca_originroute_state", %q)
	        local lock_ok, lock_err = engine.test_probe_clear(
	          "cdnca_originroute_state", %q)
	        if not state_ok or not lock_ok then ngx.status = 500 end
		        ngx.shared.cdnca_originroute_state:delete("__cdnca_test_lease_state_after_add")
		        ngx.shared.cdnca_originroute_state:delete("__cdnca_test_lease_cleanup_capture")
		        ngx.shared.cdnca_originroute_state:delete("__cdnca_test_lease_cleanup_generation")
	        ngx.say(state_ok and lock_ok and "ok" or state_err or lock_err)
	      }
	    }
	    location = /__originroute_test_history_counts {
	      content_by_lua_block {
	        local key = ngx.var.arg_kind == "adaptive" and %q or %q
		        local owners, slots, releases, values, commits = require("engine").test_lease_key_counts(
		          "cdnca_originroute_state", key)
		        ngx.say(table.concat({owners, slots, releases, values, commits}, ","))
	      }
	    }
	    location = /__originroute_test_state_history_counts {
	      content_by_lua_block {
		        local owners, slots, releases, values, commits = require("engine").test_lease_key_counts(
		          "cdnca_originroute_state", %q)
		        ngx.say(table.concat({owners, slots, releases, values, commits}, ","))
	      }
	    }
	    location = /__originroute_test_history_bound {
	      content_by_lua_block {
	        local iterations = tonumber(ngx.var.arg_iterations)
	        local ok, err = require("engine").test_probe_history_bound(
	          "cdnca_originroute_state", %q, iterations)
	        if not ok then ngx.status = 500 end
	        ngx.say(ok and "ok" or err)
	      }
	    }
	    location = /__originroute_test_history_bound_counts {
	      content_by_lua_block {
		        local owners, slots, releases, values, commits = require("engine").test_lease_key_counts(
		          "cdnca_originroute_state", %q)
		        ngx.say(table.concat({owners, slots, releases, values, commits}, ","))
	      }
	    }
	    location = /__originroute_test_state_write_ready {
	      content_by_lua_block {
	        ngx.say(ngx.shared.cdnca_originroute_state:get("__cdnca_test_lease_state_write") or "waiting")
	      }
	    }
	    location = /__originroute_test_state_after_add_ready {
	      content_by_lua_block {
	        ngx.say(ngx.shared.cdnca_originroute_state:get(
	          "__cdnca_test_lease_state_after_add") or "waiting")
	      }
	    }
		    location = /__originroute_test_state_cleanup_ready {
	      content_by_lua_block {
	        ngx.say(ngx.shared.cdnca_originroute_state:get(
	          "__cdnca_test_lease_cleanup_capture") or "waiting")
		      }
		    }
		    location = /__originroute_test_round7_lock_seed {
		      content_by_lua_block {
		        local ok, err = require("engine").test_mutation_lock_seed(
		          "cdnca_originroute_state", "__cdnca_round7_mutation_lock",
		          ngx.var.arg_token, tonumber(ngx.var.arg_ttl))
		        if not ok then ngx.status = 500 end
		        ngx.say(ok and "ok" or err)
		      }
		    }
		    location = /__originroute_test_round7_lock_release {
		      content_by_lua_block {
		        local ok, err = require("engine").test_mutation_lock_release(
		          "cdnca_originroute_state", "__cdnca_round7_mutation_lock", ngx.var.arg_token)
		        if not ok then ngx.status = 409 end
		        ngx.say(ok and "owned" or err or "not-owned")
		      }
		    }
		    location = /__originroute_test_round7_lock_value {
		      content_by_lua_block {
		        ngx.say(require("engine").test_mutation_lock_value(
		          "cdnca_originroute_state", "__cdnca_round7_mutation_lock") or "missing")
		      }
		    }
		    location = /__originroute_test_round7_history {
		      content_by_lua_block {
		        local iterations = tonumber(ngx.var.arg_iterations)
		        local engine = require("engine")
		        local ok, err
		        if ngx.var.arg_kind == "probe" then
		          ok, err = engine.test_probe_interrupted_history(
		            "cdnca_originroute_state", "__cdnca_round7_probe_history", iterations)
		        elseif ngx.var.arg_kind == "state" then
		          ok, err = engine.test_lease_state_interrupted_history(
		            "cdnca_originroute_state", "__cdnca_round7_state_history", iterations)
		        else
		          ngx.status = 400; ngx.say("invalid"); return
		        end
		        if not ok then ngx.status = 500 end
		        ngx.say(ok and "ok" or err)
		      }
		    }
			    location = /__originroute_test_round7_history_counts {
		      content_by_lua_block {
		        local key = ngx.var.arg_kind == "probe" and "__cdnca_round7_probe_history" or
		          ngx.var.arg_kind == "state" and "__cdnca_round7_state_history" or nil
		        if not key then ngx.status = 400; ngx.say("invalid"); return end
		        local engine = require("engine")
		        local owners, slots, releases, values, commits = engine.test_lease_key_counts(
		          "cdnca_originroute_state", key)
		        local cleared, clear_err
		        if ngx.var.arg_kind == "probe" then
		          cleared, clear_err = engine.test_probe_clear("cdnca_originroute_state", key)
		        else
		          cleared, clear_err = engine.test_lease_state_clear("cdnca_originroute_state", key)
		        end
		        if not cleared then ngx.status = 500; ngx.say(clear_err); return end
		        ngx.say(table.concat({owners, slots, releases, values, commits}, ","))
		      }
		    }
		    location = /__originroute_test_round7_fault {
		      content_by_lua_block {
		        local kind = ngx.var.arg_kind
		        local keys = {
		          ["counter-missing"] = "__cdnca_round7_fault_counter",
		          ["overflow"] = "__cdnca_round7_fault_overflow",
		          ["restart-mismatch"] = "__cdnca_round7_fault_restart",
		          ["order-missing"] = "__cdnca_round7_fault_order",
		        }
		        if not keys[kind] then ngx.status = 400; ngx.say("invalid"); return end
		        local rejected, err = require("engine").test_lease_protocol_fault(
		          "cdnca_originroute_state", keys[kind], kind)
		        if not rejected then ngx.status = 500 end
		        ngx.say(rejected and err or "accepted")
		      }
		    }
		    location = /__originroute_test_round7_late_write {
		      content_by_lua_block {
		        local value = ngx.var.arg_value
		        if value ~= "round7-older" and value ~= "round7-newer" then
		          ngx.status = 400; ngx.say("invalid"); return
		        end
		        local ok, err, generation = require("engine").test_lease_state_replace(
		          "cdnca_originroute_state", "__cdnca_round7_late_state", value, 60)
		        if not ok then ngx.status = 500 end
		        ngx.header["X-CDNCA-Test-Generation"] = tostring(generation or "")
		        ngx.say(ok and "ok" or err)
		      }
		    }
		    location = /__originroute_test_round7_late_value {
		      content_by_lua_block {
		        ngx.say(require("engine").test_lease_state_value(
		          "cdnca_originroute_state", "__cdnca_round7_late_state") or "missing")
		      }
		    }
		    location = /__originroute_test_round7_barrier {
		      content_by_lua_block {
		        local key = ngx.var.arg_kind == "lock" and "__cdnca_test_round7_lock_release" or
		          ngx.var.arg_kind == "late" and "__cdnca_test_round7_late_commit" or nil
		        if not key then ngx.status = 400; ngx.say("invalid"); return end
		        ngx.say(ngx.shared.cdnca_originroute_state:get(key) or "waiting")
		      }
		    }
		    location = /__originroute_test_round8_precommit {
		      content_by_lua_block {
		        local ok, err, value = require("engine").test_lease_precommit_failures(
		          "cdnca_originroute_state", "__cdnca_round8_precommit",
		          tonumber(ngx.var.arg_failures))
		        if not ok then ngx.status = 500 end
		        ngx.say(ok and value or err)
		      }
		    }
		    location = /__originroute_test_round8_value {
		      content_by_lua_block {
		        ngx.say(require("engine").test_lease_state_value(
		          "cdnca_originroute_state", "__cdnca_round8_precommit") or "missing")
		      }
		    }
		    location = /__originroute_test_round8_metadata {
		      content_by_lua_block {
		        local ok, err, before, after = require("engine").test_lease_metadata_reclaim(
		          "cdnca_originroute_state", "__cdnca_round8_revision:",
		          tonumber(ngx.var.arg_revisions))
		        if not ok then ngx.status = 500 end
		        ngx.say(ok and table.concat({before, after}, ",") or err)
		      }
		    }
		    location = /__originroute_test_round8_fault {
		      content_by_lua_block {
		        local ok, err, result = require("engine").test_lease_round8_fault(
		          "cdnca_originroute_state", "__cdnca_round8_fault", ngx.var.arg_kind)
		        if not ok then ngx.status = 500 end
		        ngx.say(ok and result or err)
		      }
		    }
		    location = /__originroute_test_state_value {
	      content_by_lua_block {
	        ngx.say(require("engine").test_circuit_state_value("l2") or "missing")
	      }
	    }
`, originRouteStateMinFreeBytes, probeKey, openKey, probeKey, openKey, openKey, probeKey, leaseSeconds, probeKey,
		casAdaptiveKey, casCircuitKey, casAdaptiveKey, casCircuitKey, casAdaptiveKey, casCircuitKey,
		casAdaptiveKey, casCircuitKey, casAdaptiveKey, casCircuitKey,
		casAdaptiveKey, casCircuitKey, casAdaptiveKey, casCircuitKey,
		casAdaptiveKey, casCircuitKey, circuitSnapshotKey, circuitStateLockKey,
		casAdaptiveKey, casCircuitKey, circuitSnapshotKey, historyBoundKey, historyBoundKey)
	needle := "    location / {\n"
	if !strings.Contains(config, needle) {
		t.Fatal("compiled config has no proxy location")
	}
	config = strings.Replace(config, needle, locations+needle, 1)
	config = strings.Replace(config, "      proxy_http_version 1.1;\n",
		"      add_header X-CDNCA-Origin-Event $cdnca_origin_event always;\n"+
			"      proxy_http_version 1.1;\n", 1)
	release := filepath.Join(root, "versions", artifact.Digest)
	if err := os.Mkdir(release, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "policy.json"), artifact.Policy, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "nginx.conf"), []byte(config), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(release, 0o500); err != nil {
		t.Fatal(err)
	}
	return release
}

func activateOriginRouteStateTestRelease(
	t *testing.T, runtime *OpenRestyRuntime, root, release, version string, port uint16,
) {
	t.Helper()
	ctx := originRouteSmokeContext(t)
	if err := runtime.Precheck(ctx, release); err != nil {
		t.Fatalf("state release precheck version=%s release=%s: %v", version, filepath.Base(release), err)
	}
	temporary := filepath.Join(root, ".current-test")
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("versions", filepath.Base(release)), temporary); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Reload(ctx, release); err != nil {
		t.Fatalf("state release reload version=%s release=%s: %v", version, filepath.Base(release), err)
	}
	if err := runtime.Healthy(ctx, version); err != nil {
		t.Fatalf("state release health version=%s: %v", version, err)
	}
	waitOriginRouteHealthVersion(t, port, version)
}

func originRouteStateKeyCount(t *testing.T, port uint16) int {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet, "/__originroute_test_keys", nil)
	if response.status != http.StatusOK {
		t.Fatalf("state key status=%d body=%q", response.status, response.body)
	}
	count, err := strconv.Atoi(response.body)
	if err != nil {
		t.Fatalf("state key count %q: %v", response.body, err)
	}
	return count
}

func verifyOriginRouteInitialFailure(t *testing.T, binary, luaRoot string, policy Policy) bool {
	t.Helper()
	policy.Revision = 1
	policy.VersionID = "route-initial-failure"
	policy.Listeners[0].Port = reserveOriginRouteSmokePort(t)
	root := privateOriginRouteSmokeDir(t)
	base, err := NewOpenRestyRuntime(binary, root, originRouteHealthProbe(policy.Listeners[0].Port))
	if err != nil {
		t.Fatal(err)
	}
	runtime := injectedOriginRouteHealth{base: base, failVersion: policy.VersionID}
	publisher, err := NewPublisher(root, luaRoot, SystemAddressInspector{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	_, err = publisher.Apply(originRouteSmokeContext(t), policyJSON(t, policy))
	if !errors.Is(err, ErrHealth) {
		t.Fatalf("initial health failure error=%v", err)
	}
	_, running, pidErr := runningProcessID(filepath.Join(root, "shared", "originroute.pid"))
	_, currentErr := os.Lstat(filepath.Join(root, "current"))
	return pidErr == nil && !running && errors.Is(currentErr, os.ErrNotExist)
}

func reserveOriginRouteSmokePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}

func privateOriginRouteSmokeDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return root
}

func originRouteSmokeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}
