package dynroute

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	testTenant = "0d13c000-0000-4000-8000-0000000000c1"
	testStream = "0d13c000-0000-4000-8000-00000000c001"
	testOther  = "0d13c000-0000-4000-8000-00000000c002"
	testL4Site = "0d13c000-0000-4000-8000-00000000c101"
)

func testV2Stream(id, protocol string, port int) edgeconfig.L4StreamRuntimeV2 {
	return edgeconfig.L4StreamRuntimeV2{SchemaVersion: "cdnca.edge.l4/v2", TenantID: testTenant,
		StreamID: id, Revision: 2, Listener: edgeconfig.L4ListenerV2{Protocol: protocol, Address: "*", Port: port},
		Endpoint:         edgeconfig.L4EndpointV2{Address: "192.0.2.10", Port: 9000},
		Geo:              edgeconfig.L4GeoPolicyV2{TenantID: testTenant, StreamID: id, Revision: 2, UnknownRegionAction: "allow"},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 3000, MaxConnectionsPerClient: 20, DrainTimeoutMS: 30000}
}

func testScopeStreams(scope string, streams ...edgeconfig.L4StreamRuntimeV2) ScopeStreams {
	return ScopeStreams{ScopeID: scope, ConfigVersionID: "0d13c000-0000-4000-8000-00000000f001", Revision: 4,
		Runtime: edgeconfig.StreamRuntime{TenantID: testTenant, StreamsV2: streams}}
}

type recordedL4 struct {
	calls   []string
	configs []*l4runtime.ConfigV2
	fail    error
}

func (r *recordedL4) Begin(_ context.Context, version string) error {
	r.calls = append(r.calls, "begin "+version)
	return nil
}

func (r *recordedL4) Apply(_ context.Context, version string, config *l4runtime.ConfigV2) error {
	r.calls = append(r.calls, "apply "+version)
	r.configs = append(r.configs, config)
	return r.fail
}

func (r *recordedL4) Finish(_ context.Context, version string, succeeded bool) error {
	if succeeded {
		r.calls = append(r.calls, "finish "+version)
	} else {
		r.calls = append(r.calls, "abort "+version)
	}
	return nil
}

// A TCP stream on a website's port takes the port's IPv4 socket: the
// website is handed over by name (TLS) to the skeleton's internal socket;
// streams on other ports are exclusive. The DDoS table gets every TCP
// stream port; UDP is not counted.
func TestPlanStreamsDispatchesSharedPorts(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	runtime.config.L4 = &recordedL4{}
	runtime.config.MuxRoot = "/run/cdnca/mux" // sun_path: the test temp dir is too long
	site := testSite(testScopeA, testSiteA, 443, 80)
	site.Hosts = edgesite.Hosts{Primary: "www.example.com", Aliases: []string{"Api.Example.com"}}
	site.Listeners[0].TLS = &edgesite.TLS{}
	passthrough := testV2Stream(testStream, "tcp", 443)
	passthrough.TLSPassthrough, passthrough.ServerNames = true, []string{"db.example.com"}
	plan, err := runtime.planStreams([]edgesite.Site{site},
		[]ScopeStreams{testScopeStreams(testScopeA, passthrough, testV2Stream(testOther, "udp", 5353))})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plan.versionID, "dynroute-l4-") || plan.config == nil || len(plan.config.Listeners) != 2 {
		t.Fatalf("plan %+v", plan)
	}
	if got := sortedPorts(plan.dispatched); !slices.Equal(got, []int{443}) {
		t.Fatalf("dispatched %v", got)
	}
	sockets := plan.config.SiteSockets
	if len(sockets) != 1 || sockets[0].Port != 443 || sockets[0].PlainSocket != "" ||
		!strings.HasSuffix(sockets[0].TLSSocket, "/mux/443-tls.sock") ||
		!slices.Equal(sockets[0].TLSServerNames, []string{"api.example.com", "www.example.com"}) {
		t.Fatalf("site sockets %+v", sockets)
	}
	// the L4 runtime's internal sockets sit under the mux root the workers
	// traverse, not the private deployment root (l4-passthrough)
	if plan.config.DispatchDirectory != "/run/cdnca/mux/l4" {
		t.Fatalf("dispatch directory %q", plan.config.DispatchDirectory)
	}
	if !slices.Equal(plan.tcp, []ddos.PortRange{{First: 443, Last: 443}}) {
		t.Fatalf("tcp %+v", plan.tcp)
	}
	for _, listener := range plan.config.Listeners {
		if listener.ConfigRevision != 4 || listener.ConfigVersionID == "" {
			t.Fatalf("listener keeps its scope release: %+v", listener)
		}
	}
	// the same input is the same version; another stream set is another
	again, err := runtime.planStreams([]edgesite.Site{site},
		[]ScopeStreams{testScopeStreams(testScopeA, passthrough, testV2Stream(testOther, "udp", 5353))})
	if err != nil || again.versionID != plan.versionID {
		t.Fatalf("%v %v", again.versionID, err)
	}
	other, err := runtime.planStreams([]edgesite.Site{site}, []ScopeStreams{testScopeStreams(testScopeA, passthrough)})
	if err != nil || other.versionID == plan.versionID {
		t.Fatalf("%v %v", other.versionID, err)
	}
}

func TestPlanStreamsRefuses(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	plainSite := testSite(testScopeA, testSiteA, 8080)
	for name, test := range map[string]struct {
		l4     L4Runtime
		sites  []edgesite.Site
		scopes []ScopeStreams
	}{
		"no L4 runtime": {nil, nil, []ScopeStreams{testScopeStreams(testScopeA, testV2Stream(testStream, "tcp", 9000))}},
		"scope without forwards": {&recordedL4{}, nil, []ScopeStreams{{ScopeID: testScopeA, ConfigVersionID: "v", Revision: 1,
			Runtime: edgeconfig.StreamRuntime{TenantID: testTenant}}}},
		// plain TCP cannot share a plaintext website's socket (no SNI)
		"plain TCP on a plaintext site port": {&recordedL4{}, []edgesite.Site{plainSite},
			[]ScopeStreams{testScopeStreams(testScopeA, testV2Stream(testStream, "tcp", 8080))}},
		// two scopes' plain forwards on one socket
		"two scopes on one socket": {&recordedL4{}, nil, []ScopeStreams{testScopeStreams(testScopeA, testV2Stream(testStream, "tcp", 9000)),
			testScopeStreams(testScopeB, testV2Stream(testOther, "tcp", 9000))}},
		"health port": {&recordedL4{}, nil, []ScopeStreams{testScopeStreams(testScopeA, testV2Stream(testStream, "tcp", 18080))}},
	} {
		runtime.config.L4, runtime.config.HealthPort = test.l4, 18080
		if _, err := runtime.planStreams(test.sites, test.scopes); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// No scope has streams: nothing until a release ran; then an empty release
// (the L4 runtime stops listening).
func TestPlanStreamsEmpty(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	if plan, err := runtime.planStreams(nil, nil); err != nil || plan.versionID != "" {
		t.Fatalf("%+v %v", plan, err)
	}
	runtime.state.L4 = "dynroute-l4-abc"
	if plan, err := runtime.planStreams(nil, nil); err != nil || plan.versionID != "dynroute-l4-none" || plan.config != nil {
		t.Fatalf("%+v %v", plan, err)
	}
}

// A release that does not pass health is reverted; one that changed
// nothing (the running version) is left alone.
func TestAbortL4(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	recorded := &recordedL4{}
	runtime.config.L4 = recorded
	runtime.state.L4 = "dynroute-l4-running"
	runtime.abortL4(l4Plan{versionID: "dynroute-l4-running"})
	runtime.abortL4(l4Plan{})
	runtime.abortL4(l4Plan{versionID: "dynroute-l4-next"})
	if !slices.Equal(recorded.calls, []string{"abort dynroute-l4-next"}) {
		t.Fatalf("%v", recorded.calls)
	}
	if got := changedPorts(map[int]bool{443: true, 80: true}, map[int]bool{80: true}); !slices.Equal(got, []int{443}) {
		t.Fatalf("%v", got)
	}
}
