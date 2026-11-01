package l4runtime

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// one forward whose origin is unreachable or unresolvable must
// not fail the release; only that forward degrades (reported, not a gate).
const (
	isolateHealthy     = "a1111111-1111-4111-8111-111111111111"
	isolateUnreachable = "b2222222-2222-4222-8222-222222222222"
	isolateUnresolved  = "c3333333-3333-4333-8333-333333333333"
	isolateUnverified  = "d4444444-4444-4444-8444-444444444444"
)

type isolateResolver map[string]DNSLookupResult

func (r isolateResolver) LookupIP(_ context.Context, host string) (DNSLookupResult, error) {
	if result, ok := r[host]; ok {
		return result, nil
	}
	return DNSLookupResult{}, errors.New("lookup " + host + ": no such host")
}

func isolateSpec(stream string, port int, endpoint EndpointV2) StreamRuntimeSpecV2 {
	spec := l403StreamSpec()
	spec.StreamID, spec.Geo.StreamID = stream, stream
	spec.Listener.Port = port
	spec.Endpoint = endpoint
	if endpoint.Address != "" {
		spec.DNS = DNSPolicyV2{}
	}
	return spec
}

func isolateConfig(t *testing.T) ConfigV2 {
	t.Helper()
	config, err := AggregateStreamRuntimeSpecsV2("isolate-1", 1, []StreamRuntimeSpecV2{
		isolateSpec(isolateHealthy, 9001, EndpointV2{Address: "8.8.8.8", Port: 443}),
		isolateSpec(isolateUnreachable, 9002, EndpointV2{Address: "9.9.9.9", Port: 443}),
		isolateSpec(isolateUnresolved, 9003, EndpointV2{Host: "unresolvable.example", Port: 443}),
		isolateSpec(isolateUnverified, 9004, EndpointV2{Host: "unhealthy.example", Port: 443}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestV2UnreachableOriginDegradesOnlyItsForward(t *testing.T) {
	manager, root := testManager(t, &v2LifecycleRuntime{})
	resolver := isolateResolver{"unhealthy.example": {Addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, TTL: 60e9}}
	coordinator, err := NewDNSCoordinator(filepath.Join(root, "dns"), resolver, func(_ context.Context, _ ListenerV2, addresses []netip.Addr) error {
		if address := addresses[0].String(); address == "9.9.9.9" || address == "1.1.1.1" {
			return errors.New("dial tcp4 " + address + ":443: i/o timeout")
		}
		return nil
	}, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	config := isolateConfig(t)
	ctx := context.Background()
	if err := manager.PrecheckV2(ctx, config, coordinator); err != nil {
		t.Fatalf("precheck failed on one forward's origin: %v", err)
	}
	result, err := manager.ApplyV2(ctx, config, coordinator)
	if err != nil || result.State != StateApplied {
		t.Fatalf("apply failed on one forward's origin: %+v %v", result, err)
	}
	conf, err := os.ReadFile(filepath.Join(root, "current", "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server 8.8.8.8:443;", "server 9.9.9.9:443;", "server 1.1.1.1:443;", "listen 0.0.0.0:9003"} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("nginx.conf lacks %q:\n%s", want, conf)
		}
	}
	if strings.Count(string(conf), "server "+unavailableUpstreamServer+" down;") != 1 {
		t.Fatalf("the unresolved forward has no placeholder upstream:\n%s", conf)
	}
	want := []DegradedStream{
		{StreamID: isolateUnreachable, ReasonCode: DNSReasonStaticUnreachable},
		{StreamID: isolateUnresolved, ReasonCode: DNSReasonUnavailable},
		{StreamID: isolateUnverified, ReasonCode: DNSReasonHealthUnverified},
	}
	if got, err := manager.DegradedStreams(ctx); err != nil || !slices.Equal(got, want) {
		t.Fatalf("degraded = %+v, %v; want %+v", got, err, want)
	}
	// the probe results are persisted, a restart keeps them all.
	restarted, err := NewManager(root, &v2LifecycleRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.DegradedStreams(ctx); err != nil || !slices.Equal(got, want) {
		t.Fatalf("degraded after restart = %+v, %v", got, err)
	}
}

func TestV2CompileAcceptsAnUnavailableHostSetButNotAnUnsafeOne(t *testing.T) {
	config := l403DNSConfig(t)
	compiled, err := CompileV2(config, nil)
	if err != nil {
		t.Fatalf("missing host set failed compile: %v", err)
	}
	if !strings.Contains(string(compiled.NginxConfig), "server "+unavailableUpstreamServer+" down;") {
		t.Fatalf("no placeholder upstream:\n%s", compiled.NginxConfig)
	}
	if _, err := CompileV2(config, map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("10.0.0.1")}}); !errors.Is(err, ErrDNSUnavailable) {
		t.Fatalf("unsafe answer compiled: %v", err)
	}
}
