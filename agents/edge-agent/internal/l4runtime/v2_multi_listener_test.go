package l4runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func multiListenerV2Spec() StreamRuntimeSpecV2 {
	spec := l403StreamSpec()
	spec.ProxyProtocolInbound, spec.ProxyProtocolOutbound = false, false
	spec.Geo.TrustedProxyCIDRs = nil
	spec.AdditionalListeners = []AdditionalListenerV2{
		{ID: "55555555-5555-4555-8555-555555555555", Protocol: ProtocolUDP, Address: "*", Port: 9445},
		{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolTCP, Address: "*", Port: 9444},
	}
	return spec
}

func TestV2AdditionalListenersKeepOneStreamAndCanonicalIdentity(t *testing.T) {
	spec := multiListenerV2Spec()
	config, err := AggregateStreamRuntimeSpecsV2("multi", 9, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Listeners) != 1 || len(config.Listeners[0].AdditionalListeners) != 2 || config.Listeners[0].ResourceRevision != 7 {
		t.Fatalf("stream or resource revision was split, or additional sockets dropped: %+v", config)
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{spec.StreamID: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.ResolvedAddressSets) != 1 || strings.Count(string(compiled.NginxConfig), "    upstream ") != 1 || strings.Count(string(compiled.NginxConfig), "    server {") != 4 {
		// three sockets and the live registry's control socket (L4-USAGE-01)
		t.Fatalf("expected one upstream and three socket servers: %s", compiled.NginxConfig)
	}
	var geo geoRuntimeConfigV2
	if err := json.Unmarshal(compiled.GeoJSON, &geo); err != nil || len(geo.Listeners) != 1 || geo.Listeners[0].ID != spec.StreamID {
		t.Fatalf("Geo stream identity was split: %s, %v", compiled.GeoJSON, err)
	}
	if strings.Count(string(compiled.NginxConfig), `.enforce("`+spec.StreamID+`")`) != 3 {
		t.Fatal("not every listener enforces the same resource Geo policy")
	}
	for _, socket := range spec.AdditionalListeners {
		if !strings.Contains(string(compiled.NginxConfig), `listener-`+socket.ID+`--`) || !strings.Contains(string(compiled.NginxConfig), `$cdnca_l4_listener_id "`+socket.ID+`"`) {
			t.Fatalf("socket has no independent telemetry identity: %s", socket.ID)
		}
	}
	spec.AdditionalListeners[0], spec.AdditionalListeners[1] = spec.AdditionalListeners[1], spec.AdditionalListeners[0]
	reordered, err := AggregateStreamRuntimeSpecsV2("multi", 9, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalV2(reordered)
	if err != nil || !bytes.Equal(canonical, compiled.CanonicalJSON) {
		t.Fatal("array order changed canonical bytes")
	}
	if spec.AdditionalListeners[0].Address != "*" {
		t.Fatal("normalization mutated caller slice")
	}
}

func TestV2AdditionalListenersRejectInvalidOrConflictingSockets(t *testing.T) {
	for name, mutate := range map[string]func(*StreamRuntimeSpecV2){
		"bad id":           func(s *StreamRuntimeSpecV2) { s.AdditionalListeners[0].ID = "not-a-uuid" },
		"stream id":        func(s *StreamRuntimeSpecV2) { s.AdditionalListeners[0].ID = s.StreamID },
		"duplicate id":     func(s *StreamRuntimeSpecV2) { s.AdditionalListeners[0].ID = s.AdditionalListeners[1].ID },
		"bad protocol":     func(s *StreamRuntimeSpecV2) { s.AdditionalListeners[0].Protocol = "quic" },
		"zero port":        func(s *StreamRuntimeSpecV2) { s.AdditionalListeners[0].Port = 0 },
		"bad bind":         func(s *StreamRuntimeSpecV2) { s.AdditionalListeners[0].Address = "host.invalid" },
		"primary conflict": func(s *StreamRuntimeSpecV2) { s.AdditionalListeners[1].Port = s.Listener.Port },
		"extra conflict": func(s *StreamRuntimeSpecV2) {
			s.AdditionalListeners[0].Protocol = ProtocolTCP
			s.AdditionalListeners[0].Port = s.AdditionalListeners[1].Port
		},
		"UDP inbound PROXY": func(s *StreamRuntimeSpecV2) {
			s.ProxyProtocolInbound = true
			s.Geo.TrustedProxyCIDRs = []string{"8.8.8.0/24"}
		},
		"UDP outbound PROXY": func(s *StreamRuntimeSpecV2) { s.ProxyProtocolOutbound = true },
		"too many":           func(s *StreamRuntimeSpecV2) { s.AdditionalListeners = make([]AdditionalListenerV2, 64) },
	} {
		t.Run(name, func(t *testing.T) {
			spec := multiListenerV2Spec()
			mutate(&spec)
			if _, err := AggregateStreamRuntimeSpecsV2("invalid", 9, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("accepted invalid sockets: %v", err)
			}
		})
	}
	first, second := multiListenerV2Spec(), multiListenerV2Spec()
	second.StreamID, second.Geo.StreamID = first.AdditionalListeners[0].ID, first.AdditionalListeners[0].ID
	second.Listener.Port = 10443
	second.AdditionalListeners = nil
	if _, err := AggregateStreamRuntimeSpecsV2("collision", 9, []StreamRuntimeSpecV2{first, second}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("extra ID collides with another stream: %v", err)
	}
}

func TestV2AdditionalListenersEnforceNodeSocketBudget(t *testing.T) {
	specs := make([]StreamRuntimeSpecV2, 4)
	for index := range specs {
		specs[index] = multiListenerV2Spec()
		specs[index].StreamID = fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", index)
		specs[index].Geo.StreamID = specs[index].StreamID
		specs[index].Listener.Port = 10000 + 100*index
		specs[index].AdditionalListeners = nil
		for socket := 1; socket < 64; socket++ {
			specs[index].AdditionalListeners = append(specs[index].AdditionalListeners, AdditionalListenerV2{
				ID: fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012d", index*100+socket), Protocol: ProtocolTCP, Address: "*", Port: 10000 + 100*index + socket,
			})
		}
	}
	if _, err := AggregateStreamRuntimeSpecsV2("limit", 9, specs); err != nil {
		t.Fatalf("256 sockets rejected: %v", err)
	}
	extra := multiListenerV2Spec()
	extra.AdditionalListeners = nil
	if _, err := AggregateStreamRuntimeSpecsV2("limit", 9, append(specs, extra)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("257 sockets accepted: %v", err)
	}
}

func TestV2AdditionalListenersPersistDeletionRollbackAndOfflineReplay(t *testing.T) {
	ctx := context.Background()
	runtime := &v2LifecycleRuntime{}
	manager, root := testManager(t, runtime)
	resolver := &l403Resolver{results: []DNSLookupResult{{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}}}
	dns, err := NewDNSCoordinator(filepath.Join(root, "dns"), resolver, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := multiListenerV2Spec()
	config, err := AggregateStreamRuntimeSpecsV2("multi", 9, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.ApplyV2(ctx, config, dns)
	if err != nil || len(first.ListenerResults) != 3 || resolver.callCount() != 1 {
		t.Fatalf("multi apply=%+v err=%v DNS=%d", first, err, resolver.callCount())
	}
	if err := manager.PrecheckV2(ctx, config, nil); err != nil {
		t.Fatalf("offline precheck: %v", err)
	}
	removed, err := manager.Apply(ctx, Config{SchemaVersion: SchemaVersionV1, VersionID: "empty"})
	if err != nil || len(removed.ListenerResults) != 3 {
		t.Fatalf("extra removal missing: %+v %v", removed, err)
	}
	for _, result := range removed.ListenerResults {
		if result.Operation != ListenerOperationDelete {
			t.Fatalf("wrong removal operation: %+v", result)
		}
	}
	rollback, err := manager.Rollback(ctx, first.VersionID, first.Digest)
	if err != nil || rollback.Digest != first.Digest || len(rollback.ListenerResults) != 3 {
		t.Fatalf("rollback lost sockets: %+v %v", rollback, err)
	}
	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.ApplyV2(ctx, config, nil)
	if err != nil || replay.Digest != first.Digest || resolver.callCount() != 1 {
		t.Fatalf("offline replay changed DNS or digest: %+v %v", replay, err)
	}
	stored, _, err := restarted.store.loadVersion(first.VersionID, first.Digest)
	if err != nil || len(stored.Config.Listeners) != 3 {
		t.Fatalf("persisted runtime lost sockets: %+v %v", stored.Config, err)
	}
}
