package l4runtime

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestV2DNSLookupRemainsSharedUntilScopedStateIsCommitted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	healthEntered, releaseHealth := make(chan struct{}, 2), make(chan struct{})
	resolver := &l403Resolver{results: []DNSLookupResult{{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}}}
	coordinator, err := NewDNSCoordinator(t.TempDir(), resolver, func(ctx context.Context, _ ListenerV2, _ []netip.Addr) error {
		healthEntered <- struct{}{}
		select {
		case <-releaseHealth:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	config := l403DNSConfig(t)
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := coordinator.Resolve(ctx, config, l403Stream); results <- err }()
		select {
		case <-healthEntered:
		case <-ctx.Done():
			t.Fatal("DNS resolution did not reach the controlled pre-commit health barrier")
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Errorf("lookup completed but scope state pending: got %d DNS lookups, want 1", got)
	}
	close(releaseHealth)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(coordinator.inflight) != 0 {
		t.Fatal("completed DNS resolution retained an inflight lookup")
	}
	if _, err := coordinator.Resolve(ctx, config, l403Stream); err != nil || resolver.callCount() != 1 {
		t.Fatalf("committed scope did not reuse sealed DNS state: %v", err)
	}
}

func TestV2StaticEndpointCompilesAndReplaysWithoutWeakeningDNS(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "10.0.0.1", "fd00::1", "192.0.2.1", "2001:db8::1"} {
		t.Run(raw, func(t *testing.T) {
			spec := l403StreamSpec()
			spec.Endpoint, spec.DNS = EndpointV2{Address: raw, Port: 443}, DNSPolicyV2{}
			config, err := AggregateStreamRuntimeSpecsV2("static-compatible", 7, []StreamRuntimeSpecV2{spec})
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := CompileV2(config, nil)
			if err != nil {
				t.Fatalf("valid explicit static endpoint failed compile: %v", err)
			}
			if addresses := compiled.ResolvedAddressSets[l403Stream]; len(addresses) != 1 || addresses[0].String() != raw {
				t.Fatalf("explicit endpoint changed: %v", addresses)
			}
			manager, root := testManager(t, &v2LifecycleRuntime{})
			resolver := &l403Resolver{results: []DNSLookupResult{{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}}}
			coordinator, err := NewDNSCoordinator(filepath.Join(root, "dns"), resolver, nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			first, err := manager.ApplyV2(context.Background(), config, coordinator)
			if err != nil || resolver.callCount() != 0 {
				t.Fatalf("static apply=%+v err=%v DNS calls=%d", first, err, resolver.callCount())
			}
			restarted, err := NewManager(root, &v2LifecycleRuntime{})
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := restarted.ApplyV2(context.Background(), config, nil)
			if err != nil || replayed.Digest != first.Digest {
				t.Fatalf("static restart replay=%+v err=%v", replayed, err)
			}
			if _, err := CompileV2(l403DNSConfig(t), map[string][]netip.Addr{l403Stream: {netip.MustParseAddr(raw)}}); !errors.Is(err, ErrDNSUnavailable) {
				t.Fatalf("DNS answer %s escaped the strict DNS filter: %v", raw, err)
			}
		})
	}
}
