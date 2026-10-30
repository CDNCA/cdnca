package l4runtime

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type l403Resolver struct {
	mu      sync.Mutex
	results []DNSLookupResult
	errors  []error
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (r *l403Resolver) LookupIP(ctx context.Context, _ string) (DNSLookupResult, error) {
	r.mu.Lock()
	index := r.calls
	r.calls++
	result := r.results[min(index, len(r.results)-1)]
	var err error
	if len(r.errors) != 0 {
		err = r.errors[min(index, len(r.errors)-1)]
	}
	entered, release := r.entered, r.release
	r.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return DNSLookupResult{}, ctx.Err()
		}
	}
	return result, err
}

func (r *l403Resolver) callCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func l403DNSConfig(t *testing.T) ConfigV2 {
	t.Helper()
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestL403DNSCoordinatorRefreshesAtomicallyAndKeepsSealedLKG(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	resolver := &l403Resolver{results: []DNSLookupResult{
		{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: 30 * time.Second},
		{Addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, TTL: 500 * time.Second},
		{Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, TTL: 30 * time.Second},
	}, errors: []error{nil, nil, nil}}
	healthCalls := 0
	coordinator, err := NewDNSCoordinator(t.TempDir(), resolver, func(_ context.Context, _ ListenerV2, addresses []netip.Addr) error {
		healthCalls++
		if len(addresses) == 0 {
			return errors.New("empty address set")
		}
		return nil
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	config := l403DNSConfig(t)
	first, err := coordinator.Resolve(context.Background(), config, l403Stream)
	if err != nil || len(first.Addresses) != 1 || first.Addresses[0].String() != "8.8.8.8" || first.ReasonCode != DNSReasonPromoted {
		t.Fatalf("first resolution = %+v, %v", first, err)
	}
	now = now.Add(29 * time.Second)
	cached, err := coordinator.Resolve(context.Background(), config, l403Stream)
	if err != nil || cached.Addresses[0] != netip.MustParseAddr("8.8.8.8") || resolver.callCount() != 1 {
		t.Fatalf("cached resolution = %+v, %v calls=%d", cached, err, resolver.callCount())
	}
	now = now.Add(2 * time.Second)
	second, err := coordinator.Resolve(context.Background(), config, l403Stream)
	if err != nil || second.Addresses[0] != netip.MustParseAddr("1.1.1.1") || second.RefreshAfter.Sub(now) != 300*time.Second {
		t.Fatalf("bounded positive refresh = %+v, %v", second, err)
	}
	now = second.RefreshAfter.Add(time.Second)
	stale, err := coordinator.Resolve(context.Background(), config, l403Stream)
	if err != nil || stale.Addresses[0] != netip.MustParseAddr("1.1.1.1") || stale.ReasonCode != DNSReasonRebindingRejected {
		t.Fatalf("unsafe candidate replaced LKG = %+v, %v", stale, err)
	}
	if healthCalls != 2 {
		t.Fatalf("unsafe DNS candidate reached health callback: calls=%d", healthCalls)
	}
}

func TestL403DNSCoordinatorNegativeTTLStaleBoundAndHealthFailure(t *testing.T) {
	now := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	resolver := &l403Resolver{results: []DNSLookupResult{
		{Addresses: []netip.Addr{netip.MustParseAddr("8.8.4.4")}, TTL: time.Second},
		{Negative: true}, {Addresses: []netip.Addr{netip.MustParseAddr("9.9.9.9")}, TTL: time.Minute},
	}}
	failHealth := false
	coordinator, err := NewDNSCoordinator(t.TempDir(), resolver, func(_ context.Context, _ ListenerV2, _ []netip.Addr) error {
		if failHealth {
			return errors.New("unhealthy")
		}
		return nil
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	config := l403DNSConfig(t)
	first, err := coordinator.Resolve(context.Background(), config, l403Stream)
	if err != nil {
		t.Fatal(err)
	}
	now = first.RefreshAfter.Add(time.Second)
	stale, err := coordinator.Resolve(context.Background(), config, l403Stream)
	if err != nil || stale.ReasonCode != DNSReasonNegativeLKG || stale.Addresses[0] != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("negative answer = %+v, %v", stale, err)
	}
	now = now.Add(9 * time.Second)
	if _, err := coordinator.Resolve(context.Background(), config, l403Stream); err != nil || resolver.callCount() != 2 {
		t.Fatalf("negative TTL did not suppress lookup: err=%v calls=%d", err, resolver.callCount())
	}
	now = now.Add(2 * time.Second)
	failHealth = true
	stillLKG, err := coordinator.Resolve(context.Background(), config, l403Stream)
	if err != nil || stillLKG.ReasonCode != DNSReasonHealthRejected || stillLKG.Addresses[0] != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("health failure = %+v, %v", stillLKG, err)
	}
	now = first.StaleUntil.Add(time.Second)
	if _, err := coordinator.Resolve(context.Background(), config, l403Stream); !errors.Is(err, ErrDNSStale) {
		t.Fatalf("stale bound error = %v, want ErrDNSStale", err)
	}
}

func TestL403DNSCoordinatorCoalescesHostLookupsAndFencesRevision(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	resolver := &l403Resolver{
		results: []DNSLookupResult{{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}},
		entered: make(chan struct{}, 2), release: make(chan struct{}),
	}
	coordinator, err := NewDNSCoordinator(t.TempDir(), resolver, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	config := l403DNSConfig(t)
	errorsCh := make(chan error, 2)
	for range 2 {
		go func() { _, err := coordinator.Resolve(context.Background(), config, l403Stream); errorsCh <- err }()
	}
	<-resolver.entered
	close(resolver.release)
	for range 2 {
		if err := <-errorsCh; err != nil {
			t.Fatal(err)
		}
	}
	if resolver.callCount() != 1 {
		t.Fatalf("same-host concurrent lookups = %d, want 1", resolver.callCount())
	}
	older := config
	older.Revision = 6
	older.Listeners[0].Geo.Revision = 6
	if _, err := coordinator.Resolve(context.Background(), older, l403Stream); !errors.Is(err, ErrConflict) {
		t.Fatalf("older revision error = %v, want ErrConflict", err)
	}
}

func TestL403DNSCoordinatorFailsClosedOnCorruptState(t *testing.T) {
	root := t.TempDir()
	coordinator, err := NewDNSCoordinator(root, &l403Resolver{results: []DNSLookupResult{{Negative: true}}}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	config := l403DNSConfig(t)
	path := coordinator.statePath(config.Listeners[0])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"seal":"forged"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Resolve(context.Background(), config, l403Stream); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("corrupt state error = %v, want ErrCorruptState", err)
	}
}

func TestL403DNSCoordinatorRejectsPrivateAndDocumentationAnswers(t *testing.T) {
	for _, raw := range []string{"10.0.0.1", "192.0.2.1"} {
		t.Run(raw, func(t *testing.T) {
			resolver := &l403Resolver{results: []DNSLookupResult{{
				Addresses: []netip.Addr{netip.MustParseAddr(raw)}, TTL: time.Minute,
			}}}
			coordinator, err := NewDNSCoordinator(t.TempDir(), resolver, nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Resolve(context.Background(), l403DNSConfig(t), l403Stream); !errors.Is(err, ErrDNSUnavailable) {
				t.Fatalf("DNS answer %s error = %v, want ErrDNSUnavailable", raw, err)
			}
		})
	}
}
