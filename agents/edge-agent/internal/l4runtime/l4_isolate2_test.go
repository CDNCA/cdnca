package l4runtime

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// degraded forwards persist across an agent restart, and the
// background DNS refresh re-resolves / re-probes the active release, reloading
// only the L4 runtime when an address set changes.

type isolate2World struct {
	mu          sync.Mutex
	now         time.Time
	answers     map[string]DNSLookupResult
	unreachable map[string]bool
	lookups     int
}

func (w *isolate2World) clock() time.Time { w.mu.Lock(); defer w.mu.Unlock(); return w.now }

func (w *isolate2World) advance(d time.Duration) { w.mu.Lock(); w.now = w.now.Add(d); w.mu.Unlock() }

func (w *isolate2World) set(host string, ttl time.Duration, addresses ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(addresses) == 0 {
		delete(w.answers, host)
		return
	}
	result := DNSLookupResult{TTL: ttl}
	for _, address := range addresses {
		result.Addresses = append(result.Addresses, netip.MustParseAddr(address))
	}
	w.answers[host] = result
}

func (w *isolate2World) reach(address string, reachable bool) {
	w.mu.Lock()
	w.unreachable[address] = !reachable
	w.mu.Unlock()
}

func (w *isolate2World) LookupIP(_ context.Context, host string) (DNSLookupResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lookups++
	if result, ok := w.answers[host]; ok {
		return cloneDNSLookupResult(result), nil
	}
	return DNSLookupResult{}, errors.New("lookup " + host + ": server misbehaving")
}

func (w *isolate2World) lookupCount() int { w.mu.Lock(); defer w.mu.Unlock(); return w.lookups }

func (w *isolate2World) health(_ context.Context, _ ListenerV2, addresses []netip.Addr) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, address := range addresses {
		if w.unreachable[address.String()] {
			return errors.New("dial " + address.String() + ": i/o timeout")
		}
	}
	return nil
}

func newIsolate2(t *testing.T) (*Manager, string, *isolate2World, *DNSCoordinator) {
	t.Helper()
	manager, root := testManager(t, &v2LifecycleRuntime{})
	world := &isolate2World{now: fixedTime(), answers: map[string]DNSLookupResult{}, unreachable: map[string]bool{}}
	world.set("unhealthy.example", 60*time.Second, "1.1.1.1")
	world.reach("9.9.9.9", false)
	world.reach("1.1.1.1", false)
	coordinator, err := NewDNSCoordinator(filepath.Join(root, "dns"), world, world.health, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	return manager, root, world, coordinator
}

func readCurrentConf(t *testing.T, root string) string {
	t.Helper()
	conf, err := os.ReadFile(filepath.Join(root, "current", "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(conf)
}

func TestV2DegradedForwardsSurviveAgentRestart(t *testing.T) {
	manager, root, _, coordinator := newIsolate2(t)
	ctx := context.Background()
	if result, err := manager.ApplyV2(ctx, isolateConfig(t), coordinator); err != nil || result.State != StateApplied {
		t.Fatalf("apply = %+v, %v", result, err)
	}
	want := []DegradedStream{
		{StreamID: isolateUnreachable, ReasonCode: DNSReasonStaticUnreachable},
		{StreamID: isolateUnresolved, ReasonCode: DNSReasonUnavailable},
		{StreamID: isolateUnverified, ReasonCode: DNSReasonHealthUnverified},
	}
	if _, err := os.Stat(filepath.Join(root, "state", "l4-streams.json")); err != nil {
		t.Fatalf("degraded forwards not persisted next to the LKG state: %v", err)
	}
	for _, restart := range []func() (*Manager, error){
		func() (*Manager, error) { return NewManager(root, &v2LifecycleRuntime{}) },
		func() (*Manager, error) { return NewDeploymentManager(root, &v2LifecycleRuntime{}) },
	} {
		restarted, err := restart()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := restarted.DegradedStreams(ctx); err != nil || !slices.Equal(got, want) {
			t.Fatalf("degraded after restart = %+v, %v; want %+v", got, err, want)
		}
	}
	// A replay of the same version reuses the snapshot and keeps the reasons.
	if _, err := manager.ApplyV2(ctx, isolateConfig(t), coordinator); err != nil {
		t.Fatal(err)
	}
	if got, _ := manager.DegradedStreams(ctx); !slices.Equal(got, want) {
		t.Fatalf("degraded after replay = %+v", got)
	}
}

func TestV2DNSRefreshClearsRecoveredForwardsAndReloadsOnlyL4(t *testing.T) {
	manager, root, world, coordinator := newIsolate2(t)
	ctx := context.Background()
	config := isolateConfig(t)
	if _, err := manager.ApplyV2(ctx, config, coordinator); err != nil {
		t.Fatal(err)
	}
	before, _ := manager.Status()

	// Nothing recovered yet: no reload, reasons kept.
	result, err := manager.RefreshDNS(ctx, coordinator)
	if err != nil || result.Reloaded || !result.Degraded {
		t.Fatalf("refresh without change = %+v, %v", result, err)
	}

	// Origins come back and the unresolved host resolves.
	world.reach("9.9.9.9", true)
	world.reach("1.1.1.1", true)
	world.set("unresolvable.example", 120*time.Second, "4.4.4.4")
	world.advance(11 * time.Second) // past the negative TTL (10 s)
	result, err = manager.RefreshDNS(ctx, coordinator)
	if err != nil || !result.Reloaded || result.Degraded {
		t.Fatalf("refresh after recovery = %+v, %v", result, err)
	}
	after, _ := manager.Status()
	if after.VersionID != before.VersionID || after.Digest == before.Digest {
		t.Fatalf("refresh changed the release identity or not the snapshot: %+v -> %+v", before, after)
	}
	conf := readCurrentConf(t, root)
	if !strings.Contains(conf, "server 4.4.4.4:443;") || strings.Contains(conf, unavailableUpstreamServer) {
		t.Fatalf("refreshed nginx.conf:\n%s", conf)
	}
	if got, err := manager.DegradedStreams(ctx); err != nil || len(got) != 0 {
		t.Fatalf("degraded after recovery = %+v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "state", "l4-streams.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered forwards left persisted reasons: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "versions", before.VersionID+"-"+before.Digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded snapshot kept: %v", err)
	}
	// The release identity still finishes / replays against the refreshed snapshot.
	if err := manager.BeginRelease(ctx, config.VersionID); err != nil {
		t.Fatal(err)
	}
	if result, err := manager.ApplyV2(ctx, config, coordinator); err != nil || result.Digest != after.Digest {
		t.Fatalf("replay after refresh = %+v, %v", result, err)
	}
	if err := manager.FinishRelease(ctx, config.VersionID, true); err != nil {
		t.Fatalf("finish after refresh: %v", err)
	}
}

func TestV2DNSRefreshFollowsTTLAndKeepsSafetyRules(t *testing.T) {
	manager, root, world, coordinator := newIsolate2(t)
	world.reach("1.1.1.1", true)
	world.reach("9.9.9.9", true)
	world.set("unresolvable.example", 60*time.Second, "4.4.4.4")
	ctx := context.Background()
	if _, err := manager.ApplyV2(ctx, isolateConfig(t), coordinator); err != nil {
		t.Fatal(err)
	}
	lookups := world.lookupCount()

	// Within the TTL nothing is looked up again.
	world.set("unresolvable.example", 60*time.Second, "5.5.5.5")
	result, err := manager.RefreshDNS(ctx, coordinator)
	if err != nil || result.Reloaded || world.lookupCount() != lookups {
		t.Fatalf("refresh inside TTL = %+v, %v lookups %d -> %d", result, err, lookups, world.lookupCount())
	}
	if want := fixedTime().Add(60 * time.Second); !result.NextRefresh.Equal(want) {
		t.Fatalf("next refresh = %s, want %s", result.NextRefresh, want)
	}

	// After it, the new answer is activated.
	world.advance(61 * time.Second)
	if result, err = manager.RefreshDNS(ctx, coordinator); err != nil || !result.Reloaded {
		t.Fatalf("refresh after TTL = %+v, %v", result, err)
	}
	if conf := readCurrentConf(t, root); !strings.Contains(conf, "server 5.5.5.5:443;") || strings.Contains(conf, "server 4.4.4.4:443;") {
		t.Fatalf("nginx.conf after TTL:\n%s", conf)
	}

	// Private and mixed-class answers are refused: the LKG keeps serving.
	for _, answer := range [][]string{{"10.0.0.7"}, {"6.6.6.6", "10.0.0.8"}} {
		world.advance(61 * time.Second)
		world.set("unresolvable.example", 60*time.Second, answer...)
		if result, err = manager.RefreshDNS(ctx, coordinator); err != nil || result.Reloaded {
			t.Fatalf("unsafe answer %v refreshed = %+v, %v", answer, result, err)
		}
		if conf := readCurrentConf(t, root); !strings.Contains(conf, "server 5.5.5.5:443;") {
			t.Fatalf("unsafe answer %v replaced the LKG:\n%s", answer, conf)
		}
	}

	// Lookups fail: the LKG serves until its stale bound, then the forward
	// degrades to refusing connections (the release rule).
	world.set("unresolvable.example", 0)
	world.advance(61 * time.Second)
	if result, err = manager.RefreshDNS(ctx, coordinator); err != nil || result.Reloaded {
		t.Fatalf("failed lookup within stale bound = %+v, %v", result, err)
	}
	world.advance(901 * time.Second)
	if result, err = manager.RefreshDNS(ctx, coordinator); err != nil || !result.Reloaded {
		t.Fatalf("failed lookup past stale bound = %+v, %v", result, err)
	}
	if got, _ := manager.DegradedStreams(ctx); !slices.Equal(got, []DegradedStream{{StreamID: isolateUnresolved, ReasonCode: DNSReasonUnavailable}}) {
		t.Fatalf("degraded past stale bound = %+v", got)
	}
}

func TestV2DNSRefreshLeavesAnOpenReleaseAlone(t *testing.T) {
	manager, _, world, coordinator := newIsolate2(t)
	ctx := context.Background()
	config := isolateConfig(t)
	if _, err := manager.ApplyV2(ctx, config, coordinator); err != nil {
		t.Fatal(err)
	}
	if err := manager.BeginRelease(ctx, "isolate-2"); err != nil {
		t.Fatal(err)
	}
	world.set("unresolvable.example", 60*time.Second, "4.4.4.4")
	world.advance(11 * time.Second)
	lookups := world.lookupCount()
	if result, err := manager.RefreshDNS(ctx, coordinator); err != nil || !result.Skipped || world.lookupCount() != lookups {
		t.Fatalf("refresh during a release = %+v, %v", result, err)
	}
}

func TestDNSRefreshDelayIsBounded(t *testing.T) {
	now := fixedTime()
	for _, item := range []struct {
		next time.Time
		want time.Duration
	}{
		{time.Time{}, DNSRefreshMaxInterval},
		{now.Add(time.Second), DNSRefreshMinInterval},
		{now.Add(-time.Minute), DNSRefreshMinInterval},
		{now.Add(2 * time.Minute), 2 * time.Minute},
		{now.Add(time.Hour), DNSRefreshMaxInterval},
	} {
		if got := refreshDelay(now, item.next); got != item.want {
			t.Fatalf("refreshDelay(%s) = %s, want %s", item.next.Sub(now), got, item.want)
		}
	}
}

func TestRunDNSRefreshRetriesDegradedForwardsAtTheMinimum(t *testing.T) {
	manager, _, world, coordinator := newIsolate2(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := manager.ApplyV2(ctx, isolateConfig(t), coordinator); err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	err := manager.RunDNSRefresh(ctx, coordinator, world.clock, func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		if len(waits) == 3 {
			return context.Canceled
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || !slices.Equal(waits, []time.Duration{DNSRefreshMinInterval, DNSRefreshMinInterval, DNSRefreshMinInterval}) {
		t.Fatalf("waits = %v, %v", waits, err)
	}
}
