package l4runtime

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

type drainLimitRecorder struct {
	drainTestRuntime
	limitsMu sync.Mutex
	limits   []time.Duration
}

func (r *drainLimitRecorder) SetDrainLimit(limit time.Duration) error {
	r.limitsMu.Lock()
	defer r.limitsMu.Unlock()
	r.limits = append(r.limits, limit)
	return nil
}

func intPointer(value int) *int { return &value }

// Every activation hands the runtime the drain limit of the version it
// activates: the candidate's on apply, the LKG's when it is restored.
func TestManagerHandsTheActivatedVersionsDrainLimitToTheRuntime(t *testing.T) {
	runtime := &drainLimitRecorder{}
	manager, _ := testManager(t, runtime)
	first := drainConfig("l4-v1", 100)
	if _, err := manager.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := drainConfig("l4-v2", 100)
	second.DrainMaxMS = intPointer(0)
	if _, err := manager.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	runtime.drainErr = errInjectedDrain
	third := drainConfig("l4-v3", 100)
	third.DrainMaxMS = intPointer(5_000)
	if _, err := manager.Apply(context.Background(), third); !errors.Is(err, ErrActivation) {
		t.Fatalf("Apply(drain failure) = %v", err)
	}
	want := []time.Duration{24 * time.Hour, 0, 5 * time.Second, 0}
	if !reflect.DeepEqual(runtime.limits, want) {
		t.Fatalf("drain limits = %v, want %v (default, unlimited, candidate, restored LKG)", runtime.limits, want)
	}
}

func TestDrainMaxMSIsOptionalBoundedAndMerged(t *testing.T) {
	base, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalV2(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("drain_max_ms")) {
		t.Fatalf("unset drain limit changed the canonical bytes: %s", canonical)
	}
	if got := compatibleCompiledV2(mustCompileV2(t, base)).Config.DrainMaxMS; got != nil {
		t.Fatalf("unset drain limit aggregated to %d", *got)
	}
	limited := l403StreamSpec()
	limited.DrainMaxMS = intPointer(5_000)
	withLimit, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{limited})
	if err != nil {
		t.Fatal(err)
	}
	if got := compatibleCompiledV2(mustCompileV2(t, withLimit)).Config.DrainMaxMS; got == nil || *got != 5_000 {
		t.Fatalf("drain limit aggregated to %v, want 5000", got)
	}
	for _, valid := range []int{0, 1_000, 86_400_000, 7 * 86_400_000} {
		spec := l403StreamSpec()
		spec.DrainMaxMS = intPointer(valid)
		config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
		if err != nil {
			t.Fatalf("drain_max_ms=%d rejected: %v", valid, err)
		}
		canonical, err := CanonicalV2(config)
		if err != nil || !bytes.Contains(canonical, []byte(`"drain_max_ms":`)) {
			t.Fatalf("drain_max_ms=%d canonical=%s err=%v", valid, canonical, err)
		}
	}
	for _, invalid := range []int{-1, 1, 999, 7*86_400_000 + 1} {
		spec := l403StreamSpec()
		spec.DrainMaxMS = intPointer(invalid)
		if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("drain_max_ms=%d accepted: %v", invalid, err)
		}
	}
	for _, test := range []struct {
		values []*int
		want   *int
	}{
		{[]*int{nil, intPointer(5_000)}, intPointer(5_000)},
		{[]*int{intPointer(5_000), intPointer(9_000)}, intPointer(9_000)},
		{[]*int{intPointer(9_000), intPointer(0), intPointer(5_000)}, intPointer(0)},
		{[]*int{nil, nil}, nil},
	} {
		var merged *int
		for _, value := range test.values {
			merged = mergeDrainMaxMS(merged, value)
		}
		if (merged == nil) != (test.want == nil) || (merged != nil && *merged != *test.want) {
			t.Fatalf("merge %v = %v, want %v", test.values, merged, test.want)
		}
	}
}

func mustCompileV2(t *testing.T, config ConfigV2) CompiledConfigV2 {
	t.Helper()
	compiled, err := CompileV2(config, map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8")}})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}
