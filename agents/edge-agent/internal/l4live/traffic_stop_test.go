package l4live

import (
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// L4_TRAFFIC_STOP: the sessions of a forward withdrawn for package traffic
// are found in the configuration before the release and closed; a forward
// still served, another forward's sessions and a port the new configuration
// serves again (untracked sessions there may be its new owner's) are left.
func TestCloseStreamsClosesWithdrawnForwardsSessions(t *testing.T) {
	const reused = "66666666-6666-4666-8666-000000000003"
	previous, err := l4runtime.AggregateStreamRuntimeSpecsV2("old", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(logged, 18480, true, nil), stream(plain, 18481, false, nil)})
	if err != nil {
		t.Fatal(err)
	}
	// plain keeps running; logged is withdrawn.
	current, err := l4runtime.AggregateStreamRuntimeSpecsV2("new", 2, []l4runtime.StreamRuntimeSpecV2{stream(plain, 18481, false, nil)})
	if err != nil {
		t.Fatal(err)
	}
	kernel := &fakeKernel{sockets: []Socket{
		socket("10.0.0.1:18480", "198.51.100.7:40001", 1), // logged, tracked
		socket("10.0.0.1:18480", "198.51.100.8:40002", 2), // logged, untracked (own port)
		socket("10.0.0.1:18481", "198.51.100.9:40003", 3), // plain: still served
	}}
	registry := &fakeRegistry{values: map[string]string{
		"10.0.0.1|18480|198.51.100.7|40001": logged + "|" + logged + "|198.51.100.7|40001|1700000001.000|1:2|0",
	}}
	executor, err := New(fakeRuntime{config: &current}, kernel, registry, true)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := executor.CloseStreams(t.Context(), &previous, &current, []string{logged, plain})
	if err != nil || closed != 2 || len(kernel.closed) != 2 || kernel.closed[0] != 1 || kernel.closed[1] != 2 {
		t.Fatalf("closed = %d %v inodes %v", closed, err, kernel.closed)
	}
	if len(registry.killed) != 1 || registry.killed[0] != "10.0.0.1|18480|198.51.100.7|40001" {
		t.Fatalf("killed = %v", registry.killed)
	}

	// The withdrawn forward's port now belongs to another forward: only
	// sessions the registry names as the withdrawn one's go.
	kernel.closed, registry.killed = nil, nil
	takeover, err := l4runtime.AggregateStreamRuntimeSpecsV2("next", 3, []l4runtime.StreamRuntimeSpecV2{stream(reused, 18480, false, nil)})
	if err != nil {
		t.Fatal(err)
	}
	closed, err = executor.CloseStreams(t.Context(), &previous, &takeover, []string{logged})
	if err != nil || closed != 1 || len(kernel.closed) != 1 || kernel.closed[0] != 1 {
		t.Fatalf("takeover closed = %d %v inodes %v", closed, err, kernel.closed)
	}

	// Nothing withdrawn by the release (no previous, the forward still
	// served, or none named), or an agent that may not close: no-op.
	kernel.closed = nil
	for name, run := range map[string]func() (int, error){
		"no previous": func() (int, error) { return executor.CloseStreams(t.Context(), nil, &current, []string{logged}) },
		"still served": func() (int, error) {
			return executor.CloseStreams(t.Context(), &previous, &previous, []string{logged})
		},
		"none named": func() (int, error) { return executor.CloseStreams(t.Context(), &previous, &current, nil) },
		"unknown forward": func() (int, error) {
			return executor.CloseStreams(t.Context(), &previous, &current, []string{reused})
		},
	} {
		if closed, err := run(); err != nil || closed != 0 {
			t.Fatalf("%s: %d %v", name, closed, err)
		}
	}
	listOnly, _ := New(fakeRuntime{config: &current}, kernel, registry, false)
	if closed, err := listOnly.CloseStreams(t.Context(), &previous, &current, []string{logged}); err != nil || closed != 0 {
		t.Fatalf("list only: %d %v", closed, err)
	}
	if len(kernel.closed) != 0 {
		t.Fatalf("no-op closed %v", kernel.closed)
	}

	// Every forward withdrawn (no L4 configuration now).
	closed, err = executor.CloseStreams(t.Context(), &previous, nil, []string{logged, plain})
	if err != nil || closed != 3 {
		t.Fatalf("all withdrawn: %d %v", closed, err)
	}
}
