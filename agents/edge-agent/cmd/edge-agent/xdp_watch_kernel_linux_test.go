//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
)

// Real kernel case (scripts/edge-xdp-smoke.sh, privileged disposable
// container only): generic XDP on a veth, the interface is
// removed so verification fails (fallback) and the reattach attempts fail
// until it is back. The fallback and the reattach are each one node security
// event, and XDP_FILTER follows the filter (Changed signalled, Ready flips).
//
//	CDNCA_XDP_KERNEL_TEST=1 go test -run KernelXDPWatch ./cmd/edge-agent/
func TestKernelXDPWatchReportsFallbackAndReattachOnce(t *testing.T) {
	if os.Getenv("CDNCA_XDP_KERNEL_TEST") != "1" {
		t.Skip("CDNCA_XDP_KERNEL_TEST is not set (privileged disposable container only)")
	}
	if os.Getenv("CDNCA_XDP_EXPECT") == "nftables" {
		t.Skip("fallback run")
	}
	const link, peer = "xdpw0", "xdpw1"
	run := func(command ...string) {
		t.Helper()
		if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", command, err, output)
		}
	}
	addLink := func() {
		run("ip", "link", "add", link, "type", "veth", "peer", "name", peer)
		run("ip", "addr", "add", "10.78.0.1/24", "dev", link)
		run("ip", "link", "set", link, "up")
		run("ip", "link", "set", peer, "up")
	}
	_ = exec.Command("ip", "link", "del", link).Run()
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", link).Run() })
	addLink()

	manager := xdp.Probe(xdp.Options{Interfaces: []string{link}, Modes: []xdp.Mode{xdp.ModeGeneric}})
	t.Cleanup(manager.Close)
	if status := manager.Status(); status.Mode != xdp.ModeGeneric {
		t.Fatalf("probe %+v", status)
	}
	capability := xdpCapability(manager)
	if !capability.Ready() {
		t.Fatal("attached filter not declared")
	}
	events := newNodeSecurityEvents("8b5d1c1e-3a43-4a47-9a6b-4a0bb2d1f0a1", time.Now)
	mirrored := 0
	watch := newXDPWatch(manager, func() { mirrored++ }, events)
	drain := func() []autodefense.NodeEvent {
		var out []autodefense.NodeEvent
		for {
			select {
			case raw := <-events.Reports():
				report, err := autodefense.DecodeReport(raw)
				if err != nil {
					t.Fatalf("report: %v", err)
				}
				out = append(out, *report.NodeEvent)
			default:
				return out
			}
		}
	}
	signalled := func() bool {
		select {
		case <-capability.Changed:
			return true
		default:
			return false
		}
	}
	now := time.Unix(1_800_000_000, 0)
	watch.step(now)
	if got := drain(); len(got) != 0 || signalled() {
		t.Fatalf("healthy step reported %v", got)
	}

	// The interface goes away: verification fails, the node falls back.
	run("ip", "link", "del", link)
	watch.step(now.Add(xdpVerifyInterval))
	got := drain()
	if len(got) != 1 || got[0].Source != "xdp" || got[0].Kind != "fallback" || got[0].Reason != xdp.ReasonVerifyFailed {
		t.Fatalf("fallback events %+v", got)
	}
	if !signalled() || capability.Ready() {
		t.Fatalf("XDP_FILTER not withdrawn: ready=%v", capability.Ready())
	}
	// The retries fail while the interface is missing: no more events.
	for range 3 {
		watch.step(watch.retryAt)
	}
	if status := manager.Status(); status.Reason != xdp.ReasonAttachFailed || manager.Running() {
		t.Fatalf("failed retries status %+v", status)
	}
	if got := drain(); len(got) != 0 || signalled() {
		t.Fatalf("failed retries reported %v", got)
	}

	// The interface is back: the next retry reattaches (one event).
	addLink()
	watch.step(watch.retryAt)
	got = drain()
	if len(got) != 1 || got[0].Kind != "reattached" || got[0].Reason != string(xdp.ModeGeneric) || got[0].Level != autodefense.LevelXDP {
		t.Fatalf("reattach events %+v (status %+v)", got, manager.Status())
	}
	if !signalled() || !capability.Ready() || mirrored != 1 {
		t.Fatalf("XDP_FILTER not restored: ready=%v mirrored=%d", capability.Ready(), mirrored)
	}
	watch.step(watch.retryAt.Add(xdpVerifyInterval))
	if got := drain(); len(got) != 0 || !manager.Running() {
		t.Fatalf("after reattach: %v %+v", got, manager.Status())
	}
	t.Logf("status %+v; interfaces %s", manager.Status(), strings.Join(manager.Status().Interfaces, ","))
}
