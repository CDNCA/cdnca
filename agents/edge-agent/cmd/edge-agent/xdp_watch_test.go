package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
)

type fakeWatched struct {
	running             bool
	verifyErr           error
	reattachErr         error
	verifies, reattachs int
	sweeps              int
}

func (f *fakeWatched) Running() bool { return f.running }
func (f *fakeWatched) Verify() error {
	f.verifies++
	if f.verifyErr != nil {
		f.running = false
	}
	return f.verifyErr
}
func (f *fakeWatched) Sweep() (int, error) { f.sweeps++; return 0, nil }
func (f *fakeWatched) Status() xdp.Status {
	if f.running {
		return xdp.Status{Mode: xdp.ModeGeneric}
	}
	return xdp.Status{Mode: xdp.ModeNFTables, Reason: xdp.ReasonVerifyFailed}
}
func (f *fakeWatched) Reattach() error {
	f.reattachs++
	if f.reattachErr != nil {
		return f.reattachErr
	}
	f.running = true
	return nil
}

type recordedTransitions []string

func (r *recordedTransitions) XDPFallback(reason string) { *r = append(*r, "fallback:"+reason) }
func (r *recordedTransitions) XDPReattached(mode string) { *r = append(*r, "reattached:"+mode) }

// A run time fallback is retried with a growing backoff; a successful reattach re-mirrors the DDoS spec.
// The fallback and the reattach are each reported once (not per failed retry).
func TestXDPWatchRetriesAfterFallback(t *testing.T) {
	filter := &fakeWatched{running: true}
	mirrored := 0
	events := &recordedTransitions{}
	watch := newXDPWatch(filter, func() { mirrored++ }, events)
	now := time.Unix(1_800_000_000, 0)
	watch.step(now)
	if filter.verifies != 1 || filter.sweeps != 1 || filter.reattachs != 0 {
		t.Fatalf("healthy step: %+v", filter)
	}
	filter.verifyErr = errors.New("link detached")
	watch.step(now.Add(xdpVerifyInterval))
	if filter.running || filter.reattachs != 0 || !watch.fellBack {
		t.Fatalf("fallback step: %+v", filter)
	}
	filter.verifyErr, filter.reattachErr = nil, errors.New("attach_failed")
	at := now.Add(2 * xdpVerifyInterval)
	watch.step(at)
	if filter.reattachs != 1 || watch.backoff != 2*xdpVerifyInterval {
		t.Fatalf("first retry: %+v backoff %v", filter, watch.backoff)
	}
	watch.step(at.Add(xdpVerifyInterval)) // within backoff
	if filter.reattachs != 1 {
		t.Fatal("retried within the backoff")
	}
	for range 10 {
		at = watch.retryAt
		watch.step(at)
	}
	if watch.backoff != xdpRetryMax {
		t.Fatalf("backoff %v, want bound %v", watch.backoff, xdpRetryMax)
	}
	filter.reattachErr = nil
	watch.step(watch.retryAt)
	if !filter.running || watch.fellBack || mirrored != 1 {
		t.Fatalf("reattach: %+v fellBack %v mirrored %d", filter, watch.fellBack, mirrored)
	}
	if got := strings.Join(*events, ","); got != "fallback:verify_failed,reattached:generic" {
		t.Fatalf("transition events %q", got)
	}
	verifies := filter.verifies
	watch.step(watch.retryAt.Add(xdpVerifyInterval))
	if filter.verifies != verifies+1 || filter.sweeps < 2 {
		t.Fatalf("after reattach the watch verifies again: %+v", filter)
	}
}

// A filter disabled at start (Reattach ErrNoRetry) stays on nftables: the watch never attaches it.
func TestXDPWatchWithoutAttachStaysOnNFTables(t *testing.T) {
	manager := xdp.Probe(xdp.Options{Disabled: true})
	watch := newXDPWatch(manager, func() { t.Fatal("reattached a disabled filter") }, nil)
	for i := range 4 {
		watch.step(time.Unix(1_800_000_000+int64(i)*600, 0))
	}
	if manager.Running() || manager.Status().Mode != xdp.ModeDisabled {
		t.Fatalf("status %+v", manager.Status())
	}
}
