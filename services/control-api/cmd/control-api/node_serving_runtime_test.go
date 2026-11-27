package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The deployment timeouts wait for the status replay (not yet wired, then
// not done) with no time limit; a long wait is logged, and the replay's end
// lets them run.
func TestDeploymentTimeoutGate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	var logs bytes.Buffer
	var replayDone func() bool
	gate := deploymentTimeoutGate(&replayDone, clock, 15*time.Minute, slog.New(slog.NewTextHandler(&logs, nil)))
	if gate() {
		t.Fatal("ready before the edge runtime opened")
	}
	done := false
	replayDone = func() bool { return done }
	if gate() || logs.Len() != 0 {
		t.Fatalf("ready or warned before the replay finished: %q", logs.String())
	}
	now = now.Add(16 * time.Minute) // e.g. NATS unreachable
	if gate() {
		t.Fatal("ready after 16 minutes without the replay")
	}
	if !strings.Contains(logs.String(), "deployment timeouts held by pending deployment status replay") {
		t.Fatalf("no warning after 16 minutes held: %q", logs.String())
	}
	now = now.Add(24 * time.Hour)
	if gate() {
		t.Fatal("ready a day later without the replay")
	}
	done = true
	if !gate() {
		t.Fatal("not ready after the replay finished")
	}
}
