package main

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

type sessionNotifiedStub struct {
	autoDefenseLocalStub
	sessions int
}

func (stub *sessionNotifiedStub) AutoDefenseSessionStarted() { stub.sessions++ }

// SEC-CONTROL-RECOVERY-01/R2: the gateway client's session start reaches the
// local runtime through the receiver and the CC stats wrapper (the runtime
// answers its settled single releases again).
func TestAutoDefenseSessionStartReachesTheRuntime(t *testing.T) {
	stub := &sessionNotifiedStub{}
	keys := newAutoDefenseKeys(t)
	receiver := newAutoDefenseReceiver(ccStatsNode, keys.trusted, stub, nil)
	if receiver == nil {
		t.Fatal("receiver not built")
	}
	wrapped := withCCStatsReports(receiver, newCCStats(ccStatsNode, func() time.Time { return time.Unix(1_900_000_000, 0) }))
	notifier, ok := wrapped.(gatewayclient.AutoDefenseSessionNotifier)
	if !ok {
		t.Fatal("the wrapped runtime is not told of a session start")
	}
	notifier.AutoDefenseSessionStarted()
	if stub.sessions != 1 {
		t.Fatalf("session starts reaching the runtime: %d", stub.sessions)
	}
}
