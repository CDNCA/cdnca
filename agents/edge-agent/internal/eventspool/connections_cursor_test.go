package eventspool

import (
	"errors"
	"testing"
)

func TestConnectionsCursorTracksDurableAckNotSourceWatermark(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)
	check := func(want uint64) {
		t.Helper()
		if got, err := spool.ConnectionsAcknowledgedSequence(t.Context()); err != nil || got != want {
			t.Fatalf("cursor=%d want=%d err=%v", got, want, err)
		}
	}
	check(0)
	for i, id := range []string{"cursor-first", "cursor-second"} {
		if _, err := spool.AppendConnections(t.Context(), connectionsEnvelope(1, id, uint64(100+i*20))); err != nil {
			t.Fatal(err)
		}
	}
	check(0)
	if _, err := spool.FlushConnections(t.Context(), &connectionsScriptedPublisher{ack: 1, err: errors.New("partial")}, 2); err == nil {
		t.Fatal("expected partial result")
	}
	spool = newTestSpool(t, config)
	check(1)
	if _, err := spool.FlushConnections(t.Context(), &connectionsScriptedPublisher{}, 2); err != nil {
		t.Fatal(err)
	}
	spool = newTestSpool(t, config)
	check(2)
	stats, err := spool.Stats()
	if err != nil || stats.AckedSequence != 0 {
		t.Fatalf("connections changed access cursor: %+v %v", stats, err)
	}
}
