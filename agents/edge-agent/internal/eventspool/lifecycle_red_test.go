package eventspool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFlushPartialAckSurvivesRestartAndReplaysOnlySuffix(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)
	access := pendingAccess("evt-access-before-restart", tenantOne)
	security := pendingAccess("evt-security-after-restart", tenantOne)
	security.Type = EventSecurity
	security.ListenPort, security.Protocol, security.RequestClass = 443, "https", "standard"
	security.CacheStatus = ""
	security.SecurityType, security.Action, security.Severity = "waf", "block", "high"
	if _, err := spool.AppendBatch(context.Background(), []Envelope{access, security}); err != nil {
		t.Fatal(err)
	}

	publisher := &scriptedPublisher{responses: []struct {
		ack int
		err error
	}{{ack: 1, err: errors.New("connection lost after durable prefix ack")}}}
	result, err := spool.Flush(context.Background(), publisher, 10)
	if err == nil || result.Published != 1 || result.LastSequence != 1 {
		t.Fatalf("partial flush = %#v, %v", result, err)
	}

	restarted := newTestSpool(t, config)
	pending, err := restarted.nextBatch(context.Background(), 10)
	if err != nil || len(pending) != 1 || pending[0].Sequence != 2 || pending[0].EventID != security.EventID {
		t.Fatalf("pending suffix after restart = %#v, %v", pending, err)
	}
	result, err = restarted.Flush(context.Background(), publisher, 10)
	if err != nil || result.Published != 1 || result.LastSequence != 2 {
		t.Fatalf("suffix flush after restart = %#v, %v", result, err)
	}
	stats, err := restarted.Stats()
	if err != nil || stats.AckedSequence != 2 || stats.PendingEvents != 0 {
		t.Fatalf("final stats = %#v, %v", stats, err)
	}
}

func TestTailerConfigSwitchUsesIsolatedSourceAndPreservesCrashReplay(t *testing.T) {
	source, spool, config := newTailHarness(t)
	config.CapturePolicy.RequestHeaders = []string{"X-Telemetry-Marker"}
	event := sourceAccess(tenantOne)
	event.RequestHeaders = map[string]string{"X-Telemetry-Marker": "kept-by-old-config"}
	appendSource(t, source, event, true)

	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tailer.TailOnce(context.Background(), &appendThenFailSink{spool: spool}); err == nil {
		t.Fatal("expected injected process death before checkpoint")
	}

	// Each signed config writes a distinct source. The old source retains its
	// immutable identity and capture policy until its checkpoint is drained.
	switchedSource := filepath.Join(filepath.Dir(source), "cfg-2-access.jsonl")
	if err := os.WriteFile(switchedSource, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	appendSource(t, switchedSource, event, true)
	switched := config
	switched.SourcePath = switchedSource
	switched.Identity.ConfigVersionID = "cfg-2"
	switched.CapturePolicy = CapturePolicy{}
	switchedTailer, err := NewTailer(switched)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := switchedTailer.TailOnce(context.Background(), spool); err != nil || result.AppendedEvents != 1 {
		t.Fatalf("new config source = %#v, %v", result, err)
	}

	restarted, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.TailOnce(context.Background(), spool)
	if err != nil {
		t.Fatalf("old config crash replay is unrecoverable: result=%#v err=%v", result, err)
	}
	if result.DuplicateEvents != 1 || result.AppendedEvents != 0 {
		t.Fatalf("config-switch replay = %#v; want one duplicate and no new event", result)
	}
}
