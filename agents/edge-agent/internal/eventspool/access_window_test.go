package eventspool

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type windowCapturePublisher struct{ records []Publication }

func (capture *windowCapturePublisher) Publish(_ context.Context, records []Publication) (PublishAck, error) {
	capture.records = append(capture.records, records...)
	return PublishAck{Acknowledged: len(records)}, nil
}

func TestAccessWindowSurvivesSpoolAndHasBoundedWireIdentity(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	end := spool.config.Now().UTC().Truncate(time.Hour)
	event := edgeconfig.AccessWindowEvent{MetricVersion: 1, WindowStart: end.Add(-time.Hour), WindowEnd: end, FinalizedThrough: end,
		TenantID: tenantOne, SiteID: siteOne, NodeID: nodeOne, ConfigVersionID: "77777777-7777-4777-8777-777777777777",
		Host: "example.test", ListenPort: 80, SourceWatermark: 1, DependencyState: "ready", EvidenceSHA256: strings.Repeat("ab", 32)}
	event.EventID = edgeconfig.AccessWindowEventID(event)
	record, err := NewAccessWindowRecord(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.AppendBatch(t.Context(), []Envelope{record}); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.AppendBatch(t.Context(), []Envelope{record}); err != nil {
		t.Fatal(err)
	}
	capture := &windowCapturePublisher{}
	result, err := spool.Flush(t.Context(), capture, 10)
	if err != nil || result.Published != 1 || len(capture.records) != 1 || !ValidAccessWindowPublication(capture.records[0]) {
		t.Fatalf("window publication rejected: %+v %v", result, err)
	}
	var envelope edgeconfig.AccessWindowEnvelope
	if err := json.Unmarshal(capture.records[0].Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Events[0].EventID != event.EventID || envelope.InstallationID != "" {
		t.Fatal("source replaced identity or asserted installation")
	}
}

func TestConnectionReplayStateRemainsBoundedDuringContinuousSampling(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	publisher := &connectionsScriptedPublisher{}
	for i := uint64(1); i <= 300; i++ {
		value := connectionsEnvelope(0, fmt.Sprintf("observed-%d", i), i)
		value.SchemaVersion = 2
		value.ConfigVersionId = "77777777-7777-4777-8777-777777777777"
		if _, err := spool.AppendConnections(t.Context(), value); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if _, err := spool.FlushConnections(t.Context(), publisher, 1); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}
	if watermark, err := spool.ConnectionsWatermark(t.Context()); err != nil || watermark != 300 {
		t.Fatalf("watermark=%d err=%v", watermark, err)
	}
	state, err := spool.loadConnectionsStateLocked()
	if err != nil || len(state.Identities) > 64 || len(state.Entries) != 0 {
		t.Fatalf("unbounded replay state: %v", err)
	}
}

func TestSourceProofDistinguishesEmptyFileFromMissingOrPartialSource(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	source := filepath.Join(root, "access.jsonl")
	state := filepath.Join(root, "tail-state")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := NewTailer(TailConfig{SourcePath: source, StateDir: state, Identity: TrustedIdentity{EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1"}, MaxLineBytes: 8192, MaxBatchEvents: 10, MaxQuarantineBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := tailer.CompleteSourceProof(t.Context()); err != nil || proof == ([32]byte{}) {
		t.Fatalf("empty source: %v", err)
	}
	if err := os.WriteFile(source, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tailer.CompleteSourceProof(t.Context()); err == nil {
		t.Fatal("partial source was certified empty")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if _, err := tailer.CompleteSourceProof(t.Context()); err == nil {
		t.Fatal("missing source was certified empty")
	}
}

func TestSourcePortComesFromSignedListener(t *testing.T) {
	event := sourceAccess(tenantOne)
	identity := TrustedIdentity{EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1", ListenPort: 80}
	parsed, err := ParseSourceLineBound(sourceLine(t, event), CapturePolicy{}, identity)
	if err != nil || parsed.ListenPort != 80 {
		t.Fatalf("bound port=%d err=%v", parsed.ListenPort, err)
	}
	event.ListenPort = 443
	if _, err := ParseSourceLineBound(sourceLine(t, event), CapturePolicy{}, identity); err == nil {
		t.Fatal("self-reported port override accepted")
	}
}
