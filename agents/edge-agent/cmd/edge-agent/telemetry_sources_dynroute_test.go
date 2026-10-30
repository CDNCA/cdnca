package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

type countingSink struct{ events []eventspool.Envelope }

func (s *countingSink) AppendBatch(_ context.Context, events []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	results := make([]eventspool.AppendResult, len(events))
	for index, event := range events {
		s.events = append(s.events, event)
		results[index] = eventspool.AppendResult{EventID: event.EventID, Sequence: uint64(len(s.events))}
	}
	return results, nil
}

// D13-b2 交接 4 (D12 遗留 1): a dynamic routing node's runner tails the
// node-level shared logs, each line bound by the resolver (here a stub that
// names one site), with no active v7 release at all.
func TestTelemetrySourceRunnerTailsDynamicRoutingSharedLogs(t *testing.T) {
	root := telemetrySecureRoot(t)
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spoolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	spoolRoot, err := filepath.EvalSymlinks(spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(t.TempDir(), "telemetry")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if logs, err = filepath.EvalSymlinks(logs); err != nil {
		t.Fatal(err)
	}
	access, security := filepath.Join(logs, "access.jsonl"), filepath.Join(logs, "security.jsonl")
	line := map[string]any{
		"schema_version": 1, "type": "access.v1", "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
		"host": "www.example.test", "path": "/shared", "client_ip": "192.0.2.10",
		"method": "GET", "protocol": "HTTP/1.1", "cache_status": "MISS", "status_code": 200,
		"request_bytes": 10, "response_bytes": 20,
	}
	encoded, _ := json.Marshal(line)
	if err := os.WriteFile(access, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(security, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	identity := eventspool.TrustedIdentity{EnrollmentNodeID: telemetryTestNodeID, TenantID: telemetryTestTenantID,
		SiteID: telemetryTestSiteID, ConfigVersionID: "cfg-dyn", ListenPort: 80}
	resolved := 0
	sink := &countingSink{}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{
		DeploymentRoot: root, SpoolRoot: spoolRoot, EnrollmentNodeID: telemetryTestNodeID,
		PollInterval: time.Millisecond, MaxLineBytes: 64 << 10, MaxBatchEvents: 100, MaxQuarantineBytes: 1 << 20,
		DynamicRouting: &dynamicRoutingTelemetry{AccessLogPath: access, SecurityLogPath: security,
			Resolve: func(raw []byte) (eventspool.ResolvedLine, error) {
				resolved++
				return eventspool.ResolvedLine{Line: raw, Identity: identity}, nil
			}},
	}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resolved != 1 || len(sink.events) != 1 || sink.events[0].SiteID != telemetryTestSiteID || sink.events[0].ConfigVersionID != "cfg-dyn" {
		t.Fatalf("resolved %d events %+v", resolved, sink.events)
	}
	if err := runner.syncOnce(context.Background()); err != nil || len(sink.events) != 1 {
		t.Fatalf("second pass re-read: %d %v", len(sink.events), err)
	}
}
