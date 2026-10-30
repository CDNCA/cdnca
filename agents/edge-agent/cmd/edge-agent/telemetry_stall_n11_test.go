package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
)

// rejectingPublisher refuses the first `rejections` publications permanently
// (the gateway's INVALID_ARGUMENT for a config version its node
// authorization does not carry yet), then acknowledges everything.
type rejectingPublisher struct {
	mu         sync.Mutex
	rejections int
	calls      int
	events     map[string]int // publication subject kind ("access"/"security") -> events
}

func (p *rejectingPublisher) Publish(_ context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls <= p.rejections {
		return eventspool.PublishAck{}, telemetryclient.ErrPermanentProtocol
	}
	for _, publication := range publications {
		var envelope struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(publication.Payload, &envelope)
		p.events[strings.SplitN(envelope.Type, ".", 2)[0]] += publication.EventCount
	}
	return eventspool.PublishAck{Acknowledged: len(publications)}, nil
}

func (p *rejectingPublisher) counts() (int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.events["access"], p.events["security"]
}

// N11 (85/78 复测): the gateway refused the first batch, the worker ended on
// the permanent error, the pipeline cancelled the tail with it and the
// shared access log's offset stayed at the first batch for good, with
// nothing logged. Now: several batches written after a rejection all reach
// the spool and the publisher, the offsets of both the access and the
// security source keep moving, and the pipeline keeps running.
func TestTelemetryPipelineKeepsTailingAcrossBatchesAfterRejection(t *testing.T) {
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
	for _, path := range []string{access, security} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spool, err := eventspool.New(eventspool.Config{
		Root: spoolRoot, MaxEventBytes: 64 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 8 << 20, HardLimitBytes: 16 << 20, MaxTenantBytes: 12 << 20,
		MaxBatchEvents: 100, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := eventspool.TrustedIdentity{EnrollmentNodeID: telemetryTestNodeID, TenantID: telemetryTestTenantID,
		SiteID: telemetryTestSiteID, ConfigVersionID: "cfg-dyn", ListenPort: 80}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{
		DeploymentRoot: root, SpoolRoot: spoolRoot, EnrollmentNodeID: telemetryTestNodeID,
		PollInterval: time.Millisecond, MaxLineBytes: 64 << 10, MaxBatchEvents: 100, MaxQuarantineBytes: 1 << 20,
		DynamicRouting: &dynamicRoutingTelemetry{AccessLogPath: access, SecurityLogPath: security,
			Resolve: func(raw []byte) (eventspool.ResolvedLine, error) {
				return eventspool.ResolvedLine{Line: raw, Identity: identity}, nil
			}},
	}, spool)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &rejectingPublisher{rejections: 2, events: map[string]int{}}
	worker, err := telemetryclient.NewWorker(telemetryclient.WorkerConfig{
		MaximumEvents: 100, EmptyInterval: time.Millisecond,
		InitialBackoff: time.Millisecond, MaximumBackoff: 5 * time.Millisecond,
	}, spool, publisher)
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &telemetryPipeline{worker: worker, sources: runner, spool: spool}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(ctx) }()

	accessLine := func(path string) []byte {
		encoded, _ := json.Marshal(map[string]any{
			"schema_version": 1, "type": "access.v1", "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
			"host": "www.example.test", "path": path, "client_ip": "192.0.2.10",
			"method": "GET", "protocol": "HTTP/1.1", "cache_status": "MISS", "status_code": 200,
			"request_bytes": 10, "response_bytes": 20,
		})
		return append(encoded, '\n')
	}
	securityLine := func(path string) []byte {
		encoded, _ := json.Marshal(map[string]any{
			"schema_version": 1, "type": "security.v1", "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
			"host": "www.example.test", "path": path, "client_ip": "192.0.2.10", "method": "GET",
			"protocol": "http", "listen_port": 80, "request_class": "standard", "security_type": "waf",
			"action": "block", "severity": "high", "rule_id": "942100", "status_code": 403,
		})
		return append(encoded, '\n')
	}
	appendTo := func(path string, line []byte) {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := file.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	sharedTailer := func(path string) *eventspool.Tailer {
		for _, tailer := range runner.shared {
			if tailer.SourcePath() == path {
				return tailer
			}
		}
		t.Fatalf("no shared tailer for %s", path)
		return nil
	}
	accessTailer, securityTailer := sharedTailer(access), sharedTailer(security)
	size := func(path string) int64 {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Size()
	}
	waitFor := func(what string, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !condition() {
			select {
			case err := <-done:
				t.Fatalf("%s: telemetry pipeline stopped: %v", what, err)
			default:
			}
			if time.Now().After(deadline) {
				calls, accessEvents, securityEvents := publisher.counts()
				_, accessOffset := accessTailer.Position()
				_, securityOffset := securityTailer.Position()
				t.Fatalf("%s: publish calls %d, access %d (offset %d/%d), security %d (offset %d/%d)", what,
					calls, accessEvents, accessOffset, size(access), securityEvents, securityOffset, size(security))
			}
			time.Sleep(2 * time.Millisecond)
		}
	}

	const batches, perBatch = 4, 3
	for batch := 1; batch <= batches; batch++ {
		for line := 0; line < perBatch; line++ {
			appendTo(access, accessLine("/b"+string(rune('0'+batch))))
		}
		appendTo(security, securityLine("/s"+string(rune('0'+batch))))
		waitFor("batch tailed", func() bool {
			_, accessOffset := accessTailer.Position()
			_, securityOffset := securityTailer.Position()
			return accessOffset == size(access) && securityOffset == size(security)
		})
		if batch == 1 {
			// The first batch meets the rejections; the next ones are
			// written only after the worker was refused at least once.
			waitFor("gateway rejections", func() bool { calls, _, _ := publisher.counts(); return calls > publisher.rejections })
		}
	}
	waitFor("all batches published", func() bool {
		_, accessEvents, securityEvents := publisher.counts()
		return accessEvents == batches*perBatch && securityEvents == batches
	})
	if snapshot := pipeline.Snapshot(); !snapshot.Running || snapshot.Degraded {
		t.Fatalf("pipeline after recovery = %+v", snapshot)
	}
	cancel()
	if err := <-done; err == nil || ctx.Err() == nil {
		t.Fatalf("pipeline Run() = %v", err)
	}
}
