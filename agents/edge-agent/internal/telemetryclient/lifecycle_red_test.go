package telemetryclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/google/uuid"
)

type alwaysOfflineDialer struct {
	attempts atomic.Int32
}

func (d *alwaysOfflineDialer) Dial(context.Context) (Connection, error) {
	d.attempts.Add(1)
	return nil, errors.New("telemetry gateway offline")
}

func TestWorkerReportsDegradedWhileClientReconnectsOffline(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	spool, err := eventspool.New(eventspool.Config{
		Root: root, MaxEventBytes: 2048, MaxSegmentBytes: 4096,
		SoftLimitBytes: 32 << 10, HardLimitBytes: 64 << 10, MaxTenantBytes: 48 << 10,
		MaxBatchEvents: 10, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = spool.AppendBatch(context.Background(), []eventspool.Envelope{{
		SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventAccess,
		EventID: "evt-offline", OccurredAt: now, TenantID: testTenantID,
		SiteID: "018f47a2-5b9c-7d31-8a60-104c9c0b7181", NodeID: testNodeID,
		ConfigVersionID: testConfigID, Host: "example.test", Path: "/offline",
		ClientIP: "192.0.2.10", Method: "GET", Protocol: "HTTP/1.1",
		CacheStatus: "MISS", StatusCode: 200, ResponseBytes: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}

	dialer := &alwaysOfflineDialer{}
	clientConfig := DefaultConfig()
	clientConfig.NodeID = testNodeID
	clientConfig.BootID = uuid.NewString()
	clientConfig.Cursor = NewDurableCursor(spool)
	clientConfig.HandshakeTimeout = 10 * time.Millisecond
	clientConfig.AckTimeout = 10 * time.Millisecond
	clientConfig.InitialBackoff = time.Millisecond
	clientConfig.MaximumBackoff = 5 * time.Millisecond
	client, err := New(clientConfig, dialer)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	publisher, err := NewPublisher(testNodeID, client)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorker(WorkerConfig{
		MaximumEvents: 10, EmptyInterval: time.Millisecond,
		InitialBackoff: time.Millisecond, MaximumBackoff: 5 * time.Millisecond,
	}, spool, publisher)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for dialer.attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := worker.Snapshot()
	cancel()
	select {
	case runErr := <-done:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("worker shutdown error = %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after offline cancellation")
	}
	if dialer.attempts.Load() < 2 {
		t.Fatalf("client did not enter reconnect loop: attempts=%d", dialer.attempts.Load())
	}
	if !snapshot.Running || !snapshot.Degraded || snapshot.LastErrorCode != "TELEMETRY_UNAVAILABLE" {
		t.Fatalf("offline reconnect is invisible to worker health: %+v", snapshot)
	}
}

var _ Dialer = (*alwaysOfflineDialer)(nil)
