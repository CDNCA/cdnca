package telemetryclient

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// the first site's generation
// ran but its rollback failed, so its scope journal had no current release
// and ScopeForSite did not know the site. Every flush of the 22 queued access
// events failed as TELEMETRY_PUBLICATION_INVALID, a permanent error logged
// every 30 seconds. The records are valid: they must wait, unsent and
// unacknowledged, and go with their own sequence once the scope is known.

func attributionSpool(t *testing.T, events int) *eventspool.Spool {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Now().UTC().Truncate(time.Second)
	spool, err := eventspool.New(eventspool.Config{Root: filepath.Join(root, "spool"), MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
		SoftLimitBytes: 1 << 30, HardLimitBytes: 2 << 30, MaxTenantBytes: 1 << 30, MaxBatchEvents: 10000,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 168 * time.Hour,
		Now: func() time.Time { return now.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	batch := make([]eventspool.Envelope, 0, events)
	for i := 0; i < events; i++ {
		batch = append(batch, eventspool.Envelope{SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventAccess,
			EventID: fmt.Sprintf("evt-%d", i), OccurredAt: now, TenantID: trustTenant, SiteID: trustSite, NodeID: trustNode,
			ConfigVersionID: trustConfig, RequestID: fmt.Sprintf("r%d", i), Host: "site.example.test", Path: "/",
			ClientIP: "198.51.100.7", Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "MISS", StatusCode: 200, ResponseBytes: 512})
	}
	if _, err := spool.AppendBatch(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	return spool
}

// ackingGateway confirms scoped_records and acknowledges every batch.
func ackingGateway(t *testing.T) (Dialer, func() []*agentv1.TelemetryBatch, func()) {
	t.Helper()
	var mu sync.Mutex
	var batches []*agentv1.TelemetryBatch
	dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		hello := validGatewayHello(1, 64)
		hello.GetHello().ScopedRecords = true
		if err := stream.Send(hello); err != nil {
			return err
		}
		for sequence := uint64(2); ; sequence++ {
			request, err := stream.Recv()
			if err != nil {
				return err
			}
			batch := request.GetBatch()
			mu.Lock()
			batches = append(batches, batch)
			mu.Unlock()
			last := batch.Records[len(batch.Records)-1]
			if err := stream.Send(ackResponse(sequence, batch.BatchId, uint32(len(batch.Records)), 0, last)); err != nil {
				return err
			}
		}
	})
	return dialer, func() []*agentv1.TelemetryBatch {
		mu.Lock()
		defer mu.Unlock()
		return append([]*agentv1.TelemetryBatch(nil), batches...)
	}, cleanup
}

func TestUnconfirmedSiteScopeHoldsTheQueueUntilTheScopeIsConfirmed(t *testing.T) {
	const events = 22
	spool := attributionSpool(t, events)
	dialer, sent, cleanup := ackingGateway(t)
	defer cleanup()
	var confirmed atomic.Bool
	config := DefaultConfig()
	config.NodeID, config.BootID, config.Cursor = trustNode, uuid.NewString(), NewDurableCursor(spool)
	config.HandshakeTimeout, config.AckTimeout = time.Second, time.Second
	config.InitialBackoff, config.MaximumBackoff = time.Millisecond, 100*time.Millisecond
	config.ScopedRecords = true
	config.ScopeForSite = func(site string) (string, bool) { return trustScope, confirmed.Load() && site == trustSite }
	client, err := New(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(trustNode, client)
	if err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		result, err := spool.Flush(context.Background(), publisher, 1000)
		if code := safeWorkerError(err); code != "TELEMETRY_ATTRIBUTION_UNCONFIRMED" || permanentWorkerError(err) ||
			errors.Is(err, ErrInvalidPublication) {
			t.Fatalf("flush with the site's scope unconfirmed = (%+v, %v, code %s, permanent %v), want the transient TELEMETRY_ATTRIBUTION_UNCONFIRMED",
				result, err, code, permanentWorkerError(err))
		}
		if result.Published != 0 {
			t.Fatalf("held flush result = %+v, want nothing published", result)
		}
	}
	stats, err := spool.Stats()
	if err != nil || stats.AckedSequence != 0 || stats.PendingEvents != events {
		t.Fatalf("held queue = (%+v, %v), want all %d events pending, cursor 0", stats, err, events)
	}
	if got := sent(); len(got) != 0 {
		t.Fatalf("held queue sent %d batches, want none", len(got))
	}

	confirmed.Store(true)
	result, err := spool.Flush(context.Background(), publisher, 1000)
	if err != nil || result.Published != events {
		t.Fatalf("flush with the scope confirmed = (%+v, %v), want all %d events", result, err, events)
	}
	batches := sent()
	if len(batches) != 1 || batches[0].FirstSequence != 1 || batches[0].LastSequence != events {
		t.Fatalf("sent batches = %+v, want one batch of sequences 1..%d", batches, events)
	}
	for _, record := range batches[0].Records {
		if record.GetConfigurationScopeId() != trustScope {
			t.Fatalf("record scope = %q, want %q", record.GetConfigurationScopeId(), trustScope)
		}
	}
	if stats, err := spool.Stats(); err != nil || stats.AckedSequence != events || stats.PendingEvents != 0 {
		t.Fatalf("queue after the upload = (%+v, %v), want cursor %d", stats, err, events)
	}
}

// A held record after valid ones does not hold them back.
func TestScopedWireBatchSendsTheRecordsBeforeAnUnconfirmedSite(t *testing.T) {
	tenant, known, unknown, scope := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	limits := sessionLimits{maxRecords: 8, maxRecordBytes: 1 << 20, maxBatchBytes: 4 << 20, scoped: true, scopeForSite: siteScopes{known: scope}.lookup}
	records := []Record{
		scopedTestRecord(t, 1, "access.v1", tenant, known),
		scopedTestRecord(t, 2, "access.v1", tenant, unknown),
		scopedTestRecord(t, 3, "access.v1", tenant, known),
	}
	wire, err := buildWireBatch(records, limits)
	if err != nil || len(wire.Records) != 1 || wire.LastSequence != 1 {
		t.Fatalf("buildWireBatch() = (%+v, %v), want the first record only", wire, err)
	}
	if _, err := buildWireBatch(records[1:], limits); !errors.Is(err, ErrAttributionUnconfirmed) {
		t.Fatalf("batch headed by the unconfirmed site error = %v, want ErrAttributionUnconfirmed", err)
	}
}
