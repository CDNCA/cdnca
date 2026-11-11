package telemetryclient

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// a publication the event spool just encoded is turned into the
// same Record and wire batch without decoding its payload again; anything
// else is verified as before.

const (
	trustNode   = "44444444-4444-4444-8444-444444444444"
	trustTenant = "11111111-1111-4111-8111-111111111111"
	trustSite   = "33333333-3333-4333-8333-333333333333"
	trustConfig = "55555555-5555-4555-8555-555555555555"
	trustScope  = "66666666-6666-4666-8666-666666666666"
)

type capturePublisher struct{ publications []eventspool.Publication }

func (c *capturePublisher) Publish(_ context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	c.publications = append(c.publications, publications...)
	return eventspool.PublishAck{Acknowledged: len(publications)}, nil
}

func spoolPublications(t *testing.T) []eventspool.Publication {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Unix(1_700_000_000, 0).UTC()
	spool, err := eventspool.New(eventspool.Config{Root: filepath.Join(root, "spool"), MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
		SoftLimitBytes: 1 << 30, HardLimitBytes: 2 << 30, MaxTenantBytes: 1 << 30, MaxBatchEvents: 10000,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 168 * time.Hour,
		Now: func() time.Time { return now.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	var events []eventspool.Envelope
	for i := 0; i < 300; i++ {
		event := eventspool.Envelope{SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventAccess, EventID: fmt.Sprintf("evt-%d", i),
			OccurredAt: now, TenantID: trustTenant, SiteID: trustSite, NodeID: trustNode, ConfigVersionID: trustConfig,
			RequestID: fmt.Sprintf("r%d", i), Host: fmt.Sprintf("h%d.example.test", i%2), Path: "/a?<b>&c", ClientIP: "198.51.100.7",
			Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "MISS", StatusCode: 200, ResponseBytes: 1304,
			RequestHeaders: map[string]string{"User-Agent": "Mozilla/5.0 é"}}
		if i%3 == 0 {
			event.Type, event.SecurityType, event.Action, event.Severity = eventspool.EventSecurity, "waf", "log", "info"
			event.RequestClass, event.CacheStatus, event.Protocol, event.ListenPort, event.RuleID = "standard", "", "http", 80, "rule-1"
		}
		events = append(events, event)
	}
	if _, err := spool.AppendBatch(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	capture := &capturePublisher{}
	for {
		result, err := spool.Flush(context.Background(), capture, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if result.Published == 0 {
			return capture.publications
		}
	}
}

func scopedLimits() sessionLimits {
	return sessionLimits{maxRecords: 64, maxRecordBytes: 1 << 20, maxBatchBytes: 4 << 20, scoped: true,
		scopeForSite: func(site string) (string, bool) { return trustScope, site == trustSite }}
}

func TestPublisherTrustsOnlyTheSpoolsOwnPublications(t *testing.T) {
	publications := spoolPublications(t)
	if len(publications) < 4 {
		t.Fatalf("publications %d", len(publications))
	}
	publisher, err := NewPublisher(trustNode, &recordingSink{})
	if err != nil {
		t.Fatal(err)
	}
	events := 0
	for _, publication := range publications {
		fast, err := publisher.record(publication)
		if err != nil {
			t.Fatal(err)
		}
		copied := publication
		copied.Payload = append([]byte(nil), publication.Payload...)
		if _, ok := copied.Analytics(); ok {
			t.Fatal("a copied payload is trusted")
		}
		slow, err := publisher.record(copied)
		if err != nil {
			t.Fatal(err)
		}
		if fast.Kind != slow.Kind || fast.MessageID != slow.MessageID || fast.FirstSequence != slow.FirstSequence ||
			fast.LastSequence != slow.LastSequence || fast.LastEventID != slow.LastEventID || fast.EventCount != slow.EventCount ||
			string(fast.Payload) != string(slow.Payload) {
			t.Fatalf("record differs\n got %+v\nwant %+v", fast, slow)
		}
		fastWire, err := buildWireBatch([]Record{fast}, scopedLimits())
		if err != nil {
			t.Fatal(err)
		}
		slowWire, err := buildWireBatch([]Record{slow}, scopedLimits())
		if err != nil || !proto.Equal(fastWire, slowWire) {
			t.Fatalf("wire batch differs: %v", err)
		}
		edited := publication
		edited.MessageID = "msg_" + fmt.Sprintf("%064d", 0)
		if _, ok := edited.Analytics(); ok {
			t.Fatal("an edited publication is trusted")
		}
		if _, err := publisher.record(edited); err == nil {
			t.Fatal("edited message id accepted")
		}
		events += publication.EventCount
	}
	allocations := testing.AllocsPerRun(5, func() {
		for _, publication := range publications {
			record, err := publisher.record(publication)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildWireBatch([]Record{record}, scopedLimits()); err != nil {
				t.Fatal(err)
			}
		}
	}) / float64(events)
	t.Logf("publisher + wire batch %.1f allocations per event", allocations)
	if allocations > publishAllocationsPerEvent {
		t.Fatalf("publisher + wire batch %.1f allocations per event, want at most %d", allocations, publishAllocationsPerEvent)
	}
}

type recordingSink struct{}

func (recordingSink) Send(_ context.Context, batch Batch) (SendAck, error) {
	return SendAck{Accepted: len(batch.Records)}, nil
}

// 549.6 per event before this change (the payload decoded again for the
// record, its message id, the package subscription and the scope), 33.6 after.
const publishAllocationsPerEvent = 120
