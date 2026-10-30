package gatewayclient

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostMetricsBridge(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	root := t.TempDir()
	bridge, err := NewNodeMonitoringBridge(root, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	report := nodemonitoring.MetricReport{SchemaVersion: 1, NodeID: nodeID, ObservedAt: now,
		LoadMetrics: &nodemonitoring.LoadMetrics{ObservedAt: now, CPUPercent: 1, MemoryTotalBytes: 2, MemoryUsedBytes: 1}}
	if err := bridge.ReportNodeMonitoring(t.Context(), report); err != nil {
		t.Fatal(err)
	}
	pending := bridge.Pending()
	if len(pending) != 1 || pending[0].Kind != agentv1.NodeMonitoringRecordKind(3) || pending[0].ConfigRevision != 0 ||
		bytes.Contains(pending[0].PayloadJson, []byte("healthy")) {
		t.Fatalf("host pending = %+v", pending)
	}
	restarted, err := NewNodeMonitoringBridge(root, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(restarted.Pending()[0], pending[0]) {
		t.Fatal("host report changed across restart")
	}
	ack := &agentv1.NodeMonitoringAck{EventId: pending[0].Event.EventId, NodeId: nodeID,
		PublicationSequence: pending[0].PublicationSequence, PublishedStream: nodeMonitoringStatusStream,
		PublishedSequence: 8, AcceptedTime: timestamppb.New(now)}
	if err := restarted.Acknowledge(ack); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Acknowledge(ack); err != nil {
		t.Fatal(err)
	}
	if len(restarted.Pending()) != 0 {
		t.Fatal("acknowledged host report retained")
	}
	report.Healthy = true
	if err := restarted.ReportNodeMonitoring(t.Context(), report); err == nil {
		t.Fatal("host report accepted fabricated probe health")
	}
	report.Healthy = false
	for range maxNodeMonitoringOutbox {
		if err := restarted.ReportNodeMonitoring(t.Context(), report); err != nil {
			t.Fatal(err)
		}
	}
	before := restarted.Pending()
	if err := restarted.ReportNodeMonitoring(t.Context(), report); !errors.Is(err, nodemonitoring.ErrMetricBackpressure) {
		t.Fatalf("full queue: %v", err)
	}
	after := restarted.Pending()
	if len(after) != maxNodeMonitoringOutbox || !proto.Equal(before[0], after[0]) || !proto.Equal(before[len(before)-1], after[len(after)-1]) {
		t.Fatal("full queue dropped or changed accepted evidence")
	}
	ack.EventId = before[0].Event.EventId
	ack.PublicationSequence = before[0].PublicationSequence
	ack.PublishedSequence++
	if err := restarted.Acknowledge(ack); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ReportNodeMonitoring(t.Context(), report); err != nil {
		t.Fatalf("queue did not resume after ACK: %v", err)
	}
}
