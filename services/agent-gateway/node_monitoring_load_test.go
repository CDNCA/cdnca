package gateway

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateNodeMonitoringLoadMetricsSupportsOldAgentsAndFailsClosed(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	receipt := time.Unix(1000, 0).UTC()
	legacy := testNodeMonitoringReport(t, nodeID, 41, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC)
	if err := validateNodeMonitoringReport(legacy, nodeID, 0, receipt); err != nil {
		t.Fatalf("legacy unknown load rejected: %v", err)
	}
	valid := proto.Clone(legacy).(*agentv1.NodeMonitoringReport)
	valid.LoadMetricsV1 = &agentv1.NodeLoadMetricsV1{
		ObservedTime: timestamppb.New(time.Unix(900, 0).UTC()), CpuPercent: 25,
		MemoryUsedBytes: 512, MemoryTotalBytes: 1024, ActiveConnections: 8,
		RxBandwidthBps: 1600, TxBandwidthBps: 800,
	}
	if err := validateNodeMonitoringReport(valid, nodeID, 0, receipt); err != nil {
		t.Fatalf("valid load rejected: %v", err)
	}

	tests := map[string]func(*agentv1.NodeLoadMetricsV1){
		"nan cpu":        func(load *agentv1.NodeLoadMetricsV1) { load.CpuPercent = math.NaN() },
		"cpu over 100":   func(load *agentv1.NodeLoadMetricsV1) { load.CpuPercent = 101 },
		"zero memory":    func(load *agentv1.NodeLoadMetricsV1) { load.MemoryTotalBytes = 0 },
		"memory overrun": func(load *agentv1.NodeLoadMetricsV1) { load.MemoryUsedBytes = load.MemoryTotalBytes + 1 },
		"future": func(load *agentv1.NodeLoadMetricsV1) {
			load.ObservedTime = timestamppb.New(receipt.Add(31 * time.Second))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := proto.Clone(valid).(*agentv1.NodeMonitoringReport)
			mutate(candidate.LoadMetricsV1)
			if err := validateNodeMonitoringReport(candidate, nodeID, 0, receipt); err == nil {
				t.Fatal("invalid load accepted")
			}
		})
	}
	stale := proto.Clone(valid).(*agentv1.NodeMonitoringReport)
	staleTime := receipt.Add(-24 * time.Hour)
	stale.Event.OccurredTime = timestamppb.New(staleTime)
	stale.LoadMetricsV1.ObservedTime = timestamppb.New(staleTime)
	var stalePayload map[string]any
	if err := json.Unmarshal(stale.PayloadJson, &stalePayload); err != nil {
		t.Fatal(err)
	}
	stalePayload["observed_at"] = staleTime
	payload, err := json.Marshal(stalePayload)
	if err != nil {
		t.Fatal(err)
	}
	stale.PayloadJson = payload
	if err := validateNodeMonitoringReport(stale, nodeID, 0, receipt); err != nil {
		t.Fatalf("durable stale load rejected: %v", err)
	}
	recovery := testNodeMonitoringReport(t, nodeID, 42, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION)
	recovery.LoadMetricsV1 = proto.Clone(valid.LoadMetricsV1).(*agentv1.NodeLoadMetricsV1)
	if err := validateNodeMonitoringReport(recovery, nodeID, 41, receipt); err == nil {
		t.Fatal("load metrics attached to recovery record were accepted")
	}
}

func TestNodeMonitoringReplayDigestBindsTypedLoadMetrics(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	report := testNodeMonitoringReport(t, nodeID, 41, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC)
	report.LoadMetricsV1 = &agentv1.NodeLoadMetricsV1{
		ObservedTime: timestamppb.New(time.Unix(900, 0).UTC()), CpuPercent: 1,
		MemoryUsedBytes: 1, MemoryTotalBytes: 2,
	}
	ack := &agentv1.NodeMonitoringAck{EventId: report.Event.EventId, NodeId: nodeID,
		ConfigRevision: 7, PublicationSequence: 41, PublishedStream: NodeMonitoringStatusStream,
		PublishedSequence: 9, AcceptedTime: timestamppb.New(time.Unix(1000, 0).UTC())}
	records := make(map[string]nodeMonitoringAckRecord)
	if err := rememberNodeMonitoringAck(records, report, ack, 8); err != nil {
		t.Fatal(err)
	}
	conflict := proto.Clone(report).(*agentv1.NodeMonitoringReport)
	conflict.LoadMetricsV1.CpuPercent = 2
	if _, replayed, err := replayNodeMonitoringAck(records, conflict); err == nil || replayed {
		t.Fatalf("conflicting typed replay = (%v, %v)", replayed, err)
	}
}
