package gateway

import (
	"encoding/json"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostMetricsValidation(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	report := testNodeMonitoringReport(t, nodeID, 41, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC)
	report.Kind = agentv1.NodeMonitoringRecordKind(3)
	report.ConfigRevision = 0
	report.PayloadJson, _ = json.Marshal(map[string]any{"schema_version": 1, "node_id": nodeID, "observed_at": time.Unix(900, 0).UTC()})
	report.LoadMetricsV1 = &agentv1.NodeLoadMetricsV1{ObservedTime: timestamppb.New(time.Unix(900, 0)), CpuPercent: 1, MemoryTotalBytes: 2, MemoryUsedBytes: 1}
	if err := validateNodeMonitoringReport(report, nodeID, 40, time.Unix(1000, 0)); err != nil {
		t.Fatalf("host report: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.NodeMonitoringReport){
		"wrong node":    func(r *agentv1.NodeMonitoringReport) { r.NodeId = "01990000-0000-7000-8000-000000000008" },
		"fake revision": func(r *agentv1.NodeMonitoringReport) { r.ConfigRevision = 1 },
		"no load":       func(r *agentv1.NodeMonitoringReport) { r.LoadMetricsV1 = nil },
		"time mismatch": func(r *agentv1.NodeMonitoringReport) { r.Event.OccurredTime = timestamppb.New(time.Unix(901, 0)) },
		"sequence gap":  func(r *agentv1.NodeMonitoringReport) { r.PublicationSequence = 43 },
		"probe fields": func(r *agentv1.NodeMonitoringReport) {
			r.PayloadJson = append(r.PayloadJson[:len(r.PayloadJson)-1], []byte(`,"healthy":true}`)...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := proto.Clone(report).(*agentv1.NodeMonitoringReport)
			mutate(invalid)
			if err := validateNodeMonitoringReport(invalid, nodeID, 40, time.Unix(1000, 0)); err == nil {
				t.Fatal("invalid host report accepted")
			}
		})
	}
}
