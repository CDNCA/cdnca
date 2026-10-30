package gateway

import (
	"encoding/json"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FX65: a CC auto switch report is unversioned (config revision 0), carries
// no load metrics, occurs at its engage second and has a strict payload.
func TestCCAutoSwitchReportValidation(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	engaged := time.Unix(900, 0).UTC()
	report := testNodeMonitoringReport(t, nodeID, 41, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC)
	report.Kind = agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH
	report.ConfigRevision = 0
	report.LoadMetricsV1 = nil
	report.Event.OccurredTime = timestamppb.New(engaged)
	payload := map[string]any{"schema_version": 1, "node_id": nodeID,
		"tenant_scope_id": "01990000-0000-7000-8000-000000000101", "site_id": "01990000-0000-7000-8000-000000000102",
		"policy_id": "01990000-0000-7000-8000-000000000103", "policy_version": 4, "engaged_at": engaged,
		"trigger_qps": 1200, "trigger_5xx": 0, "qps_total": 1000, "qps_5xx": 0, "recover_seconds": 300}
	report.PayloadJson, _ = json.Marshal(payload)
	if err := validateNodeMonitoringReport(report, nodeID, 40, time.Unix(1000, 0)); err != nil {
		t.Fatalf("CC auto switch report: %v", err)
	}
	withPayload := func(key string, value any) func(*agentv1.NodeMonitoringReport) {
		return func(r *agentv1.NodeMonitoringReport) {
			changed := map[string]any{}
			for k, v := range payload {
				changed[k] = v
			}
			changed[key] = value
			r.PayloadJson, _ = json.Marshal(changed)
		}
	}
	for name, mutate := range map[string]func(*agentv1.NodeMonitoringReport){
		"fake revision": func(r *agentv1.NodeMonitoringReport) { r.ConfigRevision = 1 },
		"load metrics":  func(r *agentv1.NodeMonitoringReport) { r.LoadMetricsV1 = &agentv1.NodeLoadMetricsV1{} },
		"time mismatch": func(r *agentv1.NodeMonitoringReport) {
			r.Event.OccurredTime = timestamppb.New(engaged.Add(time.Second))
		},
		"other node":     withPayload("node_id", "01990000-0000-7000-8000-000000000008"),
		"bad site":       withPayload("site_id", "not-a-uuid"),
		"zero version":   withPayload("policy_version", 0),
		"unknown field":  withPayload("extra", true),
		"schema version": withPayload("schema_version", 2),
	} {
		t.Run(name, func(t *testing.T) {
			invalid := proto.Clone(report).(*agentv1.NodeMonitoringReport)
			mutate(invalid)
			if err := validateNodeMonitoringReport(invalid, nodeID, 40, time.Unix(1000, 0)); err == nil {
				t.Fatal("invalid CC auto switch report accepted")
			}
		})
	}
}
