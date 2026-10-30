package nodemetrics

import (
	"encoding/json"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestHostMetricsDecoder(t *testing.T) {
	delivery := testMetricDelivery(t, true)
	report := &agentv1.NodeMonitoringReport{}
	if err := proto.Unmarshal(delivery.payload, report); err != nil {
		t.Fatal(err)
	}
	report.Kind = agentv1.NodeMonitoringRecordKind(3)
	report.ConfigRevision = 0
	report.PayloadJson, _ = json.Marshal(map[string]any{"schema_version": 1, "node_id": report.NodeId, "observed_at": time.Unix(900, 0).UTC()})
	delivery.payload, _ = proto.MarshalOptions{Deterministic: true}.Marshal(report)
	sample, skip, err := NewDecoder(DefaultDecoderConfig()).Decode(delivery)
	if err != nil || skip || sample.Kind != "host_metric" || !sample.Known || !validStoreSample(sample) ||
		sample.ConfigRevision != 0 || sample.ActiveConfigRevision != 0 || sample.ProbePort != 0 || sample.Healthy || sample.ProbesTotal != 0 ||
		sample.Telemetry == nil || sample.Telemetry.NetworkInterfaces[0].Name != "eth0" {
		t.Fatalf("host decode = %+v, skip=%v, error=%v", sample, skip, err)
	}
	for name, mutate := range map[string]func(*agentv1.NodeMonitoringReport){
		"fake revision": func(r *agentv1.NodeMonitoringReport) { r.ConfigRevision = 7 },
		"missing load":  func(r *agentv1.NodeMonitoringReport) { r.LoadMetricsV1 = nil },
		"wrong node":    func(r *agentv1.NodeMonitoringReport) { r.NodeId = "01990000-0000-7000-8000-000000000008" },
		"probe evidence": func(r *agentv1.NodeMonitoringReport) {
			r.PayloadJson = append(r.PayloadJson[:len(r.PayloadJson)-1], []byte(`,"healthy":true}`)...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := proto.Clone(report).(*agentv1.NodeMonitoringReport)
			mutate(invalid)
			delivery.payload, _ = proto.MarshalOptions{Deterministic: true}.Marshal(invalid)
			if _, _, err := NewDecoder(DefaultDecoderConfig()).Decode(delivery); err == nil {
				t.Fatal("invalid host report accepted")
			}
		})
	}
}
