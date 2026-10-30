package nodemetrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testCCAutoSwitchPayload = `{"schema_version":1,"node_id":"01990000-0000-7000-8000-000000000007",` +
	`"tenant_scope_id":"01990000-0000-7000-8000-0000000000a1","site_id":"01990000-0000-7000-8000-0000000000b1",` +
	`"policy_id":"01990000-0000-7000-8000-0000000000c1","policy_version":3,"engaged_at":"1970-01-01T00:15:00Z",` +
	`"trigger_qps":1200,"trigger_5xx":4,"qps_total":1000,"qps_5xx":0,"recover_seconds":300}`

type testRecorder struct {
	samples []Sample
	err     error
}

func (recorder *testRecorder) RecordCCAutoSwitch(_ context.Context, sample Sample) error {
	recorder.samples = append(recorder.samples, sample)
	return recorder.err
}

func testCCAutoSwitchDelivery(t *testing.T, mutate func(*agentv1.NodeMonitoringReport)) *testDelivery {
	t.Helper()
	nodeID := "01990000-0000-7000-8000-000000000007"
	namespace := uuid.MustParse(nodeID)
	report := &agentv1.NodeMonitoringReport{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("cc-auto-switch/42")).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("request/42")).String(),
			OccurredTime: timestamppb.New(time.Unix(900, 0)),
		},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: nodeID, PublicationSequence: 42,
		Kind:        agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH,
		PayloadJson: []byte(testCCAutoSwitchPayload),
	}
	if mutate != nil {
		mutate(report)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return &testDelivery{subject: DefaultSubjectPrefix + "." + nodeID, payload: payload,
		meta: DeliveryMetadata{Stream: NodeMonitoringStatusStream, Durable: DefaultConsumerDurable,
			StreamSequence: 92, ConsumerSequence: 18, NumDelivered: 1}}
}

func TestDecoderDecodesCCAutoSwitchEngagement(t *testing.T) {
	sample, skip, err := NewDecoder(DefaultDecoderConfig()).Decode(testCCAutoSwitchDelivery(t, nil))
	event := sample.CCAutoSwitch
	if err != nil || skip || sample.Kind != RecordCCAutoSwitch || event == nil || sample.ConfigRevision != 0 ||
		sample.Known || sample.PubAckSequence != 92 || event.NodeID != sample.NodeID ||
		event.TenantScopeID != "01990000-0000-7000-8000-0000000000a1" || event.SiteID != "01990000-0000-7000-8000-0000000000b1" ||
		event.PolicyVersion != 3 || !event.EngagedAt.Equal(time.Unix(900, 0)) || !sample.ObservedAt.Equal(event.EngagedAt) ||
		event.TriggerQPS != 1200 || event.Trigger5xx != 4 || event.QPSTotal != 1000 || event.RecoverSeconds != 300 {
		t.Fatalf("Decode() = (%#v, %#v, %v, %v)", sample, event, skip, err)
	}
	for name, mutate := range map[string]func(*agentv1.NodeMonitoringReport){
		"config revision": func(report *agentv1.NodeMonitoringReport) { report.ConfigRevision = 7 },
		"load metrics": func(report *agentv1.NodeMonitoringReport) {
			report.LoadMetricsV1 = &agentv1.NodeLoadMetricsV1{ObservedTime: timestamppb.New(time.Unix(900, 0)), MemoryTotalBytes: 1}
		},
		"occurred mismatch": func(report *agentv1.NodeMonitoringReport) {
			report.Event.OccurredTime = timestamppb.New(time.Unix(901, 0))
		},
		"unknown field": func(report *agentv1.NodeMonitoringReport) {
			report.PayloadJson = []byte(strings.Replace(testCCAutoSwitchPayload, `"qps_5xx":0`, `"qps_5xx":0,"extra":1`, 1))
		},
		"foreign node": func(report *agentv1.NodeMonitoringReport) {
			report.PayloadJson = []byte(strings.Replace(testCCAutoSwitchPayload, "000000000007", "000000000008", 1))
		},
		"zero policy version": func(report *agentv1.NodeMonitoringReport) {
			report.PayloadJson = []byte(strings.Replace(testCCAutoSwitchPayload, `"policy_version":3`, `"policy_version":0`, 1))
		},
		"bad scope": func(report *agentv1.NodeMonitoringReport) {
			report.PayloadJson = []byte(strings.Replace(testCCAutoSwitchPayload, "0000000000a1", "0000000000A1", 1))
		},
		"trailing data": func(report *agentv1.NodeMonitoringReport) {
			report.PayloadJson = append([]byte(testCCAutoSwitchPayload), []byte(`{}`)...)
		},
	} {
		if _, _, err := NewDecoder(DefaultDecoderConfig()).Decode(testCCAutoSwitchDelivery(t, mutate)); !errors.Is(err, ErrInvalidSample) {
			t.Errorf("%s: Decode() error = %v", name, err)
		}
	}
}

func TestProcessorRoutesCCAutoSwitchToRecorderNotSamples(t *testing.T) {
	store, recorder := &testStore{}, &testRecorder{}
	processor, err := NewProcessor(NewDecoder(DefaultDecoderConfig()), store, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unrouted := testCCAutoSwitchDelivery(t, nil)
	if disposition, err := processor.Process(t.Context(), unrouted); err != nil || disposition != DispositionTerm ||
		unrouted.termed != 1 || len(store.samples) != 0 {
		t.Fatalf("Process(no recorder) = (%s, %v), delivery=%#v", disposition, err, unrouted)
	}
	processor.WithCCAutoSwitchRecorder(recorder)
	delivery := testCCAutoSwitchDelivery(t, nil)
	if disposition, err := processor.Process(t.Context(), delivery); err != nil || disposition != DispositionAck ||
		delivery.acked != 1 || len(recorder.samples) != 1 || len(store.samples) != 0 {
		t.Fatalf("Process(valid) = (%s, %v), delivery=%#v recorded=%d stored=%d", disposition, err, delivery,
			len(recorder.samples), len(store.samples))
	}
	recorder.err = errors.New("postgres unavailable")
	retry := testCCAutoSwitchDelivery(t, nil)
	if disposition, err := processor.Process(t.Context(), retry); err != nil || disposition != DispositionNak || retry.naked != 1 {
		t.Fatalf("Process(retry) = (%s, %v), delivery=%#v", disposition, err, retry)
	}
	recorder.err = ErrInvalidSample
	invalid := testCCAutoSwitchDelivery(t, nil)
	if disposition, err := processor.Process(t.Context(), invalid); err != nil || disposition != DispositionTerm || invalid.termed != 1 {
		t.Fatalf("Process(invalid) = (%s, %v), delivery=%#v", disposition, err, invalid)
	}
	// Metric samples still go to the store.
	metric := testMetricDelivery(t, true)
	if disposition, err := processor.Process(t.Context(), metric); err != nil || disposition != DispositionAck || len(store.samples) != 1 {
		t.Fatalf("Process(metric) = (%s, %v)", disposition, err)
	}
}
