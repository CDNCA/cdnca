package nodemetrics

import (
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

func TestNode07DecoderPreservesProbeEvidence(t *testing.T) {
	sample, skip, err := NewDecoder(DefaultDecoderConfig()).Decode(testMetricDelivery(t, true))
	if err != nil || skip {
		t.Fatalf("Decode(metric) = (%#v, %v, %v)", sample, skip, err)
	}
	if sample.Kind != RecordMetric || sample.ActiveConfigRevision != 7 || sample.ProbePort != 80 ||
		!sample.Healthy || !sample.ProbeSucceeded || sample.ConsecutiveFailures != 0 ||
		sample.ConsecutiveSuccesses != 0 || sample.ProbesTotal != 1 || sample.ProbeFailuresTotal != 0 ||
		sample.Recovered || sample.RecoveryNotified || sample.RolledBack || sample.RecoveryReasonCode != "" {
		t.Fatalf("probe evidence was not preserved: %#v", sample)
	}
}

func TestNode07RecoveryNotificationIsPersistedBeforeAck(t *testing.T) {
	delivery := testRecoveryDelivery(t)
	sample, skip, err := NewDecoder(DefaultDecoderConfig()).Decode(delivery)
	if err != nil || skip || sample.Kind != RecordRecoveryNotification ||
		sample.RecoveryReasonCode != RecoveryReasonProbeRecovered ||
		!sample.ObservedAt.Equal(time.Unix(910, 0).UTC()) {
		t.Fatalf("Decode(recovery) = (%#v, %v, %v)", sample, skip, err)
	}

	store := &testStore{}
	processor, err := NewProcessor(NewDecoder(DefaultDecoderConfig()), store, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := processor.Process(t.Context(), delivery)
	if err != nil || disposition != DispositionAck || delivery.acked != 1 || len(store.samples) != 1 ||
		store.samples[0].Kind != RecordRecoveryNotification {
		t.Fatalf("Process(recovery) = (%s, %v), delivery=%#v samples=%#v", disposition, err, delivery, store.samples)
	}
}

func TestNode07DecoderRejectsCountersOutsidePolicyBounds(t *testing.T) {
	delivery := testMetricDelivery(t, true)
	report := &agentv1.NodeMonitoringReport{}
	if err := proto.Unmarshal(delivery.payload, report); err != nil {
		t.Fatal(err)
	}
	report.PayloadJson = []byte(strings.Replace(
		string(report.PayloadJson), `"consecutive_successes":0`, `"consecutive_successes":21`, 1,
	))
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	delivery.payload = payload
	if _, _, err := NewDecoder(DefaultDecoderConfig()).Decode(delivery); !errors.Is(err, ErrInvalidSample) {
		t.Fatalf("out-of-policy counter error = %v", err)
	}
}

func testRecoveryDelivery(t *testing.T) *testDelivery {
	t.Helper()
	nodeID := "01990000-0000-7000-8000-000000000007"
	recoveredAt := time.Unix(910, 0).UTC()
	namespace := uuid.MustParse(nodeID)
	report := &agentv1.NodeMonitoringReport{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("recovery/42")).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("recovery-request/42")).String(),
			OccurredTime: timestamppb.New(recoveredAt),
		},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: nodeID,
		ConfigRevision: 7, PublicationSequence: 42,
		Kind:        agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION,
		PayloadJson: []byte(`{"node_id":"01990000-0000-7000-8000-000000000007","config_revision":7,"recovered_at":"1970-01-01T00:15:10Z"}`),
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return &testDelivery{
		subject: DefaultSubjectPrefix + "." + nodeID, payload: payload,
		meta: DeliveryMetadata{Stream: NodeMonitoringStatusStream, Durable: DefaultConsumerDurable,
			StreamSequence: 92, ConsumerSequence: 18, NumDelivered: 1},
	}
}
