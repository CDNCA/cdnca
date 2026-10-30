package nodemetrics

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testDelivery struct {
	subject string
	payload []byte
	meta    DeliveryMetadata
	acked   int
	naked   int
	termed  int
}

func (delivery *testDelivery) Subject() string                          { return delivery.subject }
func (delivery *testDelivery) Data() []byte                             { return delivery.payload }
func (delivery *testDelivery) Metadata() DeliveryMetadata               { return delivery.meta }
func (delivery *testDelivery) Ack(context.Context) error                { delivery.acked++; return nil }
func (delivery *testDelivery) Nak(context.Context, time.Duration) error { delivery.naked++; return nil }
func (delivery *testDelivery) Term(context.Context) error               { delivery.termed++; return nil }

type testStore struct {
	samples []Sample
	err     error
}

func (store *testStore) Put(_ context.Context, sample Sample) (bool, error) {
	store.samples = append(store.samples, sample)
	return false, store.err
}

func TestDecoderBindsTypedAndUnknownSamplesToJetStreamIdentity(t *testing.T) {
	decoder := NewDecoder(DefaultDecoderConfig())
	known := testMetricDelivery(t, true)
	sample, skip, err := decoder.Decode(known)
	if err != nil || skip || !sample.Known || sample.NodeID != "01990000-0000-7000-8000-000000000007" ||
		sample.ConfigRevision != 7 || sample.PublicationSequence != 41 || sample.CPUPercent != 25 ||
		sample.Telemetry == nil || len(sample.Telemetry.NetworkInterfaces) != 1 ||
		sample.Telemetry.NetworkInterfaces[0].Name != "eth0" || sample.Telemetry.SystemLoad == nil ||
		len(sample.Telemetry.Disks) != 1 || sample.Telemetry.TotalRXBytes != 300 || sample.Telemetry.TotalTXBytes != 600 ||
		sample.PubAckStream != NodeMonitoringStatusStream || sample.PubAckSequence != 91 ||
		sample.ConsumerDurable != DefaultConsumerDurable || sample.ConsumerSequence != 17 {
		t.Fatalf("known Decode() = (%#v, %v, %v)", sample, skip, err)
	}
	legacy := testMetricDelivery(t, false)
	unknown, skip, err := decoder.Decode(legacy)
	if err != nil || skip || unknown.Known || unknown.PubAckSequence != 91 {
		t.Fatalf("legacy Decode() = (%#v, %v, %v)", unknown, skip, err)
	}

	conflict := testMetricDelivery(t, true)
	conflict.meta.StreamSequence = 0
	if _, _, err := decoder.Decode(conflict); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("missing PubAck identity error = %v", err)
	}
	wrongSubject := testMetricDelivery(t, true)
	wrongSubject.subject = DefaultSubjectPrefix + ".01990000-0000-7000-8000-000000000008"
	if _, _, err := decoder.Decode(wrongSubject); !errors.Is(err, ErrInvalidSample) {
		t.Fatalf("mTLS subject mismatch error = %v", err)
	}
}

func TestProcessorPersistsBeforeAckAndSeparatesPermanentFromRetryableFailures(t *testing.T) {
	decoder := NewDecoder(DefaultDecoderConfig())
	store := &testStore{}
	processor, err := NewProcessor(decoder, store, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	delivery := testMetricDelivery(t, true)
	disposition, err := processor.Process(t.Context(), delivery)
	if err != nil || disposition != DispositionAck || delivery.acked != 1 || len(store.samples) != 1 {
		t.Fatalf("Process(valid) = (%s, %v), delivery=%#v samples=%d", disposition, err, delivery, len(store.samples))
	}

	store.err = errors.New("postgres unavailable")
	retry := testMetricDelivery(t, true)
	disposition, err = processor.Process(t.Context(), retry)
	if err != nil || disposition != DispositionNak || retry.naked != 1 || retry.acked != 0 {
		t.Fatalf("Process(retry) = (%s, %v), delivery=%#v", disposition, err, retry)
	}

	invalid := testMetricDelivery(t, true)
	invalid.payload = []byte("not protobuf")
	disposition, err = processor.Process(t.Context(), invalid)
	if err != nil || disposition != DispositionTerm || invalid.termed != 1 {
		t.Fatalf("Process(invalid) = (%s, %v), delivery=%#v", disposition, err, invalid)
	}
}

func testMetricDelivery(t *testing.T, known bool) *testDelivery {
	t.Helper()
	nodeID := "01990000-0000-7000-8000-000000000007"
	observed := time.Unix(900, 0).UTC()
	namespace := uuid.MustParse(nodeID)
	report := &agentv1.NodeMonitoringReport{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("metric/41")).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("request/41")).String(),
			OccurredTime: timestamppb.New(observed),
		},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: nodeID,
		ConfigRevision: 7, PublicationSequence: 41,
		Kind:        agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC,
		PayloadJson: []byte(`{"schema_version":1,"observed_at":"1970-01-01T00:15:00Z","node_id":"01990000-0000-7000-8000-000000000007","config_revision":7,"active_config_revision":7,"probe_port":80,"healthy":true,"probe_succeeded":true,"consecutive_failures":0,"consecutive_successes":0,"probes_total":1,"probe_failures_total":0,"recovered":false,"recovery_notified":false,"rolled_back":false}`),
	}
	if known {
		report.LoadMetricsV1 = &agentv1.NodeLoadMetricsV1{
			ObservedTime: timestamppb.New(observed), CpuPercent: 25, MemoryUsedBytes: 512,
			MemoryTotalBytes: 1024, ActiveConnections: 8, RxBandwidthBps: 1600, TxBandwidthBps: 800,
			Telemetry: &agentv1.NodeTelemetryV1{
				SchemaVersion: 1, TotalRxBytes: 300, TotalTxBytes: 600,
				NetworkInterfaces: []*agentv1.NodeNetworkInterfaceMetricsV1{{Name: "eth0", RxBytes: 300, TxBytes: 600,
					RxBandwidthBps: 1200, TxBandwidthBps: 2400}},
				SystemLoad: &agentv1.NodeSystemLoadV1{OneMinute: 1.25, FiveMinutes: 0.75, FifteenMinutes: 0.5,
					RunningProcesses: 3, TotalProcesses: 40},
				Disks: []*agentv1.NodeDiskUsageV1{{Path: "/", TotalBytes: 409600, UsedBytes: 307200,
					TotalInodes: 1000, UsedInodes: 750, SpacePercent: 75, InodePercent: 75}},
			},
		}
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return &testDelivery{
		subject: DefaultSubjectPrefix + "." + nodeID, payload: payload,
		meta: DeliveryMetadata{Stream: NodeMonitoringStatusStream, Durable: DefaultConsumerDurable,
			StreamSequence: 91, ConsumerSequence: 17, NumDelivered: 1},
	}
}
