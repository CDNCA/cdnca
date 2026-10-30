package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type nodeMonitoringBusStub struct {
	seen           map[string]NodeMonitoringPublication
	subscription   NodeMonitoringSubscription
	subscribeCalls int
}

func (bus *nodeMonitoringBusStub) PublishNodeMonitoring(_ context.Context, nodeID string, report *agentv1.NodeMonitoringReport) (NodeMonitoringPublication, error) {
	if previous, ok := bus.seen[report.Event.EventId]; ok {
		previous.Replayed = true
		return previous, nil
	}
	publication := NodeMonitoringPublication{Stream: NodeMonitoringStatusStream, Sequence: uint64(len(bus.seen) + 1)}
	bus.seen[report.Event.EventId] = publication
	return publication, nil
}

func (bus *nodeMonitoringBusStub) SubscribeNodeMonitoring(context.Context, string) (NodeMonitoringSubscription, error) {
	bus.subscribeCalls++
	return bus.subscription, nil
}

func TestPublishNodeMonitoringValidatesIdentitySequenceAndPubAck(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	bus := &nodeMonitoringBusStub{seen: make(map[string]NodeMonitoringPublication)}
	now := time.Unix(1000, 0).UTC()
	report := testNodeMonitoringReport(t, nodeID, 41, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC)
	ack, err := publishNodeMonitoringReport(t.Context(), bus, nodeID, report, 0, func() time.Time { return now })
	if err != nil {
		t.Fatalf("publishNodeMonitoringReport() error = %v", err)
	}
	if ack.NodeId != nodeID || ack.ConfigRevision != 7 || ack.PublicationSequence != 41 ||
		ack.PublishedStream != NodeMonitoringStatusStream || ack.PublishedSequence != 1 || ack.Replayed {
		t.Fatalf("ack = %#v", ack)
	}
	records := make(map[string]nodeMonitoringAckRecord)
	if err := rememberNodeMonitoringAck(records, report, ack, 8); err != nil {
		t.Fatal(err)
	}
	replayed, ok, err := replayNodeMonitoringAck(records, report)
	if err != nil || !ok || !proto.Equal(replayed, ack) {
		t.Fatalf("replayed original PubAck = (%#v, %v, %v), want %#v", replayed, ok, err, ack)
	}
	next := testNodeMonitoringReport(t, nodeID, 42, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION)
	if _, err := publishNodeMonitoringReport(t.Context(), bus, nodeID, next, 41, func() time.Time { return now }); err != nil {
		t.Fatalf("exact next publication sequence rejected: %v", err)
	}
	for _, sequence := range []uint64{44, 41} {
		if _, err := publishNodeMonitoringReport(t.Context(), bus, nodeID, testNodeMonitoringReport(t, nodeID, sequence,
			agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC), 42, func() time.Time { return now }); err == nil {
			t.Fatalf("invalid publication sequence %d was accepted after 42", sequence)
		}
	}
	wrongIdentity := testNodeMonitoringReport(t, "01990000-0000-7000-8000-000000000008", 43,
		agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC)
	if _, err := publishNodeMonitoringReport(t.Context(), bus, nodeID, wrongIdentity, 42, func() time.Time { return now }); err == nil {
		t.Fatal("report identity not bound to mTLS node was accepted")
	}
}

func TestRememberNodeMonitoringAckEvictsOldestWithinBound(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	records := make(map[string]nodeMonitoringAckRecord)
	reports := []*agentv1.NodeMonitoringReport{
		testNodeMonitoringReport(t, nodeID, 41, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC),
		testNodeMonitoringReport(t, nodeID, 42, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC),
		testNodeMonitoringReport(t, nodeID, 43, agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC),
	}
	acks := make([]*agentv1.NodeMonitoringAck, len(reports))
	for index, report := range reports {
		acks[index] = &agentv1.NodeMonitoringAck{
			EventId: report.Event.EventId, NodeId: nodeID, ConfigRevision: report.ConfigRevision,
			PublicationSequence: report.PublicationSequence, PublishedStream: NodeMonitoringStatusStream,
			PublishedSequence: uint64(index + 1), AcceptedTime: timestamppb.New(time.Unix(1000, int64(index)).UTC()),
		}
		if err := rememberNodeMonitoringAck(records, report, acks[index], 2); err != nil {
			t.Fatalf("remember sequence %d: %v", report.PublicationSequence, err)
		}
	}
	if len(records) != 2 {
		t.Fatalf("replay window size = %d, want 2", len(records))
	}
	if replayed, ok, err := replayNodeMonitoringAck(records, reports[0]); err != nil || ok || replayed != nil {
		t.Fatalf("evicted first replay = (%#v, %v, %v)", replayed, ok, err)
	}
	for index := 1; index < len(reports); index++ {
		replayed, ok, err := replayNodeMonitoringAck(records, reports[index])
		if err != nil || !ok || !proto.Equal(replayed, acks[index]) {
			t.Fatalf("retained replay %d = (%#v, %v, %v), want %#v", index, replayed, ok, err, acks[index])
		}
	}
	conflict := proto.Clone(reports[1]).(*agentv1.NodeMonitoringReport)
	conflict.PayloadJson = append(conflict.PayloadJson, ' ')
	if _, ok, err := replayNodeMonitoringAck(records, conflict); err == nil || ok {
		t.Fatalf("conflicting retained replay = (%v, %v), want conflict", ok, err)
	}
}

func testNodeMonitoringReport(t *testing.T, nodeID string, sequence uint64, kind agentv1.NodeMonitoringRecordKind) *agentv1.NodeMonitoringReport {
	t.Helper()
	observed := time.Unix(900, 0).UTC()
	value := any(map[string]any{
		"schema_version": 1, "observed_at": observed, "node_id": nodeID, "config_revision": 7,
		"active_config_revision": 7, "probe_port": 80, "healthy": true, "probe_succeeded": true,
		"consecutive_failures": 0, "consecutive_successes": 3, "probes_total": 10,
		"probe_failures_total": 1, "recovered": false, "recovery_notified": false, "rolled_back": false,
	})
	if kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION {
		value = map[string]any{"node_id": nodeID, "config_revision": 7, "recovered_at": observed}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	namespace := uuid.MustParse(nodeID)
	return &agentv1.NodeMonitoringReport{
		Event: &commonv1.EventMetadata{
			EventId:      uuid.NewSHA1(namespace, []byte("event/"+strconv.FormatUint(sequence, 10))).String(),
			RequestId:    uuid.NewSHA1(namespace, []byte("request/"+strconv.FormatUint(sequence, 10))).String(),
			OccurredTime: timestamppb.New(observed),
		},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: nodeID,
		ConfigRevision: 7, PublicationSequence: sequence, Kind: kind, PayloadJson: payload,
	}
}

func TestValidateNodeMonitoringArtifactBindsDigestAndIdentity(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	config := []byte(`{"schema_version":"cdnca.node-monitoring/v1","config_revision":7}`)
	digest := sha256.Sum256(config)
	artifact := &agentv1.NodeMonitoringArtifact{
		Event: testGatewayNodeMonitoringEvent(nodeID, "artifact"), Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1,
		NodeId: nodeID, ConfigRevision: 7, PublicationSequence: 7, CanonicalConfigJson: config, ConfigSha256: digest[:],
	}
	if err := validateNodeMonitoringArtifact(artifact, nodeID); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	corrupt := proto.Clone(artifact).(*agentv1.NodeMonitoringArtifact)
	corrupt.ConfigSha256[0] ^= 0xff
	if err := validateNodeMonitoringArtifact(corrupt, nodeID); err == nil {
		t.Fatal("artifact digest mismatch was accepted")
	}
}

type nodeMonitoringSubscriptionStub struct {
	closed int
}

func (*nodeMonitoringSubscriptionStub) Next(ctx context.Context) (NodeMonitoringDelivery, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (subscription *nodeMonitoringSubscriptionStub) Close() error {
	subscription.closed++
	return nil
}

type nodeMonitoringDeliveryStub struct {
	naks int
	err  error
}

func (*nodeMonitoringDeliveryStub) Artifact() *agentv1.NodeMonitoringArtifact { return nil }
func (*nodeMonitoringDeliveryStub) Ack(context.Context) error                 { return nil }
func (delivery *nodeMonitoringDeliveryStub) Nak(context.Context) error {
	delivery.naks++
	return delivery.err
}

func (delivery *nodeMonitoringDeliveryStub) NakWithDelay(context.Context, time.Duration) error {
	delivery.naks++
	return delivery.err
}

func TestNodeMonitoringRejectionDisposition(t *testing.T) {
	applied := agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_APPLIED
	rejected := agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_REJECTED
	for _, test := range []struct {
		state          agentv1.NodeMonitoringApplyState
		config, active uint64
		want           nodeMonitoringDisposition
	}{
		{applied, 5, 5, nodeMonitoringDispositionAck},
		// Superseded: the Agent already runs a newer revision and never goes back.
		{rejected, 5, 7, nodeMonitoringDispositionAck},
		// Preflight failure for the newest revision: retry later, keep the session.
		{rejected, 5, 4, nodeMonitoringDispositionRetryLater},
		{rejected, 5, 0, nodeMonitoringDispositionRetryLater},
		{rejected, 5, 5, nodeMonitoringDispositionRetryLater},
	} {
		status := &agentv1.NodeMonitoringApplyStatus{State: test.state, ConfigRevision: test.config, ActiveConfigRevision: test.active}
		if got := nodeMonitoringRejectionDisposition(status); got != test.want {
			t.Errorf("%v %d/%d: disposition %v, want %v", test.state, test.config, test.active, got, test.want)
		}
	}
}

func TestApplyNodeMonitoringAuthorizationRevokesPendingArtifact(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	subscription := &nodeMonitoringSubscriptionStub{}
	bus := &nodeMonitoringBusStub{seen: make(map[string]NodeMonitoringPublication), subscription: subscription}
	gateway := &Gateway{config: DefaultConfig(), nodeMonitoring: bus}
	source, pending, err := gateway.applyNodeMonitoringAuthorization(t.Context(), nodeID, nil, nil, false, true)
	if err != nil || source == nil || pending != nil || bus.subscribeCalls != 1 {
		t.Fatalf("authorize monitoring = (%#v, %#v, %v), subscribe calls = %d", source, pending, err, bus.subscribeCalls)
	}
	delivery := &nodeMonitoringDeliveryStub{}
	source, pending, err = gateway.applyNodeMonitoringAuthorization(t.Context(), nodeID, source, delivery, true, false)
	if err != nil || source != nil || pending != nil || delivery.naks != 1 || subscription.closed != 1 {
		t.Fatalf("revoke monitoring = (%#v, %#v, %v), naks = %d closes = %d", source, pending, err, delivery.naks, subscription.closed)
	}
}

func TestApplyNodeMonitoringAuthorizationRetainsPendingOnNakFailure(t *testing.T) {
	failure := errors.New("nak failed")
	bus := &nodeMonitoringBusStub{seen: make(map[string]NodeMonitoringPublication)}
	gateway := &Gateway{config: DefaultConfig(), nodeMonitoring: bus}
	delivery := &nodeMonitoringDeliveryStub{err: failure}
	source, pending, err := gateway.applyNodeMonitoringAuthorization(t.Context(),
		"01990000-0000-7000-8000-000000000007", nil, delivery, true, false)
	if source != nil || pending != delivery || err == nil || delivery.naks != 1 {
		t.Fatalf("failed revocation = (%#v, %#v, %v), naks = %d", source, pending, err, delivery.naks)
	}
}

func testGatewayNodeMonitoringEvent(nodeID, suffix string) *commonv1.EventMetadata {
	namespace := uuid.MustParse(nodeID)
	return &commonv1.EventMetadata{
		EventId:      uuid.NewSHA1(namespace, []byte("event/"+suffix)).String(),
		RequestId:    uuid.NewSHA1(namespace, []byte("request/"+suffix)).String(),
		OccurredTime: timestamppb.New(time.Unix(900, 0).UTC()),
	}
}
