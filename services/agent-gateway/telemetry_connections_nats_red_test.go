package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type connectionsJetStreamStub struct {
	mu              sync.Mutex
	messages        []*nats.Msg
	duplicateNext   bool
	conflictOnRetry bool
	err             error
	ack             *nats.PubAck
}

func (s *connectionsJetStreamStub) PublishMsg(message *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.conflictOnRetry && len(s.messages) > 0 {
		return nil, errors.New("wrong last subject sequence")
	}
	copyMessage := nats.NewMsg(message.Subject)
	copyMessage.Data = append([]byte(nil), message.Data...)
	copyMessage.Header = make(nats.Header, len(message.Header))
	for key, values := range message.Header {
		copyMessage.Header[key] = append([]string(nil), values...)
	}
	s.messages = append(s.messages, copyMessage)
	ack := &nats.PubAck{Stream: ConnectionsTelemetryIngestStream, Sequence: uint64(len(s.messages))}
	if s.ack != nil {
		copyAck := *s.ack
		ack = &copyAck
	}
	if s.duplicateNext {
		ack.Duplicate = true
		s.duplicateNext = false
	}
	return ack, nil
}

func (s *connectionsJetStreamStub) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) {
	return nil, errors.New("stream info is not part of this focused publisher fixture")
}

type telemetryReadinessJetStreamStub struct {
	stream string
	info   *nats.StreamInfo
	err    error
}

func (*telemetryReadinessJetStreamStub) PublishMsg(*nats.Msg, ...nats.PubOpt) (*nats.PubAck, error) {
	return nil, errors.New("publish is not part of this readiness fixture")
}

func (s *telemetryReadinessJetStreamStub) StreamInfo(stream string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	if s.err != nil {
		return nil, s.err
	}
	if stream != s.stream {
		return nil, errors.New("unexpected telemetry stream")
	}
	return s.info, nil
}

func exactTelemetryReadinessPublisher() (*NATSTelemetryPublisher, *telemetryReadinessJetStreamStub) {
	config := DefaultNATSTelemetryPublisherConfig()
	telemetry := &telemetryReadinessJetStreamStub{stream: config.Stream, info: &nats.StreamInfo{Config: nats.StreamConfig{
		Name: config.Stream, Subjects: []string{TelemetryIngestSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 10_000_000, MaxBytes: 10 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}}}
	coordination := &telemetryReadinessJetStreamStub{stream: config.CCCoordinationStream, info: &nats.StreamInfo{Config: nats.StreamConfig{
		Name: config.CCCoordinationStream, Subjects: []string{CCCoordinationSubjectPrefix + ".*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 2_000_000, MaxBytes: 2 << 30,
		Discard: nats.DiscardNew, MaxAge: 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}}}
	connections := &telemetryReadinessJetStreamStub{stream: config.ConnectionsStream, info: &nats.StreamInfo{Config: nats.StreamConfig{
		Name: config.ConnectionsStream, Subjects: []string{ConnectionsTelemetrySubjectPrefix + ".*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 1_000_000, MaxBytes: 2 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: 1, DiscardNewPerSubject: true,
		MaxMsgSize: 64 << 10, Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}}}
	l4 := &telemetryReadinessJetStreamStub{stream: config.L4Stream, info: &nats.StreamInfo{Config: nats.StreamConfig{
		Name: config.L4Stream, Subjects: []string{L4TelemetrySubjectPrefix + ".*.*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 5_000_000, MaxBytes: 5 << 30,
		Discard: nats.DiscardNew, MaxAge: 30 * 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: L4TelemetryMaxPayloadBytes,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}}}
	return &NATSTelemetryPublisher{
		js: telemetry, cccoordJS: coordination, connectionsJS: connections, l4JS: l4, config: config,
	}, connections
}

func TestNATSTelemetryPublisherCheckRequiresExactConnectionsStream(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*NATSTelemetryPublisher, *telemetryReadinessJetStreamStub)
	}{
		{name: "missing JetStream context", mutate: func(publisher *NATSTelemetryPublisher, _ *telemetryReadinessJetStreamStub) {
			publisher.connectionsJS = nil
		}},
		{name: "stream info error", mutate: func(_ *NATSTelemetryPublisher, connections *telemetryReadinessJetStreamStub) {
			connections.err = errors.New("stream info failed")
		}},
		{name: "stream config drift", mutate: func(_ *NATSTelemetryPublisher, connections *telemetryReadinessJetStreamStub) {
			connections.info.Config.Subjects = []string{ConnectionsTelemetrySubjectPrefix + ".>"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publisher, connections := exactTelemetryReadinessPublisher()
			test.mutate(publisher, connections)
			if err := publisher.Check(context.Background()); err == nil {
				t.Fatal("connections readiness failure was reported healthy")
			}
		})
	}
}

func TestNATSTelemetryPublisherCheckAcceptsFourExactStreams(t *testing.T) {
	publisher, _ := exactTelemetryReadinessPublisher()
	if err := publisher.Check(context.Background()); err != nil {
		t.Fatalf("four exact telemetry streams were rejected: %v", err)
	}
}

func TestNATSTelemetryConnectionsPublicationCarriesExactAuthority(t *testing.T) {
	envelope := validConnectionsTelemetryEnvelope()
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	receiptID := testConnectionsReceiptID(envelope)
	batchID := "conn_batch_" + uuid.NewString()
	config := DefaultNATSTelemetryPublisherConfig()
	stub := &connectionsJetStreamStub{}
	publisher := &NATSTelemetryPublisher{connectionsJS: stub, config: config}
	publication := TelemetryPublication{
		NodeID: testNodeID, TenantID: envelope.GetTenantId(), SiteID: envelope.GetSiteId(),
		InstallationID: envelope.GetInstallationId(), Domain: envelope.GetDomain(), ListenPort: envelope.GetListenPort(),
		BatchID: batchID, MessageID: receiptID, Payload: payload,
	}
	result, err := publisher.PublishConnections(context.Background(), publication)
	if err != nil || result.Stream != config.ConnectionsStream || result.Sequence != 1 || result.Duplicate {
		t.Fatalf("connections publication = %+v, err=%v", result, err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.messages) != 1 {
		t.Fatalf("published messages = %d, want 1", len(stub.messages))
	}
	message := stub.messages[0]
	payloadDigest := sha256.Sum256(payload)
	wantSubject := ConnectionsTelemetrySubjectPrefix + "." + envelope.GetInstallationId() + "." + receiptID
	if message.Subject != wantSubject || string(message.Data) != string(payload) ||
		message.Header.Get(nats.MsgIdHdr) != receiptID+":"+hex.EncodeToString(payloadDigest[:]) ||
		message.Header.Get(connectionsBatchHeader) != batchID ||
		message.Header.Get(connectionsSchemaHeader) != "1" ||
		message.Header.Get(connectionsReceiptHeader) != receiptID ||
		message.Header.Get(telemetryTenantHeader) != envelope.GetTenantId() ||
		message.Header.Get(telemetryNodeHeader) != envelope.GetNodeId() ||
		message.Header.Get(telemetryInstallationHeader) != envelope.GetInstallationId() ||
		message.Header.Get(telemetrySiteHeader) != envelope.GetSiteId() ||
		message.Header.Get(connectionsDomainHeader) != envelope.GetDomain() ||
		message.Header.Get(connectionsListenPortHeader) != "443" ||
		message.Header.Get(connectionsSubscriptionHeader) != envelope.GetPackageSubscriptionId() ||
		message.Header.Get(connectionsCanonicalDigestHeader) != hex.EncodeToString(envelope.GetCanonicalEventSha256()) ||
		message.Header.Get(connectionsEvidenceDigestHeader) != hex.EncodeToString(envelope.GetEvidenceSha256()) ||
		message.Header.Get(connectionsWatermarkHeader) != "7" ||
		message.Header.Get(connectionsFinalizedThroughHeader) != envelope.GetFinalizedThrough().AsTime().UTC().Format(time.RFC3339Nano) ||
		message.Header.Get(nats.ExpectedLastSubjSeqHdr) != "0" {
		t.Fatalf("connections message subject/data/headers = %s %q %#v", message.Subject, message.Data, message.Header)
	}
}

func TestNATSTelemetryConnectionsPublicationRejectsMissingListenerIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*agentv1.ConnectionsMetricEnvelopeV1)
	}{
		{name: "node", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.NodeId = "" }},
		{name: "domain", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.Domain = "" }},
		{name: "zero port", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.ListenPort = 0 }},
		{name: "overflow port", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.ListenPort = 65536 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := validConnectionsTelemetryEnvelope()
			test.mutate(envelope)
			payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			stub := &connectionsJetStreamStub{}
			publisher := &NATSTelemetryPublisher{connectionsJS: stub, config: DefaultNATSTelemetryPublisherConfig()}
			_, err = publisher.PublishConnections(context.Background(), TelemetryPublication{
				NodeID: envelope.GetNodeId(), TenantID: envelope.GetTenantId(), SiteID: envelope.GetSiteId(),
				InstallationID: envelope.GetInstallationId(), Domain: envelope.GetDomain(), ListenPort: envelope.GetListenPort(),
				BatchID: "conn_batch_" + uuid.NewString(), MessageID: testConnectionsReceiptID(envelope), Payload: payload,
			})
			if err == nil || len(stub.messages) != 0 {
				t.Fatalf("invalid listener identity was published: err=%v messages=%d", err, len(stub.messages))
			}
		})
	}
}

func TestNATSTelemetryConnectionsPublicationDeduplicatesAndFencesConflict(t *testing.T) {
	envelope := validConnectionsTelemetryEnvelope()
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	publication := TelemetryPublication{
		NodeID: testNodeID, TenantID: envelope.GetTenantId(), SiteID: envelope.GetSiteId(),
		InstallationID: envelope.GetInstallationId(), Domain: envelope.GetDomain(), ListenPort: envelope.GetListenPort(),
		BatchID:   "conn_batch_" + uuid.NewString(),
		MessageID: testConnectionsReceiptID(envelope), Payload: payload,
	}
	stub := &connectionsJetStreamStub{}
	publisher := &NATSTelemetryPublisher{connectionsJS: stub, config: DefaultNATSTelemetryPublisherConfig()}
	if _, err := publisher.PublishConnections(context.Background(), publication); err != nil {
		t.Fatal(err)
	}
	stub.duplicateNext = true
	stub.ack = &nats.PubAck{Stream: DefaultNATSTelemetryPublisherConfig().ConnectionsStream, Sequence: 1}
	duplicate, err := publisher.PublishConnections(context.Background(), publication)
	if err != nil || duplicate.Stream != DefaultNATSTelemetryPublisherConfig().ConnectionsStream ||
		duplicate.Sequence != 1 || !duplicate.Duplicate {
		t.Fatalf("same-digest duplicate = %+v, err=%v", duplicate, err)
	}

	conflictEnvelope := proto.Clone(envelope).(*agentv1.ConnectionsMetricEnvelopeV1)
	conflictEnvelope.Connections++
	conflictPayload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(conflictEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	conflict := publication
	conflict.Payload = conflictPayload
	stub.conflictOnRetry = true
	if _, err := publisher.PublishConnections(context.Background(), conflict); err == nil {
		t.Fatal("different payload digest was accepted for the same receipt subject")
	}
}

func TestNATSTelemetryConnectionsPublicationUnknownOutcomeFailsClosed(t *testing.T) {
	envelope := validConnectionsTelemetryEnvelope()
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	stub := &connectionsJetStreamStub{err: errors.New("publish timeout after server acceptance")}
	publisher := &NATSTelemetryPublisher{connectionsJS: stub, config: DefaultNATSTelemetryPublisherConfig()}
	_, err = publisher.PublishConnections(context.Background(), TelemetryPublication{
		NodeID: testNodeID, TenantID: envelope.GetTenantId(), SiteID: envelope.GetSiteId(),
		InstallationID: envelope.GetInstallationId(), Domain: envelope.GetDomain(), ListenPort: envelope.GetListenPort(),
		BatchID:   "conn_batch_" + uuid.NewString(),
		MessageID: testConnectionsReceiptID(envelope), Payload: payload,
	})
	if err == nil || strings.Contains(err.Error(), "server acceptance") {
		t.Fatalf("unknown outcome error = %v", err)
	}
}

func TestNATSTelemetryConnectionsPublicationRejectsInvalidPubAckProof(t *testing.T) {
	envelope := validConnectionsTelemetryEnvelope()
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	publication := TelemetryPublication{
		NodeID: testNodeID, TenantID: envelope.GetTenantId(), SiteID: envelope.GetSiteId(),
		InstallationID: envelope.GetInstallationId(), Domain: envelope.GetDomain(), ListenPort: envelope.GetListenPort(),
		BatchID:   "conn_batch_" + uuid.NewString(),
		MessageID: testConnectionsReceiptID(envelope), Payload: payload,
	}
	tests := []struct {
		name string
		ack  *nats.PubAck
	}{
		{name: "wrong stream", ack: &nats.PubAck{Stream: "OTHER_STREAM", Sequence: 1}},
		{name: "zero sequence", ack: &nats.PubAck{Stream: ConnectionsTelemetryIngestStream}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publisher := &NATSTelemetryPublisher{
				connectionsJS: &connectionsJetStreamStub{ack: test.ack},
				config:        DefaultNATSTelemetryPublisherConfig(),
			}
			result, err := publisher.PublishConnections(context.Background(), publication)
			if err == nil || result != (TelemetryPublishResult{}) || strings.Contains(err.Error(), test.ack.Stream) {
				t.Fatalf("invalid PubAck result = %+v, err=%v", result, err)
			}
		})
	}
}

func TestNATSTelemetryConnectionsStreamConfigIsIndependentAndExact(t *testing.T) {
	config := DefaultNATSTelemetryPublisherConfig()
	if config.Stream == config.ConnectionsStream || config.ConnectionsStream == "" ||
		ConnectionsTelemetrySubjectPrefix == TelemetryIngestSubjectPrefix {
		t.Fatalf("connections config is not independent: %+v", config)
	}
	valid := &nats.StreamInfo{Config: nats.StreamConfig{
		Name: config.ConnectionsStream, Subjects: []string{ConnectionsTelemetrySubjectPrefix + ".*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 1_000_000, MaxBytes: 2 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: 1, DiscardNewPerSubject: true,
		MaxMsgSize: 64 << 10, Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}}
	if !validConnectionsTelemetryStreamInfo(valid) {
		t.Fatal("authoritative connections stream was rejected")
	}
	mutated := *valid
	mutated.Config.Subjects = []string{ConnectionsTelemetrySubjectPrefix + ".>"}
	if validConnectionsTelemetryStreamInfo(&mutated) {
		t.Fatal("broad connections subject set was accepted")
	}
}
