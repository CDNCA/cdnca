//go:build integration

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNATSTelemetryPublisherDurabilityDeduplicationAndRecovery(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ANALYTICS_INGEST_TEST_" + suffix
	nodeID := uuid.NewString()
	tenantID := uuid.NewString()
	siteID := uuid.NewString()
	configVersionID := uuid.NewString()
	installationID := "control-runtime-test-" + suffix
	subject := TelemetryIngestSubjectPrefix + "." + nodeID

	firstConnection := connectIntegrationNATS(t, natsURL)
	defer firstConnection.Close()
	secondConnection := connectIntegrationNATS(t, natsURL)
	defer secondConnection.Close()
	js, err := secondConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	createStream := func() {
		if err := addAuthoritativeTelemetryTestStream(js, streamName); err != nil {
			t.Fatal(err)
		}
	}
	createStream()
	defer func() { _ = js.DeleteStream(streamName) }()
	addTelemetryCompanionTestStreams(t, js)

	config := DefaultNATSTelemetryPublisherConfig()
	config.Stream = streamName
	config.OperationTimeout = time.Second
	firstPublisher, err := NewNATSTelemetryPublisher(firstConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	publication := TelemetryPublication{
		NodeID: nodeID, TenantID: tenantID, SiteID: siteID, ConfigVersionID: configVersionID, InstallationID: installationID,
		MessageID: "msg_" + suffix, Payload: []byte(`{"schema_version":1}`),
	}
	missingSite := publication
	missingSite.SiteID = ""
	if _, err := firstPublisher.Publish(context.Background(), missingSite); err == nil {
		t.Fatal("telemetry publication without authoritative site ID was accepted")
	}
	missingConfig := publication
	missingConfig.ConfigVersionID = ""
	if _, err := firstPublisher.Publish(context.Background(), missingConfig); err == nil {
		t.Fatal("telemetry publication without authoritative config version ID was accepted")
	}
	result, err := firstPublisher.Publish(context.Background(), publication)
	if err != nil || result.Duplicate {
		t.Fatalf("first PubAck = %+v, err=%v", result, err)
	}

	secondPublisher, err := NewNATSTelemetryPublisher(secondConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err = secondPublisher.Publish(context.Background(), publication)
	if err != nil || !result.Duplicate {
		t.Fatalf("cross-Gateway duplicate PubAck = %+v, err=%v", result, err)
	}
	info, err := js.StreamInfo(streamName)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("deduplicated stream state = %+v, err=%v", info, err)
	}
	stored, err := js.GetLastMsg(streamName, subject)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Header.Get(nats.MsgIdHdr) != publication.MessageID ||
		stored.Header.Get(telemetryNodeHeader) != nodeID || stored.Header.Get(telemetryTenantHeader) != tenantID ||
		stored.Header.Get(telemetrySiteHeader) != siteID || stored.Header.Get(telemetryConfigHeader) != configVersionID ||
		stored.Header.Get(telemetryInstallationHeader) != installationID || string(stored.Data) != string(publication.Payload) {
		t.Fatal("stored telemetry bytes or authoritative headers changed")
	}

	if err := js.DeleteStream(streamName); err != nil {
		t.Fatal(err)
	}
	publication.MessageID = "msg_recovery_" + suffix
	if _, err := firstPublisher.Publish(context.Background(), publication); err == nil {
		t.Fatal("telemetry publish succeeded without a durable stream")
	}
	if err := firstPublisher.Check(context.Background()); err == nil {
		t.Fatal("missing telemetry stream was reported healthy")
	}
	createStream()
	if _, err := secondPublisher.Publish(context.Background(), publication); err != nil {
		t.Fatalf("telemetry resume after stream recovery failed: %v", err)
	}
	if err := secondPublisher.Check(context.Background()); err != nil {
		t.Fatalf("recovered telemetry stream was not healthy: %v", err)
	}
}

func TestStreamTelemetryJetStreamRestartResume(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ANALYTICS_RPC_TEST_" + suffix
	firstConnection := connectIntegrationNATS(t, natsURL)
	defer firstConnection.Close()
	secondConnection := connectIntegrationNATS(t, natsURL)
	defer secondConnection.Close()
	js, err := secondConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	createStream := func() {
		if err := addAuthoritativeTelemetryTestStream(js, streamName); err != nil {
			t.Fatal(err)
		}
	}
	createStream()
	defer func() { _ = js.DeleteStream(streamName) }()
	config := DefaultNATSTelemetryPublisherConfig()
	config.Stream = streamName
	config.OperationTimeout = time.Second
	pki := newTestPKI(t)
	clientCertificate := pki.client(t, 72, nodeSPIFFEPrefix+testNodeID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	firstBatch := telemetryBatch(t, 1, 1)
	firstGateway := startTelemetryIntegrationGateway(t, pki, firstConnection, config)
	firstClientConnection := dialGateway(t, firstGateway.address, pki.rootPool, clientCertificate)
	firstStream, firstAck := sendTelemetryIntegrationBatch(t, firstClientConnection, 0, firstBatch)
	if firstAck.DuplicateRecordCount != 0 || firstAck.AcceptedThroughSequence != 1 {
		t.Fatalf("first Gateway durable ACK = %+v", firstAck)
	}
	firstGateway.stop()
	if _, err := firstStream.Recv(); err == nil {
		t.Fatal("stopped Gateway left the old telemetry stream able to ACK")
	}
	_ = firstClientConnection.Close()

	secondGateway := startTelemetryIntegrationGateway(t, pki, secondConnection, config)
	defer secondGateway.stop()
	secondClientConnection := dialGateway(t, secondGateway.address, pki.rootPool, clientCertificate)
	defer secondClientConnection.Close()
	duplicateStream, duplicateAck := sendTelemetryIntegrationBatch(t, secondClientConnection, 0, firstBatch)
	if duplicateAck.DuplicateRecordCount != 1 || duplicateAck.AcceptedThroughSequence != 1 {
		t.Fatalf("restarted Gateway duplicate ACK = %+v", duplicateAck)
	}
	if err := duplicateStream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	backlogBatch := telemetryBatch(t, 2, 2)
	continuedStream, continuedAck := sendTelemetryIntegrationBatch(t, secondClientConnection, 1, backlogBatch)
	if continuedAck.DuplicateRecordCount != 0 || continuedAck.AcceptedThroughSequence != 2 {
		t.Fatalf("restarted Gateway continuation ACK = %+v", continuedAck)
	}
	if err := continuedStream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	info, err := js.StreamInfo(streamName)
	if err != nil || info.State.Msgs != 2 {
		t.Fatalf("Gateway restart dedup state=%+v err=%v", info, err)
	}
	stored, err := js.GetLastMsg(streamName, TelemetryIngestSubjectPrefix+"."+testNodeID)
	if err != nil || stored.Header.Get(nats.MsgIdHdr) != backlogBatch.Records[0].MessageId ||
		stored.Header.Get(telemetryNodeHeader) != testNodeID || stored.Header.Get(telemetryTenantHeader) != testTelemetryTenantID ||
		stored.Header.Get(telemetrySiteHeader) != testTelemetrySiteID || stored.Header.Get(telemetryConfigHeader) != testTelemetryConfigVersionID ||
		stored.Header.Get(telemetryInstallationHeader) != testTelemetryInstallationID || string(stored.Data) != string(backlogBatch.Records[0].Payload) {
		t.Fatal("resumed backlog did not preserve the stable message identity and original payload")
	}
}

func TestStreamTelemetrySeparatesAuthorizedTuplesIntoNATSHeaders(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ANALYTICS_TUPLE_TEST_" + suffix
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := addAuthoritativeTelemetryTestStream(js, streamName); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(streamName) }()

	secondSiteID, secondConfigID := uuid.NewString(), uuid.NewString()
	control := &multiScopeTelemetryControl{fakeControl: defaultFakeControl(), scopes: []*controlv1.TelemetrySiteScope{
		{SiteId: testTelemetrySiteID, TenantId: testTelemetryTenantID, ConfigVersionId: testTelemetryConfigVersionID},
		{SiteId: secondSiteID, TenantId: testTelemetryTenantID, ConfigVersionId: secondConfigID},
	}}
	config := DefaultNATSTelemetryPublisherConfig()
	config.Stream = streamName
	config.OperationTimeout = time.Second
	pki := newTestPKI(t)
	clientCertificate := pki.client(t, 72, nodeSPIFFEPrefix+testNodeID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	gateway := startTelemetryIntegrationGatewayWithControl(t, pki, connection, config, control)
	defer gateway.stop()
	clientConnection := dialGateway(t, gateway.address, pki.rootPool, clientCertificate)
	defer clientConnection.Close()

	batch := telemetryBatch(t, 1, 2)
	secondRecord := batch.Records[1]
	var envelope telemetryAccessEnvelope
	if err := json.Unmarshal(secondRecord.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Events[0].SiteID = secondSiteID
	envelope.Events[0].ConfigVersion = secondConfigID
	envelope.MessageID = telemetryMessageID(testNodeID, testTelemetryTenantID, secondSiteID, secondConfigID,
		"access.v1", envelope.Events[0].EventID, envelope.Events[0].EventID)
	secondRecord.MessageId = envelope.MessageID
	secondRecord.Payload = marshalTelemetryEnvelope(t, envelope)
	batch.BatchId = telemetryBatchID(batch.Records)
	stream, ack := sendTelemetryIntegrationBatch(t, clientConnection, 0, batch)
	defer stream.CloseSend()
	if ack.AcceptedRecordCount != 2 || ack.DuplicateRecordCount != 0 || ack.AcceptedThroughSequence != 2 {
		t.Fatalf("two-tuple durable ACK = %+v", ack)
	}

	want := []struct{ siteID, configID, messageID string }{
		{testTelemetrySiteID, testTelemetryConfigVersionID, batch.Records[0].MessageId},
		{secondSiteID, secondConfigID, batch.Records[1].MessageId},
	}
	if want[0].messageID == want[1].messageID {
		t.Fatal("different authority tuples produced the same message ID")
	}
	for index, expected := range want {
		stored, err := js.GetMsg(streamName, uint64(index+1))
		if err != nil {
			t.Fatal(err)
		}
		if stored.Header.Get(nats.MsgIdHdr) != expected.messageID ||
			stored.Header.Get(telemetryNodeHeader) != testNodeID ||
			stored.Header.Get(telemetryTenantHeader) != testTelemetryTenantID ||
			stored.Header.Get(telemetrySiteHeader) != expected.siteID ||
			stored.Header.Get(telemetryConfigHeader) != expected.configID ||
			stored.Header.Get(telemetryInstallationHeader) != testTelemetryInstallationID {
			t.Fatalf("stored tuple %d headers = %#v", index, stored.Header)
		}
	}
}

func addAuthoritativeTelemetryTestStream(js nats.JetStreamContext, name string) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name: name, Subjects: []string{TelemetryIngestSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
		MaxConsumers: 1, MaxMsgs: 10_000_000, MaxBytes: 10 << 30, Discard: nats.DiscardNew,
		MaxAge: 0, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	})
	return err
}

func TestNATSTelemetryPublisherRejectsRealBehaviorChangingStreamConfig(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*nats.StreamConfig){
		"no publish ack": func(config *nats.StreamConfig) { config.NoAck = true },
		"sealed":         func(config *nats.StreamConfig) { config.Sealed = true },
		"rollup":         func(config *nats.StreamConfig) { config.AllowRollup = true },
		"message limit":  func(config *nats.StreamConfig) { config.MaxMsgs-- },
		"byte limit":     func(config *nats.StreamConfig) { config.MaxBytes-- },
		"deduplication":  func(config *nats.StreamConfig) { config.Duplicates-- },
		"discard new per subject": func(config *nats.StreamConfig) {
			config.DiscardNewPerSubject = true
			config.MaxMsgsPerSubject = 10
		},
	}
	addTelemetryCompanionTestStreams(t, js)
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			streamName := "ANALYTICS_READINESS_TEST_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if err := addAuthoritativeTelemetryTestStream(js, streamName); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = js.DeleteStream(streamName) }()
			config := DefaultNATSTelemetryPublisherConfig()
			config.Stream = streamName
			config.OperationTimeout = time.Second
			publisher, err := NewNATSTelemetryPublisher(connection, config)
			if err != nil {
				t.Fatal(err)
			}
			if err := publisher.Check(context.Background()); err != nil {
				t.Fatalf("exact real stream was rejected: %v", err)
			}
			info, err := js.StreamInfo(streamName)
			if err != nil {
				t.Fatal(err)
			}
			actual := info.Config
			mutate(&actual)
			if _, err := js.UpdateStream(&actual); err != nil {
				t.Fatalf("server rejected %s fixture: %v", name, err)
			}
			if err := publisher.Check(context.Background()); err == nil {
				t.Fatalf("behavior-changing real stream %q was reported healthy", name)
			}
		})
	}
}

type multiScopeTelemetryControl struct {
	*fakeControl
	scopes []*controlv1.TelemetrySiteScope
}

func (control *multiScopeTelemetryControl) GetNodeAuthorization(
	_ context.Context,
	request *controlv1.GetNodeAuthorizationRequest,
) (*controlv1.GetNodeAuthorizationResponse, error) {
	return &controlv1.GetNodeAuthorizationResponse{
		NodeId: request.NodeId, AdministrativeState: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE,
		ConnectionAllowed: true, AcceptedProtocolVersions: versionRange(1, 0),
		SnapshotExpirationTime: timestamppb.New(time.Now().Add(time.Hour)), ArtifactEncryptionKeyId: "artifact-key",
		InstallationId: testTelemetryInstallationID, TenantId: testTelemetryTenantID,
		TelemetrySiteScopes: control.scopes,
	}, nil
}

type telemetryIntegrationGateway struct {
	servers  *Servers
	listener net.Listener
	address  string
}

func startTelemetryIntegrationGateway(
	t *testing.T,
	pki *testPKI,
	connection *nats.Conn,
	config NATSTelemetryPublisherConfig,
) *telemetryIntegrationGateway {
	t.Helper()
	return startTelemetryIntegrationGatewayWithControl(t, pki, connection, config,
		&telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}})
}

func startTelemetryIntegrationGatewayWithControl(
	t *testing.T,
	pki *testPKI,
	connection *nats.Conn,
	config NATSTelemetryPublisherConfig,
	control ControlPlane,
) *telemetryIntegrationGateway {
	t.Helper()
	publisher, err := NewNATSTelemetryPublisher(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	service := newTelemetryGateway(t, control, publisher)
	servers, err := NewServers(service,
		&tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool},
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	running := &telemetryIntegrationGateway{servers: servers, listener: listener, address: listener.Addr().String()}
	go func() { _ = servers.MTLS.Serve(listener) }()
	return running
}

func (g *telemetryIntegrationGateway) stop() {
	if g == nil {
		return
	}
	g.servers.MTLS.Stop()
	g.servers.Enrollment.Stop()
	_ = g.listener.Close()
}

func sendTelemetryIntegrationBatch(
	t *testing.T,
	connection grpc.ClientConnInterface,
	lastAcknowledged uint64,
	batch *agentv1.TelemetryBatch,
) (grpc.BidiStreamingClient[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse], *agentv1.TelemetryAck) {
	t.Helper()
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).StreamTelemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(telemetryHelloRequest(lastAcknowledged, 1)); err != nil {
		t.Fatal(err)
	}
	if response, err := stream.Recv(); err != nil || response.GetHello() == nil {
		t.Fatalf("telemetry integration hello=%+v err=%v", response, err)
	}
	if err := stream.Send(telemetryBatchRequest(batch, 2)); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || response.GetAck() == nil {
		t.Fatalf("telemetry integration ACK=%+v err=%v", response, err)
	}
	return stream, response.GetAck()
}

// addTelemetryCompanionTestStreams creates the CC coordination, connections and
// L4 ingest streams that Check also requires (added after the telemetry stream
// fixture was written), with exactly the configuration production validates.
func addTelemetryCompanionTestStreams(t *testing.T, js nats.JetStreamContext) {
	t.Helper()
	for _, config := range []*nats.StreamConfig{
		{Name: CCCoordinationStream, Subjects: []string{CCCoordinationSubjectPrefix + ".*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 2_000_000, MaxBytes: 2 << 30,
			Discard: nats.DiscardNew, MaxAge: 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
			Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute},
		{Name: ConnectionsTelemetryIngestStream, Subjects: []string{ConnectionsTelemetrySubjectPrefix + ".*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 1_000_000, MaxBytes: 2 << 30,
			Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: 1, DiscardNewPerSubject: true,
			MaxMsgSize: 64 << 10, Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute},
		{Name: L4TelemetryIngestStream, Subjects: []string{L4TelemetrySubjectPrefix + ".*.*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 5_000_000, MaxBytes: 5 << 30,
			Discard: nats.DiscardNew, MaxAge: 30 * 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: L4TelemetryMaxPayloadBytes,
			Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute},
	} {
		if _, err := js.AddStream(config); err != nil {
			t.Fatalf("add %s: %v", config.Name, err)
		}
		name := config.Name
		t.Cleanup(func() { _ = js.DeleteStream(name) })
	}
}
