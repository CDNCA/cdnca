//go:build integration

package gateway

// ADR 0013 §5.4 / GW-11: two Gateway processes (here two gRPC servers in one
// test process, each with its own NATS connection and Redis coordinator)
// share one Redis and one NATS. A node moving from A to B loses no command,
// gets no command twice after its status was persisted, and the old session
// on A is fenced; the telemetry ACK cursor stays continuous (no regression,
// no duplicate storage, no gap). Needs CDNCA_TEST_NATS_URL (JetStream) and
// CDNCA_TEST_REDIS_ADDR.

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type multiGatewayFixture struct {
	pki      *testPKI
	node     ed25519Node
	js       nats.JetStreamContext
	prefix   string
	stream   string
	status   string
	consumer string
}

func (f multiGatewayFixture) startGateway(t *testing.T, name string, redisClient redis.UniversalClient, keyPrefix, natsURL string) string {
	t.Helper()
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close)
	busConfig := DefaultNATSCommandBusConfig()
	busConfig.CommandStream, busConfig.StatusStream = f.stream, f.status
	busConfig.CommandSubjectPrefix, busConfig.StatusSubjectPrefix = f.prefix+".commands", f.prefix+".status"
	busConfig.HeartbeatStream, busConfig.HeartbeatSubjectPrefix = f.status, f.prefix+".status.heartbeats"
	busConfig.ConsumerPrefix = f.consumer
	busConfig.AckWait = 500 * time.Millisecond
	busConfig.OperationTimeout = 2 * time.Second
	bus, err := NewNATSCommandBus(connection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	state := allowedAuthorization(time.Hour)
	state.deploymentsAllowed = true
	control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{state}}
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = name, "test"
	config.HeartbeatInterval, config.OfflineAfter = 200*time.Millisecond, 5*time.Second
	gateway, err := NewWithDurableMessaging(config, control, newIntegrationCoordinator(t, context.Background(), redisClient, name, keyPrefix), bus, bus)
	if err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(gateway, &tls.Config{Certificates: []tls.Certificate{f.pki.server}},
		&tls.Config{Certificates: []tls.Certificate{f.pki.server}, ClientCAs: f.pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(listener) }()
	t.Cleanup(servers.MTLS.Stop)
	return listener.Addr().String()
}

func (f multiGatewayFixture) publish(t *testing.T, command *agentv1.DeploymentCommand) {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.js.Publish(f.prefix+".commands."+testNodeID, payload, nats.MsgId(command.Event.EventId)); err != nil {
		t.Fatal(err)
	}
}

type nodeSession struct {
	stream   agentv1.AgentGatewayService_ConnectClient
	cancel   context.CancelFunc
	sequence uint64
}

func (f multiGatewayFixture) connect(t *testing.T, address string) *nodeSession {
	t.Helper()
	connection := dialGateway(t, address, f.pki.rootPool, f.node.certificate)
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(validHello(testNodeID, versionRange(1, 0), 1)); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || response.GetHello() == nil {
		t.Fatalf("hello from %s: %v %v", address, response, err)
	}
	return &nodeSession{stream: stream, cancel: cancel, sequence: 1}
}

// nextCommand skips heartbeat acknowledgements and other pushes.
func (s *nodeSession) nextCommand(t *testing.T) *agentv1.DeploymentCommand {
	t.Helper()
	type result struct {
		response *agentv1.ConnectResponse
		err      error
	}
	deadline := time.After(5 * time.Second)
	for {
		received := make(chan result, 1)
		go func() {
			response, err := s.stream.Recv()
			received <- result{response, err}
		}()
		select {
		case r := <-received:
			if r.err != nil {
				t.Fatalf("receive: %v", r.err)
			}
			if command := r.response.GetDeploymentCommand(); command != nil {
				return command
			}
		case <-deadline:
			t.Fatal("no deployment command")
		}
	}
}

func (s *nodeSession) sendStatus(t *testing.T, command *agentv1.DeploymentCommand) {
	t.Helper()
	s.sequence++
	if err := s.stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: s.sequence, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: validDeploymentStatus(command)},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTwoGatewaysShareRedisAndNATSWhileANodeMoves(t *testing.T) {
	natsURL, redisAddress := os.Getenv("CDNCA_TEST_NATS_URL"), os.Getenv("CDNCA_TEST_REDIS_ADDR")
	if natsURL == "" || redisAddress == "" {
		t.Skip("CDNCA_TEST_NATS_URL and CDNCA_TEST_REDIS_ADDR are required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	admin := connectIntegrationNATS(t, natsURL)
	defer admin.Close()
	js, err := admin.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	pki := newTestPKI(t)
	now := time.Now()
	f := multiGatewayFixture{pki: pki, node: pki.ed25519Node(t, 61, testNodeID, now.Add(-time.Hour), now.Add(time.Hour)), js: js,
		prefix: "cdnca.test." + suffix, stream: "AGENT_COMMANDS_" + suffix, status: "AGENT_STATUS_" + suffix, consumer: "node_" + suffix}
	for _, stream := range []*nats.StreamConfig{
		{Name: f.stream, Subjects: []string{f.prefix + ".commands.>"}, Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage},
		{Name: f.status, Subjects: []string{f.prefix + ".status.>"}, Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Duplicates: time.Minute},
	} {
		if _, err := js.AddStream(stream); err != nil {
			t.Fatal(err)
		}
		name := stream.Name
		defer func() { _ = js.DeleteStream(name) }()
	}
	redisClient := redis.NewClient(&redis.Options{Addr: redisAddress, DialTimeout: time.Second, ReadTimeout: time.Second,
		WriteTimeout: time.Second, MaxRetries: 0, ContextTimeoutEnabled: true})
	defer redisClient.Close()
	keyPrefix := "cdnca:agent-gateway:multi-test:" + suffix
	defer redisClient.Del(context.Background(), keyPrefix+":session:{"+testNodeID+"}:state", keyPrefix+":session:{"+testNodeID+"}:epoch")
	gatewayA := f.startGateway(t, "gateway-a-"+suffix, redisClient, keyPrefix, natsURL)
	gatewayB := f.startGateway(t, "gateway-b-"+suffix, redisClient, keyPrefix, natsURL)

	// 1. On A: first command delivered and completed (status persisted, acked).
	first, second := validDeploymentCommand(), validDeploymentCommand()
	f.publish(t, first)
	onA := f.connect(t, gatewayA)
	if got := onA.nextCommand(t); !proto.Equal(got, first) {
		t.Fatalf("A delivered %v", got)
	}
	onA.sendStatus(t, first)
	durable := f.consumer + "_" + strings.ReplaceAll(testNodeID, "-", "_")
	eventually(t, 5*time.Second, func() bool {
		info, err := js.ConsumerInfo(f.stream, durable)
		return err == nil && info.NumAckPending == 0 && info.NumPending == 0
	}, "first command not acknowledged on A")

	// 2. Second command reaches A but the node moves to B before reporting.
	f.publish(t, second)
	if got := onA.nextCommand(t); !proto.Equal(got, second) {
		t.Fatalf("A delivered %v", got)
	}
	onB := f.connect(t, gatewayB)
	// The old session on A is fenced: its stream ends as superseded.
	_, err = onA.stream.Recv()
	for err == nil {
		_, err = onA.stream.Recv()
	}
	if status.Code(err) != codes.Aborted {
		t.Fatalf("old session on A ended with %v, want Aborted (superseded)", err)
	}
	onA.cancel()

	// 3. B redelivers the unfinished command exactly; the finished one never.
	if got := onB.nextCommand(t); !proto.Equal(got, second) {
		t.Fatalf("B delivered %v, want the unfinished command", got)
	}
	onB.sendStatus(t, second)
	eventually(t, 5*time.Second, func() bool {
		info, err := js.ConsumerInfo(f.stream, durable)
		return err == nil && info.NumAckPending == 0 && info.NumPending == 0
	}, "second command not acknowledged on B")
	// Exactly one durable status per command crossed both Gateways.
	eventually(t, 5*time.Second, func() bool {
		info, err := js.StreamInfo(f.status, &nats.StreamInfoRequest{SubjectsFilter: f.prefix + ".status.>"})
		if err != nil {
			return false
		}
		statuses := uint64(0)
		for subject, count := range info.State.Subjects {
			if !strings.Contains(subject, ".heartbeats.") {
				statuses += count
			}
		}
		return statuses == 2
	}, "durable statuses are not exactly one per command")
	onB.cancel()
}

// startTelemetryGatewayOn serves StreamTelemetry with the shared Redis
// session coordinator (the fence) and its own NATS connection.
func startTelemetryGatewayOn(t *testing.T, pki *testPKI, name string, redisClient redis.UniversalClient, keyPrefix, natsURL string, config NATSTelemetryPublisherConfig) string {
	t.Helper()
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close)
	publisher, err := NewNATSTelemetryPublisher(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	control := &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}}
	service := newTelemetryGatewayWithCoordinator(t, control, publisher,
		newIntegrationCoordinator(t, context.Background(), redisClient, name, keyPrefix))
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(listener) }()
	t.Cleanup(servers.MTLS.Stop)
	return listener.Addr().String()
}

type telemetrySession struct {
	stream   grpc.BidiStreamingClient[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]
	sequence uint64
}

func openTelemetrySession(t *testing.T, pki *testPKI, certificate tls.Certificate, address string, lastAcknowledged uint64) *telemetrySession {
	t.Helper()
	connection := dialGateway(t, address, pki.rootPool, certificate)
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).StreamTelemetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(telemetryHelloRequest(lastAcknowledged, 1)); err != nil {
		t.Fatal(err)
	}
	if response, err := stream.Recv(); err != nil || response.GetHello() == nil {
		t.Fatalf("telemetry hello from %s: %v %v", address, response, err)
	}
	return &telemetrySession{stream: stream, sequence: 1}
}

func (s *telemetrySession) send(t *testing.T, batch *agentv1.TelemetryBatch) {
	t.Helper()
	s.sequence++
	if err := s.stream.Send(telemetryBatchRequest(batch, s.sequence)); err != nil {
		t.Fatal(err)
	}
}

func (s *telemetrySession) ack(t *testing.T) *agentv1.TelemetryAck {
	t.Helper()
	response, err := s.stream.Recv()
	if err != nil || response.GetAck() == nil {
		t.Fatalf("telemetry ACK=%v err=%v", response, err)
	}
	return response.GetAck()
}

// ADR 0013 §5.4 third item: the telemetry ACK cursor stays continuous while
// a node moves from Gateway A to B (shared Redis fence + shared JetStream
// dedup): it never goes back, a record durable on A but unacknowledged to the
// node is acknowledged on B as a duplicate (stored once), and a gap is refused
// (nothing silently skipped).
func TestTwoGatewaysKeepTheTelemetryAckCursorContinuousWhileANodeMoves(t *testing.T) {
	natsURL, redisAddress := os.Getenv("CDNCA_TEST_NATS_URL"), os.Getenv("CDNCA_TEST_REDIS_ADDR")
	if natsURL == "" || redisAddress == "" {
		t.Skip("CDNCA_TEST_NATS_URL and CDNCA_TEST_REDIS_ADDR are required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	admin := connectIntegrationNATS(t, natsURL)
	defer admin.Close()
	js, err := admin.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	streamName := "ANALYTICS_MULTI_GW_TEST_" + suffix
	if err := addAuthoritativeTelemetryTestStream(js, streamName); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(streamName) }()
	config := DefaultNATSTelemetryPublisherConfig()
	config.Stream, config.OperationTimeout = streamName, 2*time.Second
	redisClient := redis.NewClient(&redis.Options{Addr: redisAddress, DialTimeout: time.Second, ReadTimeout: time.Second,
		WriteTimeout: time.Second, MaxRetries: 0, ContextTimeoutEnabled: true})
	defer redisClient.Close()
	keyPrefix := "cdnca:agent-gateway:multi-telemetry-test:" + suffix
	defer redisClient.Del(context.Background(), keyPrefix+":session:{"+testNodeID+"}:state", keyPrefix+":session:{"+testNodeID+"}:epoch")
	pki := newTestPKI(t)
	certificate := pki.client(t, 73, nodeSPIFFEPrefix+testNodeID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	gatewayA := startTelemetryGatewayOn(t, pki, "gateway-a-"+suffix, redisClient, keyPrefix, natsURL, config)
	gatewayB := startTelemetryGatewayOn(t, pki, "gateway-b-"+suffix, redisClient, keyPrefix, natsURL, config)

	// 1. On A: 1..2 acknowledged; 3..4 become durable on A but the node moves
	// before it reads that ACK, so its durable cursor is still 2.
	onA := openTelemetrySession(t, pki, certificate, gatewayA, 0)
	onA.send(t, telemetryBatch(t, 1, 2))
	if ack := onA.ack(t); ack.AcceptedThroughSequence != 2 || ack.DuplicateRecordCount != 0 {
		t.Fatalf("A first ACK = %+v", ack)
	}
	inflight := telemetryBatch(t, 3, 4)
	onA.send(t, inflight)
	eventually(t, 5*time.Second, func() bool {
		info, err := js.StreamInfo(streamName)
		return err == nil && info.State.Msgs == 4
	}, "in-flight batch did not become durable on A")

	// 2. The node resumes on B from cursor 2; A's telemetry session is fenced.
	onB := openTelemetrySession(t, pki, certificate, gatewayB, 2)
	for {
		response, err := onA.stream.Recv()
		if err != nil {
			if status.Code(err) != codes.Aborted {
				t.Fatalf("old telemetry session on A ended with %v, want Aborted (superseded)", err)
			}
			break
		}
		if ack := response.GetAck(); ack != nil && ack.AcceptedThroughSequence != 4 {
			t.Fatalf("late ACK on A = %+v", ack)
		}
	}

	// 3. B continues at 3: the replayed records are duplicates (not stored
	// twice), the cursor advances to 4, then new records continue at 5.
	onB.send(t, inflight)
	if ack := onB.ack(t); ack.AcceptedThroughSequence != 4 || ack.DuplicateRecordCount != 2 || ack.AcceptedRecordCount != 2 {
		t.Fatalf("B replay ACK = %+v, want through 4 with 2 duplicates", ack)
	}
	onB.send(t, telemetryBatch(t, 5, 6))
	if ack := onB.ack(t); ack.AcceptedThroughSequence != 6 || ack.DuplicateRecordCount != 0 {
		t.Fatalf("B continuation ACK = %+v", ack)
	}
	if info, err := js.StreamInfo(streamName); err != nil || info.State.Msgs != 6 {
		t.Fatalf("stored telemetry = %+v err=%v, want exactly 6 records", info, err)
	}

	// 4. Neither going back nor skipping ahead is accepted on the new Gateway.
	refusedWithoutAck := func(session *telemetrySession, batch *agentv1.TelemetryBatch, label string) {
		session.send(t, batch)
		for {
			response, err := session.stream.Recv()
			if err != nil {
				return
			}
			if response.GetAck() != nil {
				t.Fatalf("%s was acknowledged: %+v", label, response.GetAck())
			}
		}
	}
	refusedWithoutAck(onB, telemetryBatch(t, 3, 3), "a batch behind cursor 6")
	refusedWithoutAck(openTelemetrySession(t, pki, certificate, gatewayB, 6), telemetryBatch(t, 8, 8), "a gap after cursor 6")
	if info, err := js.StreamInfo(streamName); err != nil || info.State.Msgs != 6 {
		t.Fatalf("stored telemetry after refused batches = %+v err=%v", info, err)
	}
}
