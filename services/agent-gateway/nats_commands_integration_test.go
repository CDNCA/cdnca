//go:build integration

package gateway

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestDurableGatewayLeavesSiteScopedOverlayBacklogWithoutConsumer(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	commandStream := "AGENT_COMMANDS_" + suffix
	commandPrefix := "cdnca.test." + suffix + ".commands"
	overlayPrefix := "cdnca.test." + suffix + ".overlay"

	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: commandStream, Subjects: []string{commandPrefix + ".>", overlayPrefix + ".>"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(commandStream) }()

	busConfig := DefaultNATSCommandBusConfig()
	busConfig.CommandStream = commandStream
	busConfig.StatusStream = "AGENT_STATUS_" + suffix
	busConfig.HeartbeatStream = "AGENT_HEARTBEATS_" + suffix
	busConfig.CommandSubjectPrefix = commandPrefix
	busConfig.OverlayCommandSubjectPrefix = overlayPrefix
	// 默认状态前缀 cdnca.agent.deployment-status 与 .acme-http01 子前缀重叠，NATS 2.11 拒绝在同一
	// 流里同时用 ">" 订阅二者；测试用独立的前缀，与命令流一致。
	busConfig.StatusSubjectPrefix = "cdnca.test." + suffix + ".status"
	busConfig.OverlayStatusSubjectPrefix = "cdnca.test." + suffix + ".overlay-status"
	busConfig.ConsumerPrefix = "node_" + suffix
	busConfig.OverlayConsumerPrefix = "node_overlay_" + suffix
	busConfig.OperationTimeout = time.Second
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: busConfig.StatusStream,
		Subjects: []string{
			busConfig.StatusSubjectPrefix + ".>",
			busConfig.OverlayStatusSubjectPrefix + ".>",
		},
		Retention: nats.LimitsPolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(busConfig.StatusStream) }()
	bus, err := NewNATSCommandBus(connection, busConfig)
	if err != nil {
		t.Fatal(err)
	}

	overlay := validOverlayCommand()
	overlayPayload, err := proto.MarshalOptions{Deterministic: true}.Marshal(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(
		overlayPrefix+"."+testNodeID, overlayPayload,
		nats.MsgId(overlay.Event.EventId), nats.ExpectStream(commandStream),
	); err != nil {
		t.Fatal(err)
	}

	serviceConfig := DefaultConfig()
	serviceConfig.GatewayInstanceID = "gateway-no-overlay-" + suffix
	serviceConfig.GatewayVersion = "test"
	service, err := NewWithDurableMessaging(
		serviceConfig, defaultFakeControl(), NewMemorySessionCoordinator(), bus, bus,
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewMemorySessionCoordinator().Acquire(t.Context(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 2)}
	received := make(chan connectReceive, 1)
	done := make(chan error, 1)
	go func() {
		done <- service.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, true,
		)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("durable Gateway session did not stop")
		}
	})

	ordinaryDurable := busConfig.ConsumerPrefix + "_" + strings.ReplaceAll(testNodeID, "-", "_")
	eventually(t, time.Second, func() bool {
		_, err := js.ConsumerInfo(commandStream, ordinaryDurable)
		return err == nil
	}, "ordinary durable consumer was not created")
	overlayDurable := busConfig.OverlayConsumerPrefix + "_" + strings.ReplaceAll(testNodeID, "-", "_")
	if _, err := js.ConsumerInfo(commandStream, overlayDurable); err == nil || !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatalf("site-scoped overlay consumer exists or lookup failed unexpectedly: %v", err)
	}
	select {
	case response := <-stream.sent:
		t.Fatalf("preloaded site-scoped overlay was delivered: %+v", response)
	case <-time.After(100 * time.Millisecond):
	}

	command := validDeploymentCommand()
	commandPayload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(
		commandPrefix+"."+testNodeID, commandPayload,
		nats.MsgId(command.Event.EventId), nats.ExpectStream(commandStream),
	); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-stream.sent:
		if response.GetDeploymentCommand() == nil || !proto.Equal(response.GetDeploymentCommand(), command) {
			t.Fatalf("ordinary durable response = %+v", response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary durable command was not delivered")
	}
	stored, err := js.GetMsg(commandStream, 1)
	if err != nil {
		t.Fatalf("read preloaded overlay backlog: %v", err)
	}
	if stored.Subject != overlayPrefix+"."+testNodeID {
		t.Fatalf("preloaded overlay backlog subject = %q", stored.Subject)
	}
}

func TestJetStreamCommandRedeliveryStatusDurabilityAndRedisFence(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	redisAddress := os.Getenv("CDNCA_TEST_REDIS_ADDR")
	if natsURL == "" || redisAddress == "" {
		t.Skip("CDNCA_TEST_NATS_URL and CDNCA_TEST_REDIS_ADDR are required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	commandStream := "AGENT_COMMANDS_" + suffix
	statusStream := "AGENT_STATUS_" + suffix
	commandPrefix := "cdnca.test." + suffix + ".commands"
	statusPrefix := "cdnca.test." + suffix + ".status"

	firstConnection := connectIntegrationNATS(t, natsURL)
	defer firstConnection.Close()
	secondConnection := connectIntegrationNATS(t, natsURL)
	defer secondConnection.Close()
	js, err := firstConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: commandStream, Subjects: []string{commandPrefix + ".>"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(commandStream) }()
	createStatusStream := func() {
		if _, err := js.AddStream(&nats.StreamConfig{
			Name: statusStream, Subjects: []string{statusPrefix + ".>"},
			Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Duplicates: time.Minute,
		}); err != nil {
			t.Fatal(err)
		}
	}
	createStatusStream()
	defer func() { _ = js.DeleteStream(statusStream) }()

	busConfig := DefaultNATSCommandBusConfig()
	busConfig.CommandStream = commandStream
	busConfig.StatusStream = statusStream
	busConfig.CommandSubjectPrefix = commandPrefix
	busConfig.StatusSubjectPrefix = statusPrefix
	busConfig.ConsumerPrefix = "node_" + suffix
	busConfig.AckWait = 250 * time.Millisecond
	busConfig.OperationTimeout = time.Second
	firstBus, err := NewNATSCommandBus(firstConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	secondBus, err := NewNATSCommandBus(secondConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}

	firstSubscription, err := firstBus.Subscribe(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	command := validRollbackDeploymentCommand()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(commandPrefix+"."+testNodeID, payload, nats.MsgId(command.Event.EventId)); err != nil {
		t.Fatal(err)
	}
	firstDelivery := nextIntegrationCommand(t, firstSubscription)

	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddress, DialTimeout: time.Second, ReadTimeout: time.Second,
		WriteTimeout: time.Second, MaxRetries: 0, ContextTimeoutEnabled: true,
	})
	defer redisClient.Close()
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	keyPrefix := "cdnca:agent-gateway:nats-test:" + suffix
	defer redisClient.Del(context.Background(), keyPrefix+":session:{"+testNodeID+"}:state", keyPrefix+":session:{"+testNodeID+"}:epoch")
	coordinatorOne := newIntegrationCoordinator(t, context.Background(), redisClient, "gateway-one-"+suffix, keyPrefix)
	coordinatorTwo := newIntegrationCoordinator(t, context.Background(), redisClient, "gateway-two-"+suffix, keyPrefix)
	oldLease, err := coordinatorOne.Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	newLease, err := coordinatorTwo.Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer newLease.Release()
	staleStream := &capturingBidiStream{ctx: context.Background(), sent: make(chan *agentv1.ConnectResponse, 1)}
	err = sendSessionResponse(oldLease, staleStream, &agentv1.ConnectResponse{
		Payload: &agentv1.ConnectResponse_DeploymentCommand{DeploymentCommand: firstDelivery.Command()},
	})
	if status.Code(err) != codes.Aborted || len(staleStream.sent) != 0 {
		t.Fatalf("stale gateway send = %v, sent=%d", status.Code(err), len(staleStream.sent))
	}
	if err := firstDelivery.Nak(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldLease.Release()
	if err := firstSubscription.Close(); err != nil {
		t.Fatal(err)
	}

	secondSubscription, err := secondBus.Subscribe(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	redelivered := nextIntegrationCommand(t, secondSubscription)
	if !proto.Equal(command, redelivered.Command()) {
		t.Fatalf("redelivered command changed: got=%+v want=%+v", redelivered.Command(), command)
	}
	if len(redelivered.Command().Artifacts) != 0 {
		t.Fatalf("redelivered rollback artifacts = %d, want 0", len(redelivered.Command().Artifacts))
	}

	if err := js.DeleteStream(statusStream); err != nil {
		t.Fatal(err)
	}
	statusUpdate := validDeploymentStatus(command)
	if _, err := secondBus.PublishStatus(context.Background(), testNodeID, statusUpdate); err == nil {
		t.Fatal("status publication succeeded without its durable stream")
	}
	if err := redelivered.Nak(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := secondSubscription.Close(); err != nil {
		t.Fatal(err)
	}
	createStatusStream()

	finalSubscription, err := secondBus.Subscribe(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer finalSubscription.Close()
	finalDelivery := nextIntegrationCommand(t, finalSubscription)
	if !proto.Equal(command, finalDelivery.Command()) {
		t.Fatal("command changed after status publication failure")
	}
	if _, err := secondBus.PublishStatus(context.Background(), testNodeID, statusUpdate); err != nil {
		t.Fatal(err)
	}
	if _, err := secondBus.PublishStatus(context.Background(), testNodeID, statusUpdate); err != nil {
		t.Fatal(err)
	}
	if err := finalDelivery.Ack(context.Background()); err != nil {
		t.Fatal(err)
	}

	eventually(t, time.Second, func() bool {
		info, err := js.StreamInfo(statusStream)
		return err == nil && info.State.Msgs == 1
	}, "duplicate status event was not deduplicated")
	durable := busConfig.ConsumerPrefix + "_" + strings.ReplaceAll(testNodeID, "-", "_")
	eventually(t, time.Second, func() bool {
		info, err := js.ConsumerInfo(commandStream, durable)
		return err == nil && info.NumAckPending == 0 && info.NumPending == 0
	}, "command consumer did not reach a fully acknowledged state")
}

func TestJetStreamSiteRuntimeV2CommandPreservesOuterScopeRoundTrip(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "AGENT_COMMANDS_" + suffix
	subjectPrefix := "cdnca.test." + suffix + ".commands"
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{subjectPrefix + ".>"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(streamName) }()
	config := DefaultNATSCommandBusConfig()
	config.CommandStream = streamName
	config.CommandSubjectPrefix = subjectPrefix
	config.ConsumerPrefix = "site_runtime_v2_" + suffix
	config.OperationTimeout = time.Second
	bus, err := NewNATSCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := bus.Subscribe(t.Context(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	command := validSiteObjectCommand(t)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(subjectPrefix+"."+testNodeID, payload, nats.MsgId(command.Event.EventId)); err != nil {
		t.Fatal(err)
	}
	delivery := nextIntegrationCommand(t, subscription)
	if !proto.Equal(delivery.Command(), command) {
		t.Fatalf("S2 command changed across JetStream: got=%+v want=%+v", delivery.Command(), command)
	}
	if err := delivery.Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func connectIntegrationNATS(t *testing.T, url string) *nats.Conn {
	t.Helper()
	connection, err := nats.Connect(url, nats.Name("cdnca-agent-gateway-integration"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func nextIntegrationCommand(t *testing.T, subscription CommandSubscription) CommandDelivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	delivery, err := subscription.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}
