//go:build integration

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNATSUpgradeCommandRedeliveryAckAndStatusWire(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ensureUpgradeIntegrationStreams(t, js)

	config := DefaultNATSCommandBusConfig()
	config.AckWait = 150 * time.Millisecond
	config.OperationTimeout = 500 * time.Millisecond
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	command := integrationUpgradeCommand(t)
	ensureUpgradeIntegrationConsumer(t, js, upgradeConsumerConfig(command.NodeID, config.AckWait,
		config.MaxWaiting, config.MaxAckPending, config.OperationTimeout))
	publishUpgradeIntegrationCommand(t, js, command, nil)

	first, err := bus.SubscribeUpgrade(t.Context(), command.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	trackSubscription := func(name string, subscription UpgradeCommandSubscription) func() {
		closed := false
		closeSubscription := func() {
			t.Helper()
			if closed {
				return
			}
			if err := subscription.Close(); err != nil {
				t.Fatalf("close %s subscription: %v", name, err)
			}
			closed = true
		}
		t.Cleanup(closeSubscription)
		return closeSubscription
	}
	closeFirst := trackSubscription("first", first)
	delivery := nextUpgradeIntegrationCommand(t, first)
	if delivery.Command().CommandID != command.CommandID || !bytes.Equal(delivery.Command().Encoded, command.Encoded) {
		t.Fatalf("first delivery = %#v", delivery.Command())
	}
	closeFirst()
	time.Sleep(2 * config.AckWait)

	second, err := bus.SubscribeUpgrade(t.Context(), command.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	closeSecond := trackSubscription("second", second)
	redelivered := nextUpgradeIntegrationCommand(t, second)
	if redelivered.Command().CommandID != command.CommandID || !bytes.Equal(redelivered.Command().Encoded, command.Encoded) {
		t.Fatalf("redelivery = %#v", redelivered.Command())
	}

	status := integrationUpgradeStatus(t, command)
	firstPublication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	duplicatePublication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if duplicatePublication != firstPublication {
		t.Fatalf("duplicate publication = %#v, want %#v", duplicatePublication, firstPublication)
	}
	stored, err := js.GetMsg(UpgradeStatusStream, firstPublication.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Subject != UpgradeStatusV2SubjectPrefix+"."+status.StatusID || !bytes.Equal(stored.Data, status.Encoded) ||
		stored.Sequence != firstPublication.Sequence ||
		!exactUpgradeHeaders(stored.Header, map[string]string{
			nats.MsgIdHdr: upgradeStatusV2MessageIDPrefix + status.StatusID, nats.ExpectedStreamHdr: UpgradeStatusStream,
			nats.ExpectedLastSubjSeqHdr: "0",
			UpgradePayloadSHA256Header:  hex.EncodeToString(status.SHA256[:]), UpgradeMessageKeyHeader: status.StatusID,
		}) {
		t.Fatalf("stored status wire = %#v", stored)
	}
	if err := redelivered.Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	closeSecond()

	third, err := bus.SubscribeUpgrade(t.Context(), command.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	trackSubscription("third", third)
	ctx, cancel := context.WithTimeout(context.Background(), 2*config.AckWait)
	defer cancel()
	if delivery, err := third.Next(ctx); err == nil || delivery != nil {
		t.Fatalf("acknowledged command redelivered: delivery=%v error=%v", delivery, err)
	}
}

func TestNATSUpgradeConsumerRejectsMismatchAndPostBindDrift(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ensureUpgradeIntegrationStreams(t, js)

	config := DefaultNATSCommandBusConfig()
	config.AckWait = time.Second
	config.OperationTimeout = time.Second
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	// A node that advertises EDGE_UPGRADE for the first time has no durable
	// yet: the Gateway creates exactly the expected one and accepts the
	// session, and a later session binds the same consumer idempotently.
	missingNodeID := uuid.NewString()
	missing := upgradeConsumerConfig(missingNodeID, config.AckWait, config.MaxWaiting, config.MaxAckPending, config.OperationTimeout)
	if _, err := js.ConsumerInfo(UpgradeCommandStream, missing.Durable); !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatalf("fixture consumer unexpectedly exists: %v", err)
	}
	t.Cleanup(func() {
		if err := js.DeleteConsumer(UpgradeCommandStream, missing.Durable); err != nil {
			t.Errorf("delete created upgrade consumer: %v", err)
		}
	})
	for attempt := range 2 {
		subscription, err := bus.SubscribeUpgrade(t.Context(), missingNodeID)
		if err != nil {
			t.Fatalf("subscribe %d with missing durable: %v", attempt, err)
		}
		if err := subscription.Close(); err != nil {
			t.Fatalf("close subscription %d: %v", attempt, err)
		}
		info, err := js.ConsumerInfo(UpgradeCommandStream, missing.Durable)
		if err != nil || !sameUpgradeConsumerConfig(info, missing) {
			t.Fatalf("created durable after subscribe %d = %+v, %v", attempt, info, err)
		}
	}
	mismatchNodeID := uuid.NewString()
	mismatch := *upgradeConsumerConfig(mismatchNodeID, config.AckWait, config.MaxWaiting, config.MaxAckPending, config.OperationTimeout)
	mismatch.MaxDeliver = 8
	if _, err := js.AddConsumer(UpgradeCommandStream, &mismatch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := js.DeleteConsumer(UpgradeCommandStream, mismatch.Durable); err != nil {
			t.Errorf("delete mismatched upgrade consumer: %v", err)
		}
	})
	if subscription, err := bus.SubscribeUpgrade(t.Context(), mismatchNodeID); err == nil {
		if closeErr := subscription.Close(); closeErr != nil {
			t.Fatalf("close unexpected mismatched-consumer subscription: %v", closeErr)
		}
		t.Fatal("behavior-changing durable mismatch was accepted")
	}
	// Creation never repairs an existing durable: the drifted config stays.
	if info, err := js.ConsumerInfo(UpgradeCommandStream, mismatch.Durable); err != nil || info.Config.MaxDeliver != 8 {
		t.Fatalf("mismatched durable was modified: %+v, %v", info, err)
	}

	driftNodeID := uuid.NewString()
	expected := upgradeConsumerConfig(driftNodeID, config.AckWait, config.MaxWaiting, config.MaxAckPending, config.OperationTimeout)
	ensureUpgradeIntegrationConsumer(t, js, expected)
	drifting := &upgradePostBindDriftJetStream{JetStreamContext: js, expected: expected}
	driftBus := &NATSUpgradeCommandBus{
		js: drifting, ackWait: config.AckWait, maxWaiting: config.MaxWaiting,
		maxAckPending: config.MaxAckPending, operationTimeout: config.OperationTimeout,
	}
	if subscription, err := driftBus.SubscribeUpgrade(t.Context(), driftNodeID); err == nil {
		if closeErr := subscription.Close(); closeErr != nil {
			t.Fatalf("close unexpected post-bind-drift subscription: %v", closeErr)
		}
		t.Fatal("post-bind durable drift was accepted")
	}
	if drifting.updateErr != nil {
		t.Fatalf("inject post-bind drift: %v", drifting.updateErr)
	}
	if drifting.subscription == nil || drifting.subscription.IsValid() {
		t.Fatal("post-bind drift did not unsubscribe the local pull subscription")
	}
}

// A freshly installed node advertises EDGE_UPGRADE before any per-node
// durable exists. Its session must be accepted (not codes.Unavailable, which
// would take the node offline) and receive commands published afterwards.
func TestGatewayUpgradeSessionCreatesMissingConsumerAndDelivers(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ensureUpgradeIntegrationStreams(t, js)
	config := DefaultNATSCommandBusConfig()
	config.AckWait = 150 * time.Millisecond
	config.OperationTimeout = 500 * time.Millisecond
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	command := integrationUpgradeCommand(t)
	durable := upgradeConsumerConfig(command.NodeID, config.AckWait, config.MaxWaiting, config.MaxAckPending, config.OperationTimeout).Durable
	if _, err := js.ConsumerInfo(UpgradeCommandStream, durable); !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatalf("fixture consumer unexpectedly exists: %v", err)
	}
	t.Cleanup(func() {
		if err := js.DeleteConsumer(UpgradeCommandStream, durable); err != nil {
			t.Errorf("delete created upgrade consumer: %v", err)
		}
	})
	gatewayConfig := DefaultConfig()
	gatewayConfig.GatewayInstanceID = "upgrade-integration-create"
	gatewayConfig.GatewayVersion = "test"
	gatewayConfig.CommandOperationTimeout = config.OperationTimeout
	service := &Gateway{config: gatewayConfig, upgrades: bus, now: time.Now}
	lease, err := NewMemorySessionCoordinator().Acquire(t.Context(), command.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	received := make(chan connectReceive, 2)
	done := make(chan error, 1)
	go func() {
		done <- service.serveSessionWithInstallation(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: command.NodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", command.InstallationID,
			time.Now().Add(time.Hour), true, false, false, false, false, true, true,
		)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("upgrade Gateway session did not stop")
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if info, err := js.ConsumerInfo(UpgradeCommandStream, durable); err == nil {
			if !sameUpgradeConsumerConfig(info, upgradeConsumerConfig(command.NodeID, config.AckWait,
				config.MaxWaiting, config.MaxAckPending, config.OperationTimeout)) {
				t.Fatalf("session created a different durable: %+v", info.Config)
			}
			break
		}
		select {
		case err := <-done:
			t.Fatalf("session with a missing upgrade consumer was rejected: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("session did not create the upgrade consumer")
		}
		time.Sleep(20 * time.Millisecond)
	}
	publishUpgradeIntegrationCommand(t, js, command, nil)
	select {
	case response := <-stream.sent:
		if response.GetUpgradeCommand() == nil {
			t.Fatalf("unexpected Gateway response: %+v", response)
		}
	case err := <-done:
		t.Fatalf("session ended before delivering: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("upgrade command was not delivered through the created consumer")
	}
}

func TestGatewayUpgradeCommandRedeliversAcrossSessionRestartUntilAcceptedStatus(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ensureUpgradeIntegrationStreams(t, js)
	config := DefaultNATSCommandBusConfig()
	config.AckWait = 150 * time.Millisecond
	config.OperationTimeout = 500 * time.Millisecond
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	command := integrationUpgradeCommand(t)
	ensureUpgradeIntegrationConsumer(t, js, upgradeConsumerConfig(command.NodeID, config.AckWait,
		config.MaxWaiting, config.MaxAckPending, config.OperationTimeout))
	publishUpgradeIntegrationCommand(t, js, command, nil)

	gatewayConfig := DefaultConfig()
	gatewayConfig.GatewayInstanceID = "upgrade-integration"
	gatewayConfig.GatewayVersion = "test"
	gatewayConfig.CommandOperationTimeout = config.OperationTimeout
	service := &Gateway{config: gatewayConfig, upgrades: bus, now: time.Now}
	coordinator := NewMemorySessionCoordinator()
	type runningSession struct {
		cancel   context.CancelFunc
		done     <-chan error
		stream   *capturingBidiStream
		received chan<- connectReceive
		lease    SessionLease
	}
	startSession := func() runningSession {
		t.Helper()
		lease, err := coordinator.Acquire(t.Context(), command.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
		received := make(chan connectReceive, 2)
		done := make(chan error, 1)
		go func() {
			done <- service.serveSessionWithInstallation(
				stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
				nodeIdentity{NodeID: command.NodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
				&commonv1.ProtocolVersion{Major: 1}, "artifact-key", command.InstallationID,
				time.Now().Add(time.Hour), true, false, false, false, false, true, true,
			)
		}()
		return runningSession{cancel: cancel, done: done, stream: stream, received: received, lease: lease}
	}
	stopSession := func(session runningSession) {
		t.Helper()
		session.cancel()
		select {
		case <-session.done:
		case <-time.After(2 * time.Second):
			t.Fatal("upgrade Gateway session did not stop")
		}
		session.lease.Release()
	}
	nextCommand := func(session runningSession) *agentv1.UpgradeCommand {
		t.Helper()
		select {
		case response := <-session.stream.sent:
			if response.GetUpgradeCommand() == nil {
				t.Fatalf("unexpected Gateway response: %+v", response)
			}
			return response.GetUpgradeCommand()
		case <-time.After(2 * time.Second):
			t.Fatal("upgrade command was not delivered")
			return nil
		}
	}

	first := startSession()
	if delivered := nextCommand(first); !bytes.Equal(delivered.Command, command.Encoded) || !bytes.Equal(delivered.CommandSha256, command.SHA256[:]) {
		t.Fatalf("first session command = %#v", delivered)
	}
	stopSession(first)

	second := startSession()
	if delivered := nextCommand(second); !bytes.Equal(delivered.Command, command.Encoded) || !bytes.Equal(delivered.CommandSha256, command.SHA256[:]) {
		t.Fatalf("restarted session command = %#v", delivered)
	}
	status := integrationUpgradeStatus(t, command)
	second.received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: 2},
		Payload: &agentv1.ConnectRequest_UpgradeStatus{UpgradeStatus: &agentv1.UpgradeStatus{
			Status: append([]byte(nil), status.Encoded...), StatusSha256: append([]byte(nil), status.SHA256[:]...),
		}},
	}}
	var publishedSequence uint64
	select {
	case response := <-second.stream.sent:
		ack := response.GetUpgradeStatusAck()
		if ack == nil || ack.StatusEventId != status.StatusID || ack.CommandId != command.CommandID ||
			ack.StatusRevision != status.StatusRevision || !bytes.Equal(ack.StatusSha256, status.SHA256[:]) ||
			ack.PublishedStream != UpgradeStatusStream || ack.PublishedSequence == 0 {
			t.Fatalf("upgrade status acknowledgement = %+v", response)
		}
		publishedSequence = ack.PublishedSequence
	case <-time.After(2 * time.Second):
		t.Fatal("accepted upgrade status was not acknowledged")
	}
	stopSession(second)

	durable := upgradeConsumerConfig(command.NodeID, config.AckWait, config.MaxWaiting, config.MaxAckPending, config.OperationTimeout).Durable
	eventually(t, 2*time.Second, func() bool {
		info, err := js.ConsumerInfo(UpgradeCommandStream, durable)
		return err == nil && info.NumAckPending == 0 && info.NumPending == 0
	}, "accepted upgrade command remained pending in JetStream")
	stored, err := js.GetLastMsg(UpgradeStatusStream, UpgradeStatusV2SubjectPrefix+"."+status.StatusID)
	if err != nil || !bytes.Equal(stored.Data, status.Encoded) || stored.Sequence != publishedSequence {
		t.Fatalf("stored accepted status = (%#v, %v)", stored, err)
	}

	third := startSession()
	select {
	case response := <-third.stream.sent:
		t.Fatalf("acknowledged upgrade command redelivered after restart: %+v", response)
	case <-time.After(2 * config.AckWait):
	}
	stopSession(third)
}

type upgradePostBindDriftJetStream struct {
	nats.JetStreamContext
	expected     *nats.ConsumerConfig
	subscription *nats.Subscription
	updateErr    error
	once         sync.Once
}

func (jetstream *upgradePostBindDriftJetStream) PullSubscribe(
	subject, durable string, options ...nats.SubOpt,
) (*nats.Subscription, error) {
	subscription, err := jetstream.JetStreamContext.PullSubscribe(subject, durable, options...)
	if err != nil {
		return nil, err
	}
	jetstream.subscription = subscription
	jetstream.once.Do(func() {
		drift := *jetstream.expected
		drift.Description = "deterministic post-bind drift"
		_, jetstream.updateErr = jetstream.JetStreamContext.UpdateConsumer(UpgradeCommandStream, &drift)
	})
	return subscription, nil
}

func ensureUpgradeIntegrationStreams(t *testing.T, js nats.JetStreamContext) {
	t.Helper()
	verifySubjects := func(config *nats.StreamConfig, info *nats.StreamInfo) {
		t.Helper()
		if info == nil || !slices.Equal(info.Config.Subjects, config.Subjects) {
			t.Fatalf("stream %s subjects=%v, want %v", config.Name, info.Config.Subjects, config.Subjects)
		}
	}
	ensure := func(config *nats.StreamConfig) {
		info, err := js.StreamInfo(config.Name)
		if err == nil {
			t.Fatalf("task-owned NATS already contains stream %s; refusing to mutate or reuse it", config.Name)
		} else if !errors.Is(err, nats.ErrStreamNotFound) {
			t.Fatal(err)
		}
		if _, err := js.AddStream(config); err != nil {
			t.Fatal(err)
		}
		info, err = js.StreamInfo(config.Name)
		if err != nil {
			t.Fatal(err)
		}
		verifySubjects(config, info)
		t.Cleanup(func() {
			if err := js.DeleteStream(config.Name); err != nil {
				t.Errorf("delete upgrade integration stream %s: %v", config.Name, err)
			}
		})
	}
	ensure(&nats.StreamConfig{
		Name: UpgradeCommandStream, Subjects: []string{UpgradeCommandSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	})
	ensure(&nats.StreamConfig{
		Name: UpgradeStatusStream, Subjects: []string{
			UpgradeStatusSubjectPrefix + ".*",
			UpgradeStatusV2SubjectPrefix + ".*",
			UpgradeStatusProofSubjectPrefix + ".pending.*",
			UpgradeStatusProofSubjectPrefix + ".confirmed.*.*",
			UpgradeStatusProofSubjectPrefix + ".completed.*.*.*",
			UpgradeStatusProofSubjectPrefix + ".status.*.*",
		},
		Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Duplicates: 2 * time.Minute,
		Discard: nats.DiscardOld, MaxAge: 0, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
	})
}

func ensureUpgradeIntegrationConsumer(t *testing.T, js nats.JetStreamContext, config *nats.ConsumerConfig) {
	t.Helper()
	if _, err := js.AddConsumer(UpgradeCommandStream, config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := js.DeleteConsumer(UpgradeCommandStream, config.Durable); err != nil {
			t.Errorf("delete upgrade integration consumer %s: %v", config.Durable, err)
		}
	})
}

func integrationUpgradeCommand(t *testing.T) UpgradeCommandRecord {
	t.Helper()
	wire := upgradeCommandWire{
		Schema: UpgradeCommandSchema, CommandID: uuid.NewString(), PlanID: uuid.NewString(), PlanRevision: 1,
		BatchID: uuid.NewString(), InstallationID: uuid.NewString(), NodeID: uuid.NewString(), Action: "upgrade",
	}
	wire.SignedExecution = gatewayUpgradeExecutionV2(t, wire.PlanID, wire.PlanRevision, wire.BatchID)
	signedDigest := sha256.Sum256(wire.SignedExecution)
	wire.SignedExecutionSHA256 = hex.EncodeToString(signedDigest[:])
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeUpgradeCommandRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func integrationUpgradeStatus(t *testing.T, command UpgradeCommandRecord) UpgradeStatusRecord {
	t.Helper()
	wire := upgradeStatusWire{
		Schema: UpgradeStatusSchema, StatusID: uuid.NewString(), StatusRevision: 1,
		CommandID: command.CommandID, PlanID: command.PlanID, PlanRevision: command.PlanRevision,
		InstallationID: command.InstallationID, NodeID: command.NodeID,
		CommandSHA256: hex.EncodeToString(command.SHA256[:]), State: "accepted", ObservedAt: time.Now().UTC(),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeUpgradeStatusRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func publishUpgradeIntegrationCommand(t *testing.T, js nats.JetStreamContext, command UpgradeCommandRecord, extra nats.Header) {
	t.Helper()
	message := nats.NewMsg(UpgradeCommandSubjectPrefix + "." + command.NodeID)
	message.Data = append([]byte(nil), command.Encoded...)
	message.Header.Set(nats.MsgIdHdr, controlUpgradeMessageID(command.Encoded))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeCommandStream)
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(command.SHA256[:]))
	message.Header.Set(UpgradeMessageKeyHeader, command.CommandID)
	for key, values := range extra {
		message.Header[key] = append([]string(nil), values...)
	}
	ack, err := js.PublishMsg(message)
	if err != nil || ack == nil || ack.Stream != UpgradeCommandStream || ack.Sequence == 0 {
		t.Fatalf("publish command ack=%#v error=%v", ack, err)
	}
}

func nextUpgradeIntegrationCommand(t *testing.T, subscription UpgradeCommandSubscription) UpgradeCommandDelivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	delivery, err := subscription.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}
