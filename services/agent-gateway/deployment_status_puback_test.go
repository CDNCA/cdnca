package gateway

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type deploymentStatusPubAckJetStream struct {
	nats.JetStreamContext
	ack                  *nats.PubAck
	err                  error
	publishes            int
	messages             map[string]*nats.RawStreamMsg
	published            *nats.Msg
	readbackAfterPublish bool
}

func (stream *deploymentStatusPubAckJetStream) PublishMsg(message *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	stream.publishes++
	stream.published = message
	if stream.err == nil && stream.ack != nil && stream.ack.Stream != "" && stream.ack.Sequence > 0 {
		if stream.messages == nil {
			stream.messages = make(map[string]*nats.RawStreamMsg)
		}
		if _, exists := stream.messages[message.Subject]; !exists {
			stream.messages[message.Subject] = &nats.RawStreamMsg{
				Subject: message.Subject, Sequence: stream.ack.Sequence,
				Data: append([]byte(nil), message.Data...), Header: cloneStatusHeaders(message.Header),
			}
		}
	}
	return stream.ack, stream.err
}

func (stream *deploymentStatusPubAckJetStream) GetLastMsg(_ string, subject string, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	if stream.readbackAfterPublish && stream.publishes == 0 {
		return nil, nats.ErrMsgNotFound
	}
	message := stream.messages[subject]
	if message == nil {
		return nil, nats.ErrMsgNotFound
	}
	return message, nil
}

func TestNATSDeploymentStatusPublishReturnsExactPubAck(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	statusUpdate := validDeploymentStatus(validDeploymentCommand())
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(statusUpdate)
	if err != nil {
		t.Fatal(err)
	}
	subject := config.StatusSubjectPrefix + ".generic-v2." + testNodeID + "." + statusUpdate.Event.EventId
	jetstream := &deploymentStatusPubAckJetStream{
		ack:                  &nats.PubAck{Stream: config.StatusStream, Sequence: 73},
		readbackAfterPublish: true,
		messages: map[string]*nats.RawStreamMsg{subject: {
			Subject: subject, Sequence: 73, Data: payload,
			Header: deploymentStatusCorrelationHeaders(statusUpdate, config),
		}},
	}
	bus := &NATSCommandBus{js: jetstream, config: config}

	publication, err := bus.PublishStatus(t.Context(), testNodeID, statusUpdate)
	if err != nil || publication.Stream != config.StatusStream || publication.Sequence != 73 || jetstream.publishes != 1 {
		t.Fatalf("deployment status publication = (%+v, %v), publishes=%d", publication, err, jetstream.publishes)
	}
	wantSubject := config.StatusSubjectPrefix + ".generic-v2." + testNodeID + "." + statusUpdate.Event.EventId
	if jetstream.published == nil || jetstream.published.Subject != wantSubject || jetstream.published.Header.Get(nats.MsgIdHdr) != statusUpdate.Event.EventId {
		t.Fatalf("deployment status wire = %+v, want subject %q", jetstream.published, wantSubject)
	}
	wantPayload, err := proto.MarshalOptions{Deterministic: true}.Marshal(statusUpdate)
	if err != nil || !bytes.Equal(jetstream.published.Data, wantPayload) {
		t.Fatalf("deployment status payload = %x, want %x (err=%v)", jetstream.published.Data, wantPayload, err)
	}
}

func TestNATSDeploymentStatusPublishRejectsPubAckSequenceMismatch(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	statusUpdate := validDeploymentStatus(validDeploymentCommand())
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(statusUpdate)
	if err != nil {
		t.Fatal(err)
	}
	subject := config.StatusSubjectPrefix + ".generic-v2." + testNodeID + "." + statusUpdate.Event.EventId
	jetstream := &deploymentStatusPubAckJetStream{
		ack:                  &nats.PubAck{Stream: config.StatusStream, Sequence: 74},
		readbackAfterPublish: true,
		messages: map[string]*nats.RawStreamMsg{subject: {
			Subject: subject, Sequence: 73, Data: payload,
			Header: deploymentStatusCorrelationHeaders(statusUpdate, config),
		}},
	}
	bus := &NATSCommandBus{js: jetstream, config: config}

	publication, err := bus.PublishStatus(t.Context(), testNodeID, statusUpdate)
	if err == nil || publication != (DeploymentStatusPublication{}) || jetstream.publishes != 1 {
		t.Fatalf("mismatched PubAck publication = (%+v, %v), publishes=%d", publication, err, jetstream.publishes)
	}
}

func TestNATSDeploymentStatusPublishReadsExactEventSubjectAcrossRestart(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	statusUpdate := validDeploymentStatus(validDeploymentCommand())
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(statusUpdate)
	if err != nil {
		t.Fatal(err)
	}
	subject := config.StatusSubjectPrefix + ".generic-v2." + testNodeID + "." + statusUpdate.Event.EventId
	jetstream := &deploymentStatusPubAckJetStream{messages: map[string]*nats.RawStreamMsg{
		subject: {
			Subject: subject, Sequence: 73, Data: payload,
			Header: deploymentStatusCorrelationHeaders(statusUpdate, config),
		},
	}}

	for attempt := 0; attempt < 2; attempt++ {
		bus := &NATSCommandBus{js: jetstream, config: config}
		publication, err := bus.PublishStatus(t.Context(), testNodeID, proto.Clone(statusUpdate).(*agentv1.DeploymentStatus))
		if err != nil || publication != (DeploymentStatusPublication{Stream: config.StatusStream, Sequence: 73}) {
			t.Fatalf("restart readback %d = (%+v, %v)", attempt, publication, err)
		}
	}
	if jetstream.publishes != 0 {
		t.Fatalf("restart readback republished %d times", jetstream.publishes)
	}
}

func TestNATSDeploymentStatusPublishRejectsEventSubjectConflict(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	statusUpdate := validDeploymentStatus(validDeploymentCommand())
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(statusUpdate)
	if err != nil {
		t.Fatal(err)
	}
	subject := config.StatusSubjectPrefix + ".generic-v2." + testNodeID + "." + statusUpdate.Event.EventId
	payload[len(payload)-1] ^= 0xff
	jetstream := &deploymentStatusPubAckJetStream{messages: map[string]*nats.RawStreamMsg{
		subject: {
			Subject: subject, Sequence: 73, Data: payload,
			Header: nats.Header{nats.MsgIdHdr: []string{statusUpdate.Event.EventId}},
		},
	}}
	bus := &NATSCommandBus{js: jetstream, config: config}

	publication, err := bus.PublishStatus(t.Context(), testNodeID, statusUpdate)
	if err == nil || publication != (DeploymentStatusPublication{}) || jetstream.publishes != 0 {
		t.Fatalf("conflicting event subject = (%+v, %v), publishes=%d", publication, err, jetstream.publishes)
	}
}

func TestNATSDeploymentStatusPublishRejectsInvalidPubAck(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	for _, test := range []struct {
		name string
		ack  *nats.PubAck
		err  error
	}{
		{name: "missing", ack: nil},
		{name: "wrong stream", ack: &nats.PubAck{Stream: "OTHER", Sequence: 73}},
		{name: "zero sequence", ack: &nats.PubAck{Stream: config.StatusStream}},
		{name: "publisher failure", ack: &nats.PubAck{Stream: config.StatusStream, Sequence: 73}, err: errors.New("publish failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			jetstream := &deploymentStatusPubAckJetStream{ack: test.ack, err: test.err}
			bus := &NATSCommandBus{js: jetstream, config: config}
			publication, err := bus.PublishStatus(t.Context(), testNodeID, validDeploymentStatus(validDeploymentCommand()))
			if err == nil || publication != (DeploymentStatusPublication{}) || jetstream.publishes != 1 {
				t.Fatalf("invalid PubAck publication = (%+v, %v), publishes=%d", publication, err, jetstream.publishes)
			}
		})
	}
}

type terminalReceiptPublicationBus struct {
	*testTerminalReceiptBus
	publication DeploymentStatusPublication
	publishErr  error
}

func (bus *terminalReceiptPublicationBus) PublishStatus(_ context.Context, _ string,
	deploymentStatus *agentv1.DeploymentStatus,
) (DeploymentStatusPublication, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if bus.publishErr != nil {
		return DeploymentStatusPublication{}, bus.publishErr
	}
	for _, persisted := range bus.published {
		if persisted.GetEvent().GetEventId() != deploymentStatus.GetEvent().GetEventId() {
			continue
		}
		if !proto.Equal(persisted, deploymentStatus) {
			return DeploymentStatusPublication{}, errors.New("deployment status event conflicts with durable state")
		}
		return bus.publication, nil
	}
	bus.published = append(bus.published, deploymentStatus)
	return bus.publication, nil
}

func TestGatewayTerminalReceiptPersistsExactStatusPublicationAndReplayDoesNotPublish(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	bus := &terminalReceiptPublicationBus{
		testTerminalReceiptBus: newTestTerminalReceiptBus(store),
		publication:            DeploymentStatusPublication{Stream: config.StatusStream, Sequence: 73},
	}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	deploymentStatus := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:73",
	}
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{delivery},
	}}

	receipt, err := gateway.persistStatusAndAckCommandReceipt(
		t.Context(), testNodeID, deploymentStatus, pending, true, true,
	)
	if err != nil || receipt == nil || receipt.PublishedStream != config.StatusStream ||
		receipt.PublishedSequence != 73 || delivery.acks.Load() != 1 || len(pending) != 0 {
		t.Fatalf("persisted receipt = (%+v, %v), command_acks=%d pending=%d", receipt, err, delivery.acks.Load(), len(pending))
	}
	stored, err := bus.loadTerminalCommandReceipt(t.Context(), testNodeID, commandKey(command))
	if err != nil || stored == nil || stored.PublishedStream != receipt.PublishedStream ||
		stored.PublishedSequence != receipt.PublishedSequence {
		t.Fatalf("read-back publication = (%+v, %v)", stored, err)
	}

	replayed, err := gateway.persistStatusAndAckCommandReceipt(
		t.Context(), testNodeID, deploymentStatus, make(pendingCommandSet), true, true,
	)
	if err != nil || replayed == nil || replayed.PublishedStream != config.StatusStream ||
		replayed.PublishedSequence != 73 || len(bus.published) != 1 {
		t.Fatalf("replayed receipt = (%+v, %v), publishes=%d", replayed, err, len(bus.published))
	}
}

func TestGatewayDeploymentStatusAckAndReceiptCarryExactPublication(t *testing.T) {
	receipt := &terminalCommandReceipt{
		StatusEventID: uuid.NewString(), DeploymentID: uuid.NewString(), Attempt: 3,
		ConfigVersionID: uuid.NewString(), TransitionSequence: 5,
		PublishedStream: DefaultNATSCommandBusConfig().StatusStream, PublishedSequence: 73,
		PersistedUnixNano: time.Unix(100, 0).UnixNano(),
	}

	ack := receipt.deploymentStatusAck()
	if ack.GetPublishedStream() != receipt.PublishedStream || ack.GetPublishedSequence() != receipt.PublishedSequence {
		t.Fatalf("deployment status ACK publication = (%q, %d), want (%q, %d)",
			ack.GetPublishedStream(), ack.GetPublishedSequence(), receipt.PublishedStream, receipt.PublishedSequence)
	}
	confirmation := receipt.deploymentStatusAckReceipt()
	if confirmation.GetPublishedStream() != receipt.PublishedStream || confirmation.GetPublishedSequence() != receipt.PublishedSequence {
		t.Fatalf("deployment status ACK receipt publication = (%q, %d), want (%q, %d)",
			confirmation.GetPublishedStream(), confirmation.GetPublishedSequence(), receipt.PublishedStream, receipt.PublishedSequence)
	}
}

func TestGatewayInvalidStatusPublicationDoesNotPersistOrAckCommand(t *testing.T) {
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	bus := &terminalReceiptPublicationBus{testTerminalReceiptBus: newTestTerminalReceiptBus(store)}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	deploymentStatus := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:74",
	}
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{delivery},
	}}

	receipt, err := gateway.persistStatusAndAckCommandReceipt(
		t.Context(), testNodeID, deploymentStatus, pending, true, true,
	)
	if receipt != nil || status.Code(err) != codes.Unavailable || delivery.acks.Load() != 0 ||
		len(pending) != 1 || store.count() != 0 {
		t.Fatalf("invalid publication = (%+v, %v), command_acks=%d pending=%d receipts=%d",
			receipt, err, delivery.acks.Load(), len(pending), store.count())
	}
}

type terminalReceiptPersistenceFailureBus struct {
	*terminalReceiptPublicationBus
	saveFailures int
}

func (bus *terminalReceiptPersistenceFailureBus) saveTerminalCommandReceipt(ctx context.Context, receipt *terminalCommandReceipt) (*terminalCommandReceipt, error) {
	if bus.saveFailures > 0 {
		bus.saveFailures--
		return nil, errors.New("receipt persistence interrupted")
	}
	return bus.testTerminalReceiptBus.saveTerminalCommandReceipt(ctx, receipt)
}

func TestGatewayTerminalReceiptRetryDoesNotRepublishAfterPersistenceFailure(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	bus := &terminalReceiptPersistenceFailureBus{
		terminalReceiptPublicationBus: &terminalReceiptPublicationBus{
			testTerminalReceiptBus: newTestTerminalReceiptBus(store),
			publication:            DeploymentStatusPublication{Stream: config.StatusStream, Sequence: 91},
		},
		saveFailures: 1,
	}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	deploymentStatus := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:91",
	}
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{delivery},
	}}

	first, err := gateway.persistStatusAndAckCommandReceipt(
		t.Context(), testNodeID, deploymentStatus, pending, true, true,
	)
	if first != nil || status.Code(err) != codes.Unavailable || delivery.acks.Load() != 0 || len(pending) != 1 || store.count() != 0 || len(bus.published) != 1 {
		t.Fatalf("first persistence failure = (%+v, %v), acks=%d pending=%d receipts=%d publishes=%d", first, err, delivery.acks.Load(), len(pending), store.count(), len(bus.published))
	}

	second, err := gateway.persistStatusAndAckCommandReceipt(
		t.Context(), testNodeID, deploymentStatus, pending, true, true,
	)
	if err != nil || second == nil || second.PublishedStream != config.StatusStream || second.PublishedSequence != 91 || delivery.acks.Load() != 1 || len(pending) != 0 || store.count() != 1 || len(bus.published) != 1 {
		t.Fatalf("retry after persistence failure = (%+v, %v), acks=%d pending=%d receipts=%d publishes=%d", second, err, delivery.acks.Load(), len(pending), store.count(), len(bus.published))
	}
}
