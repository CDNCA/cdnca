package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type blockingPublishJetStream struct {
	nats.JetStreamContext
	subject string
	arrived chan<- struct{}
	release <-chan struct{}
}

func (b *blockingPublishJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	if message.Subject == b.subject {
		b.arrived <- struct{}{}
		<-b.release
	}
	return b.JetStreamContext.PublishMsg(message, options...)
}

type uncertainPubAckJetStream struct {
	nats.JetStreamContext
	subject  string
	once     sync.Once
	injected chan struct{}
}

type predecessorHistoryJetStream struct {
	nats.JetStreamContext
	messages    map[uint64]*nats.RawStreamMsg
	deleteCalls []uint64
}

type currentHeadJetStream struct {
	nats.JetStreamContext
	message *nats.RawStreamMsg
}

type recreatingStreamJetStream struct {
	nats.JetStreamContext
	replacementContext nats.JetStreamContext
	sequence           uint64
	recreate           func()
	once               sync.Once
}

func (s *currentHeadJetStream) GetLastMsg(_ string, _ string, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	if s.message == nil {
		return nil, nats.ErrMsgNotFound
	}
	clone := *s.message
	clone.Data = append([]byte(nil), s.message.Data...)
	clone.Header = make(nats.Header, len(s.message.Header))
	for name, values := range s.message.Header {
		clone.Header[name] = append([]string(nil), values...)
	}
	return &clone, nil
}

func (s *recreatingStreamJetStream) GetMsg(stream string, sequence uint64, options ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	message, err := s.JetStreamContext.GetMsg(stream, sequence, options...)
	if err == nil && sequence == s.sequence {
		s.once.Do(s.recreate)
	}
	return message, err
}

func (s *recreatingStreamJetStream) DeleteMsg(stream string, sequence uint64, options ...nats.JSOpt) error {
	return s.replacementContext.DeleteMsg(stream, sequence, options...)
}

func (s *predecessorHistoryJetStream) GetMsg(_ string, sequence uint64, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	message := s.messages[sequence]
	if message == nil {
		return nil, nats.ErrMsgNotFound
	}
	clone := *message
	clone.Data = append([]byte(nil), message.Data...)
	clone.Header = make(nats.Header, len(message.Header))
	for name, values := range message.Header {
		clone.Header[name] = append([]string(nil), values...)
	}
	return &clone, nil
}

func (s *predecessorHistoryJetStream) DeleteMsg(_ string, sequence uint64, _ ...nats.JSOpt) error {
	s.deleteCalls = append(s.deleteCalls, sequence)
	return fmt.Errorf("unsafe predecessor delete")
}

func (u *uncertainPubAckJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	ack, err := u.JetStreamContext.PublishMsg(message, options...)
	if err != nil || message.Subject != u.subject {
		return ack, err
	}
	inject := false
	u.once.Do(func() {
		inject = true
		if u.injected != nil {
			close(u.injected)
		}
	})
	if inject {
		return nil, context.DeadlineExceeded
	}
	return ack, nil
}

func TestActiveConfigIdentityWireContract(t *testing.T) {
	if got := int32(agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY); got != 18 {
		t.Fatalf("active identity capability = %d, want 18", got)
	}
	if got := int32(agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_UNSPECIFIED); got != 0 {
		t.Fatalf("unspecified schema = %d, want 0", got)
	}
	if got := int32(agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1); got != 1 {
		t.Fatalf("v1 schema = %d, want 1", got)
	}
	assertActiveIdentityFields(t, (&agentv1.ActiveConfigIdentity{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{
		"config_version_id": 1, "artifact_sha256": 2, "schema": 3,
	})
	assertActiveIdentityFields(t, (&agentv1.ActiveDeployment{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{"observed_active_config_identity": 5})
	assertActiveIdentityFields(t, (&agentv1.AgentHello{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{
		"current_config_identity": 9, "previous_config_identity": 10,
	})
	assertActiveIdentityFields(t, (&agentv1.EdgeRuntimeStatus{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{"loaded_config_identity": 4})
	assertActiveIdentityFields(t, (&agentv1.Heartbeat{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{
		"active_config_identity_capability": 10, "current_config_identity": 11, "previous_config_identity": 12,
	})
	assertActiveIdentityFields(t, (&agentv1.DeploymentStatus{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{
		"active_config_identity_capability": 10, "active_config_identity": 11,
	})
}

func TestTerminalConfirmationPredecessorCleanupIsBoundedAndAtomic(t *testing.T) {
	const hopLimit = 3
	for _, index := range []bool{false, true} {
		name := "confirmation"
		if index {
			name = "index"
		}
		t.Run(name, func(t *testing.T) {
			for _, test := range []struct {
				name        string
				count       int
				wrongAt     int
				oversizedAt int
				tamper      string
				wantErr     bool
			}{
				{name: "exactBoundary", count: hopLimit},
				{name: "boundaryPlusOne", count: hopLimit + 1},
				{name: "wrongPredecessor", count: hopLimit, wrongAt: 1, wantErr: true},
				{name: "aggregateByteBound", count: hopLimit, oversizedAt: 1, wantErr: true},
				{name: "wrongEmbeddedIdentity", count: hopLimit, tamper: "identity", wantErr: true},
				{name: "wrongMessageID", count: hopLimit, tamper: "message-id", wantErr: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					stream, subject := predecessorHistory(t, index, test.count, test.wrongAt, test.oversizedAt)
					if test.tamper == "identity" {
						previous := uint64(0)
						var encoded []byte
						var messageID string
						var err error
						if index {
							value := &terminalCommandReceiptConfirmationIndex{
								Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: uuid.NewString(),
								PreviousSequence: previous,
							}
							encoded, messageID, err = terminalCommandReceiptConfirmationIndexWireIdentity(subject, value)
						} else {
							confirmation := activeIdentityNATSConfirmation(t, uuid.NewString(), "wrong-embedded-identity")
							encoded, messageID, err = terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, previous)
						}
						if err != nil {
							t.Fatal(err)
						}
						stream.messages[1].Data = encoded
						stream.messages[1].Header.Set(nats.MsgIdHdr, messageID)
					}
					if test.tamper == "message-id" {
						stream.messages[1].Header.Set(nats.MsgIdHdr, "wrong-message-id")
					}
					currentSequence := uint64(100)
					stream.messages[currentSequence] = &nats.RawStreamMsg{
						Subject: subject, Sequence: currentSequence, Data: []byte("current durable value"),
					}
					bus := &NATSCommandBus{js: stream, config: DefaultNATSCommandBusConfig()}
					bus.config.StatusSubjectPrefix = "cdnca.test.predecessor"
					bus.config.MaxAckPending = hopLimit
					bus.config.MaxStatusBytes = 4096
					var err error
					if index {
						err = bus.deleteTerminalCommandReceiptConfirmationIndexPredecessors(t.Context(), subject, uint64(test.count))
					} else {
						err = bus.deleteTerminalCommandReceiptConfirmationPredecessors(t.Context(), subject, uint64(test.count))
					}
					if test.wantErr && err == nil {
						t.Fatal("predecessor cleanup accepted invalid history")
					}
					if !test.wantErr && err != nil {
						t.Fatal(err)
					}
					if stream.messages[currentSequence] == nil {
						t.Fatal("predecessor cleanup deleted the current durable value")
					}
					if len(stream.deleteCalls) != 0 {
						t.Fatalf("predecessor validation attempted destructive cleanup: %v", stream.deleteCalls)
					}
					for sequence := 1; sequence <= test.count; sequence++ {
						if stream.messages[uint64(sequence)] == nil {
							t.Fatalf("predecessor %d changed during validation", sequence)
						}
					}
				})
			}
		})
	}
}

func TestTerminalConfirmationPredecessorCleanupResumesAfterPartialDelete(t *testing.T) {
	for _, index := range []bool{false, true} {
		name := "confirmation"
		if index {
			name = "index"
		}
		t.Run(name, func(t *testing.T) {
			stream, subject := predecessorHistory(t, index, 3, 0, 0)
			bus := &NATSCommandBus{js: stream, config: DefaultNATSCommandBusConfig()}
			bus.config.StatusSubjectPrefix = "cdnca.test.predecessor"
			bus.config.MaxAckPending = 4
			bus.config.MaxStatusBytes = 4096
			cleanup := bus.deleteTerminalCommandReceiptConfirmationPredecessors
			if index {
				cleanup = bus.deleteTerminalCommandReceiptConfirmationIndexPredecessors
			}
			if err := cleanup(t.Context(), subject, 3); err != nil {
				t.Fatal(err)
			}
			if err := cleanup(t.Context(), subject, 3); err != nil {
				t.Fatalf("predecessor validation retry failed: %v", err)
			}
			if len(stream.deleteCalls) != 0 {
				t.Fatalf("predecessor validation retry attempted deletion: %v", stream.deleteCalls)
			}
			for sequence := uint64(1); sequence <= 3; sequence++ {
				if stream.messages[sequence] == nil {
					t.Fatalf("predecessor validation retry changed sequence %d", sequence)
				}
			}
		})
	}
}

func TestTerminalConfirmationCurrentHeadRequiresStableMessageID(t *testing.T) {
	for _, index := range []bool{false, true} {
		for _, tamper := range []string{"missing", "wrong"} {
			name := "confirmation"
			if index {
				name = "index"
			}
			t.Run(name+"/"+tamper, func(t *testing.T) {
				nodeID := uuid.NewString()
				confirmation := activeIdentityNATSConfirmation(t, nodeID, "current-head")
				prefix := "cdnca.test.current-head"
				subject := terminalCommandReceiptConfirmationSubject(prefix, nodeID, confirmation.deploymentKey())
				var wire []byte
				var messageID string
				var err error
				if index {
					subject = terminalCommandReceiptConfirmationIndexSubject(prefix, nodeID)
					wire, messageID, err = terminalCommandReceiptConfirmationIndexWireIdentity(subject, &terminalCommandReceiptConfirmationIndex{
						Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID, PreviousSequence: 41,
					})
				} else {
					wire, messageID, err = terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, 41)
				}
				if err != nil {
					t.Fatal(err)
				}
				message := &nats.RawStreamMsg{Subject: subject, Sequence: 42, Data: wire, Header: make(nats.Header)}
				if tamper == "wrong" {
					message.Header.Set(nats.MsgIdHdr, messageID+"-wrong")
				}
				bus := &NATSCommandBus{js: &currentHeadJetStream{message: message}, config: DefaultNATSCommandBusConfig()}
				bus.config.StatusSubjectPrefix = prefix
				if index {
					_, _, err = bus.loadTerminalCommandReceiptConfirmationIndexMessage(t.Context(), nodeID)
				} else {
					_, _, _, err = bus.loadTerminalCommandReceiptConfirmationMessage(t.Context(), nodeID, confirmation.deploymentKey())
				}
				if err == nil {
					t.Fatal("current head with an invalid Nats-Msg-Id was accepted")
				}
			})
		}
	}
}

func predecessorHistory(t *testing.T, index bool, count, wrongAt, oversizedAt int) (*predecessorHistoryJetStream, string) {
	t.Helper()
	stream := &predecessorHistoryJetStream{messages: make(map[uint64]*nats.RawStreamMsg)}
	nodeID := uuid.NewString()
	confirmation := activeIdentityNATSConfirmation(t, nodeID, "bounded-predecessor")
	prefix := "cdnca.test.predecessor"
	subject := terminalCommandReceiptConfirmationSubject(prefix, nodeID, confirmation.deploymentKey())
	if index {
		subject = terminalCommandReceiptConfirmationIndexSubject(prefix, nodeID)
	}
	for sequence := 1; sequence <= count; sequence++ {
		previous := uint64(sequence - 1)
		var encoded []byte
		var messageID string
		var err error
		if index {
			value := &terminalCommandReceiptConfirmationIndex{
				Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID,
				PreviousSequence: previous,
			}
			encoded, messageID, err = terminalCommandReceiptConfirmationIndexWireIdentity(subject, value)
		} else {
			encoded, messageID, err = terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, previous)
		}
		if err != nil {
			t.Fatal(err)
		}
		if sequence == oversizedAt {
			encoded = make([]byte, 4097)
		}
		messageSubject := subject
		if sequence == wrongAt {
			messageSubject += ".wrong"
		}
		stream.messages[uint64(sequence)] = &nats.RawStreamMsg{
			Subject: messageSubject, Sequence: uint64(sequence), Data: encoded,
			Header: nats.Header{nats.MsgIdHdr: []string{messageID}},
		}
	}
	return stream, subject
}

func TestDeploymentStatusAckWireContract(t *testing.T) {
	if got := int32(agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT); got != 19 {
		t.Fatalf("deployment status ACK receipt capability = %d, want 19", got)
	}
	response := (&agentv1.ConnectResponse{}).ProtoReflect().Descriptor()
	field := response.Fields().ByName("deployment_status_ack")
	if field == nil || field.Number() != 9 {
		t.Fatalf("ConnectResponse.deployment_status_ack = %v, want field 9", field)
	}
	assertActiveIdentityFields(t, (&agentv1.DeploymentStatusAck{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{
		"status_event_id": 1, "deployment_id": 2, "attempt": 3, "config_version_id": 4,
		"transition_sequence": 5, "persisted_time": 6, "published_stream": 7, "published_sequence": 8,
	})
	request := (&agentv1.ConnectRequest{}).ProtoReflect().Descriptor()
	field = request.Fields().ByName("deployment_status_ack_receipt")
	if field == nil || field.Number() != 7 {
		t.Fatalf("ConnectRequest.deployment_status_ack_receipt = %v, want field 7", field)
	}
	assertActiveIdentityFields(t, (&agentv1.DeploymentStatusAckReceipt{}).ProtoReflect().Descriptor(), map[string]protoreflect.FieldNumber{
		"status_event_id": 1, "deployment_id": 2, "attempt": 3, "config_version_id": 4,
		"transition_sequence": 5, "persisted_time": 6, "published_stream": 7, "published_sequence": 8,
	})
}

func TestGatewayNegotiatesActiveConfigIdentityOnlyAtExactV1(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	stream, hello, cleanup := connectWithActiveIdentityHello(t, servers, true)
	defer cleanup()
	if !gatewayHelloHasActiveIdentityV1(hello) {
		t.Fatalf("enabled capabilities = %+v, want active identity v1", hello.EnabledCapabilities)
	}
	_ = stream.CloseSend()

	legacyStream, legacyHello, legacyCleanup := connectWithActiveIdentityHello(t, servers, false)
	defer legacyCleanup()
	if gatewayHelloHasActiveIdentityV1(legacyHello) {
		t.Fatalf("legacy enabled capabilities = %+v", legacyHello.EnabledCapabilities)
	}
	_ = legacyStream.CloseSend()
}

func TestGatewayRejectsMalformedOrUnnegotiatedActiveIdentity(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	currentID := uuid.NewString()
	previousID := uuid.NewString()
	digest := bytes.Repeat([]byte{0x42}, 32)
	hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
	hello.Capabilities.Features = []*agentv1.Capability{testActiveIdentityCapability()}
	hello.CurrentConfigVersionId = &currentID
	hello.PreviousConfigVersionId = &previousID
	hello.CurrentConfigIdentity = testActiveIdentity(currentID, digest)
	hello.PreviousConfigIdentity = testActiveIdentity(previousID, digest)
	hello.ActiveDeployments = []*agentv1.ActiveDeployment{{
		DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: currentID,
		State:                        agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		ObservedActiveConfigIdentity: testActiveIdentity(currentID, digest),
	}}
	if err := gateway.validateHello(hello); err != nil {
		t.Fatalf("valid hello rejected: %v", err)
	}

	tests := []struct {
		name   string
		change func(*agentv1.AgentHello)
	}{
		{name: "identity without capability", change: func(value *agentv1.AgentHello) { value.Capabilities.Features = nil }},
		{name: "unsupported capability version", change: func(value *agentv1.AgentHello) { value.Capabilities.Features[0].ApiVersion = 2 }},
		{name: "unknown schema", change: func(value *agentv1.AgentHello) { value.CurrentConfigIdentity.Schema = 99 }},
		{name: "short digest", change: func(value *agentv1.AgentHello) { value.CurrentConfigIdentity.ArtifactSha256 = digest[:31] }},
		{name: "noncanonical UUID", change: func(value *agentv1.AgentHello) { value.CurrentConfigIdentity.ConfigVersionId = "NOT-A-UUID" }},
		{name: "noncanonical current companion without identity", change: func(value *agentv1.AgentHello) {
			value.CurrentConfigVersionId = proto.String("cfg-current")
			value.CurrentConfigIdentity = nil
		}},
		{name: "noncanonical previous companion without identity", change: func(value *agentv1.AgentHello) {
			value.PreviousConfigVersionId = proto.String("cfg-previous")
			value.PreviousConfigIdentity = nil
		}},
		{name: "current UUID mismatch", change: func(value *agentv1.AgentHello) { value.CurrentConfigIdentity.ConfigVersionId = uuid.NewString() }},
		{name: "active deployment UUID mismatch", change: func(value *agentv1.AgentHello) {
			value.ActiveDeployments[0].ObservedActiveConfigIdentity.ConfigVersionId = uuid.NewString()
		}},
		{name: "noncanonical active deployment without identity", change: func(value *agentv1.AgentHello) {
			value.ActiveDeployments[0].ConfigVersionId = "cfg-active"
			value.ActiveDeployments[0].ObservedActiveConfigIdentity = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.Clone(hello).(*agentv1.AgentHello)
			test.change(candidate)
			if err := gateway.validateHello(candidate); err == nil {
				t.Fatal("invalid hello was accepted")
			}
		})
	}
}

func TestGatewayValidatesAndForwardsNegotiatedHeartbeatIdentity(t *testing.T) {
	sink := &fakeHeartbeatSink{}
	gateway := newHeartbeatGateway(t, sink, nil)
	received, stream, done := startActiveIdentityHeartbeatSession(t, gateway)
	currentID := uuid.NewString()
	previousID := uuid.NewString()
	digest := bytes.Repeat([]byte{0x24}, 32)
	request := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())
	heartbeat := request.GetHeartbeat()
	heartbeat.CurrentConfigVersionId = &currentID
	heartbeat.PreviousConfigVersionId = &previousID
	heartbeat.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	heartbeat.CurrentConfigIdentity = testActiveIdentity(currentID, digest)
	heartbeat.PreviousConfigIdentity = testActiveIdentity(previousID, digest)
	heartbeat.Runtime = &agentv1.EdgeRuntimeStatus{LoadedConfigVersionId: &currentID, LoadedConfigIdentity: testActiveIdentity(currentID, digest)}
	heartbeat.ActiveDeployments = []*agentv1.ActiveDeployment{{
		DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: currentID,
		State:                        agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		ObservedActiveConfigIdentity: testActiveIdentity(currentID, digest),
	}}
	if err := gateway.validateHeartbeat(heartbeat, 1, 0, false, "", true); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	for _, test := range []struct {
		name       string
		negotiated bool
		change     func(*agentv1.Heartbeat)
	}{
		{name: "unnegotiated", negotiated: false},
		{name: "unknown schema", negotiated: true, change: func(value *agentv1.Heartbeat) { value.CurrentConfigIdentity.Schema = 99 }},
		{name: "short digest", negotiated: true, change: func(value *agentv1.Heartbeat) {
			value.CurrentConfigIdentity.ArtifactSha256 = value.CurrentConfigIdentity.ArtifactSha256[:31]
		}},
		{name: "runtime UUID mismatch", negotiated: true, change: func(value *agentv1.Heartbeat) { value.Runtime.LoadedConfigIdentity.ConfigVersionId = uuid.NewString() }},
		{name: "noncanonical current companion without identity", negotiated: true, change: func(value *agentv1.Heartbeat) {
			value.CurrentConfigVersionId = proto.String("cfg-current")
			value.CurrentConfigIdentity = nil
		}},
		{name: "noncanonical previous companion without identity", negotiated: true, change: func(value *agentv1.Heartbeat) {
			value.PreviousConfigVersionId = proto.String("cfg-previous")
			value.PreviousConfigIdentity = nil
		}},
		{name: "noncanonical runtime companion without identity", negotiated: true, change: func(value *agentv1.Heartbeat) {
			value.Runtime.LoadedConfigVersionId = proto.String("cfg-runtime")
			value.Runtime.LoadedConfigIdentity = nil
		}},
		{name: "noncanonical active deployment without identity", negotiated: true, change: func(value *agentv1.Heartbeat) {
			value.ActiveDeployments[0].ConfigVersionId = "cfg-active"
			value.ActiveDeployments[0].ObservedActiveConfigIdentity = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.Clone(heartbeat).(*agentv1.Heartbeat)
			if test.change != nil {
				test.change(candidate)
			}
			if err := gateway.validateHeartbeat(candidate, 1, 0, false, "", test.negotiated); err == nil {
				t.Fatal("invalid heartbeat was accepted")
			}
		})
	}
	received <- connectReceive{request: request}
	received <- connectReceive{request: proto.Clone(request).(*agentv1.ConnectRequest)}
	received <- connectReceive{err: io.EOF}
	for range 2 {
		if response := <-stream.sent; response.GetHeartbeatAck() == nil {
			t.Fatalf("response = %+v, want heartbeat ack", response)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.attempts) != 2 || !proto.Equal(sink.attempts[0], sink.attempts[1]) {
		t.Fatalf("persisted duplicate identities = %+v", sink.attempts)
	}
	if !bytes.Equal(sink.attempts[0].CurrentConfigIdentity.ArtifactSha256, digest) {
		t.Fatal("heartbeat identity digest was not forwarded unchanged")
	}
}

func TestGatewayRejectsNoncanonicalConfigUUIDBeforePublication(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	if err := gateway.validateDeploymentCommand(command, "", true); err == nil {
		t.Fatal("noncanonical command config version was accepted for active identity")
	}
	command.ConfigVersionId = uuid.NewString()
	command.PreviousConfigVersionId = proto.String("cfg-previous")
	if err := gateway.validateDeploymentCommand(command, "", true); err == nil {
		t.Fatal("noncanonical command previous config version was accepted for active identity")
	}
	command.PreviousConfigVersionId = nil
	statusUpdate := validDeploymentStatus(command)
	statusUpdate.ConfigVersionId = "cfg-status"
	pending := pendingCommandSet{commandKey(command): {command: command}}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, statusUpdate, pending, true); grpcstatus.Code(err) != codes.InvalidArgument {
		t.Fatalf("noncanonical status error = %v, want InvalidArgument", err)
	}
	if len(bus.published) != 0 {
		t.Fatalf("noncanonical status was published: %d", len(bus.published))
	}
}

func TestGatewayDeploymentStatusIdentityValidationAndForwarding(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	command.Event.TaskId = proto.String("active-identity-task")
	status := validDeploymentStatus(command)
	bindDeploymentStatusEvent(t, status, command)
	status.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
	status.TransitionSequence = 5
	status.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	status.ActiveConfigIdentity = testActiveIdentity(command.ConfigVersionId, bytes.Repeat([]byte{0x17}, 32))
	if err := gateway.validateDeploymentStatus(status, true); err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, status, pendingCommandSet{}, true); grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("status without authoritative command code = %v, want FailedPrecondition", grpcstatus.Code(err))
	}
	if len(bus.published) != 0 {
		t.Fatalf("unbound status was published: %+v", bus.published)
	}
	bound := proto.Clone(status).(*agentv1.DeploymentStatus)
	bound.ActiveConfigIdentity.ArtifactSha256 = append([]byte(nil), command.Artifacts[0].Sha256...)
	pending := pendingCommandSet{commandKey(command): {command: command}}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, bound, pending, true); err != nil {
		t.Fatalf("signed artifact binding rejected: %v", err)
	}
	if len(bus.published) != 1 || !proto.Equal(bus.published[0].ActiveConfigIdentity, bound.ActiveConfigIdentity) {
		t.Fatalf("published status = %+v", bus.published)
	}
	mismatch := proto.Clone(bound).(*agentv1.DeploymentStatus)
	mismatch.ActiveConfigIdentity.ArtifactSha256[0] ^= 0xff
	pending = pendingCommandSet{commandKey(command): {command: command}}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, mismatch, pending, true); err == nil {
		t.Fatal("mismatched signed artifact digest was published")
	}
	eventTests := []struct {
		name   string
		change func(*agentv1.DeploymentStatus)
	}{
		{name: "causation", change: func(value *agentv1.DeploymentStatus) { value.Event.CausationId = proto.String(uuid.NewString()) }},
		{name: "request", change: func(value *agentv1.DeploymentStatus) { value.Event.RequestId = uuid.NewString() }},
		{name: "traceparent", change: func(value *agentv1.DeploymentStatus) {
			value.Event.Traceparent = "00-33333333333333333333333333333333-4444444444444444-01"
		}},
		{name: "correlation", change: func(value *agentv1.DeploymentStatus) { value.Event.CorrelationId = uuid.NewString() }},
		{name: "task", change: func(value *agentv1.DeploymentStatus) { value.Event.TaskId = proto.String("different-task") }},
	}
	for _, test := range eventTests {
		t.Run("command event "+test.name, func(t *testing.T) {
			candidate := proto.Clone(bound).(*agentv1.DeploymentStatus)
			test.change(candidate)
			pending := pendingCommandSet{commandKey(command): {command: command}}
			published := len(bus.published)
			if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, candidate, pending, true); grpcstatus.Code(err) != codes.FailedPrecondition {
				t.Fatalf("event mismatch code = %v, want FailedPrecondition", grpcstatus.Code(err))
			}
			if len(bus.published) != published || len(pending) != 1 {
				t.Fatalf("event mismatch changed durable state: published=%d pending=%d", len(bus.published), len(pending))
			}
		})
	}

	tests := []struct {
		name       string
		negotiated bool
		change     func(*agentv1.DeploymentStatus)
	}{
		{name: "unnegotiated", negotiated: false},
		{name: "missing final capability", negotiated: true, change: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentityCapability = nil }},
		{name: "unknown schema", negotiated: true, change: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentity.Schema = 99 }},
		{name: "short digest", negotiated: true, change: func(value *agentv1.DeploymentStatus) {
			value.ActiveConfigIdentity.ArtifactSha256 = value.ActiveConfigIdentity.ArtifactSha256[:31]
		}},
		{name: "healthy target mismatch", negotiated: true, change: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentity.ConfigVersionId = uuid.NewString() }},
		{name: "nonterminal identity", negotiated: true, change: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED
		}},
		{name: "failed identity", negotiated: true, change: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
		}},
		{name: "reverted identity", negotiated: true, change: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED
		}},
		{name: "rollback failed identity", negotiated: true, change: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.Clone(status).(*agentv1.DeploymentStatus)
			if test.change != nil {
				test.change(candidate)
			}
			if err := gateway.validateDeploymentStatus(candidate, test.negotiated); err == nil {
				t.Fatal("invalid deployment status was accepted")
			}
		})
	}

	historical := proto.Clone(status).(*agentv1.DeploymentStatus)
	historical.ActiveConfigIdentityCapability = nil
	historical.ActiveConfigIdentity = nil
	if err := gateway.validateDeploymentStatus(historical, true); err != nil {
		t.Fatalf("historical terminal status rejected: %v", err)
	}
}

func TestGatewayKeepsAuthoritativeCommandUntilHealthyIdentity(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	delivery := &fakeCommandDelivery{command: command}
	delivered := validDeploymentStatus(command)
	pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, delivered, pending, true); err != nil {
		t.Fatal(err)
	}
	if delivery.acks.Load() != 0 || len(pending) != 1 || len(bus.published) != 1 {
		t.Fatalf("DELIVERED destroyed binding: acks=%d pending=%d published=%d", delivery.acks.Load(), len(pending), len(bus.published))
	}
	healthy := proto.Clone(delivered).(*agentv1.DeploymentStatus)
	healthy.Event.EventId = uuid.NewString()
	bindDeploymentStatusEvent(t, healthy, command)
	healthy.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
	healthy.TransitionSequence = 5
	healthy.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	healthy.ActiveConfigIdentity = testActiveIdentity(command.ConfigVersionId, command.Artifacts[0].Sha256)
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, healthy, pending, true); err != nil {
		t.Fatal(err)
	}
	if delivery.acks.Load() != 1 || len(pending) != 0 || len(bus.published) != 2 {
		t.Fatalf("HEALTHY did not complete binding: acks=%d pending=%d published=%d", delivery.acks.Load(), len(pending), len(bus.published))
	}
}

func TestGatewayBindsEveryAuthoritativeTerminalStatusEvent(t *testing.T) {
	states := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
	}
	eventTests := []struct {
		name   string
		change func(*agentv1.DeploymentStatus)
	}{
		{name: "causation", change: func(value *agentv1.DeploymentStatus) { value.Event.CausationId = proto.String(uuid.NewString()) }},
		{name: "request", change: func(value *agentv1.DeploymentStatus) { value.Event.RequestId = uuid.NewString() }},
		{name: "traceparent", change: func(value *agentv1.DeploymentStatus) {
			value.Event.Traceparent = "00-33333333333333333333333333333333-4444444444444444-01"
		}},
		{name: "correlation", change: func(value *agentv1.DeploymentStatus) { value.Event.CorrelationId = uuid.NewString() }},
		{name: "task", change: func(value *agentv1.DeploymentStatus) { value.Event.TaskId = proto.String("different-task") }},
	}
	for _, state := range states {
		for _, eventTest := range eventTests {
			t.Run(state.String()+"/"+eventTest.name, func(t *testing.T) {
				bus := &fakeCommandBus{}
				gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
				command := validDeploymentCommand()
				command.ConfigVersionId = uuid.NewString()
				command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
				command.Event.TaskId = proto.String("terminal-task")
				delivery := &fakeCommandDelivery{command: command}
				candidate := terminalStatusForCommand(t, command, state)
				eventTest.change(candidate)
				pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}
				err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, candidate, pending, true)
				if grpcstatus.Code(err) != codes.FailedPrecondition {
					t.Fatalf("event mismatch code = %v, want FailedPrecondition", grpcstatus.Code(err))
				}
				if delivery.acks.Load() != 0 || len(pending) != 1 || len(bus.published) != 0 {
					t.Fatalf("event mismatch changed durable state: acks=%d pending=%d published=%d", delivery.acks.Load(), len(pending), len(bus.published))
				}
			})
		}
		t.Run(state.String()+"/valid", func(t *testing.T) {
			bus := &fakeCommandBus{}
			gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
			command := validDeploymentCommand()
			command.ConfigVersionId = uuid.NewString()
			command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
			command.Event.TaskId = proto.String("terminal-task")
			delivery := &fakeCommandDelivery{command: command}
			pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}
			if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, terminalStatusForCommand(t, command, state), pending, true); err != nil {
				t.Fatal(err)
			}
			if delivery.acks.Load() != 1 || len(pending) != 0 || len(bus.published) != 1 {
				t.Fatalf("valid terminal did not ACK: acks=%d pending=%d published=%d", delivery.acks.Load(), len(pending), len(bus.published))
			}
		})
	}
}

func TestGatewaySendsDeploymentStatusAckAfterTerminalPersistence(t *testing.T) {
	subscription := newFakeCommandSubscription()
	bus := &fakeCommandBus{subscription: subscription, publication: DeploymentStatusPublication{
		Stream: DefaultNATSCommandBusConfig().StatusStream, Sequence: 41,
	}}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	command.Event.TaskId = proto.String("terminal-task")
	delivery := &fakeCommandDelivery{command: command}
	subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer lease.Release()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	received := make(chan connectReceive, 1)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true,
		)
	}()
	select {
	case response := <-stream.sent:
		if !proto.Equal(response.GetDeploymentCommand(), command) {
			t.Fatalf("command response = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("command was not delivered")
	}
	terminal := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: terminal},
	}}
	select {
	case response := <-stream.sent:
		ack := response.GetDeploymentStatusAck()
		if ack == nil || ack.StatusEventId != terminal.Event.EventId || ack.DeploymentId != terminal.DeploymentId ||
			ack.Attempt != terminal.Attempt || ack.ConfigVersionId != terminal.ConfigVersionId ||
			ack.TransitionSequence != terminal.TransitionSequence || ack.PersistedTime == nil || ack.PersistedTime.CheckValid() != nil ||
			ack.PublishedStream != DefaultNATSCommandBusConfig().StatusStream || ack.PublishedSequence != 41 {
			t.Fatalf("deployment status ack = %+v", ack)
		}
		if delivery.acks.Load() != 1 || len(bus.published) != 1 {
			t.Fatalf("ACK preceded persistence: command_acks=%d published=%d", delivery.acks.Load(), len(bus.published))
		}
	case <-time.After(time.Second):
		t.Fatal("terminal deployment status was not acknowledged")
	}
	cancel()
	<-done
}

func TestGatewayDefersDeploymentStatusAckUntilAuthoritativeCommandArrives(t *testing.T) {
	subscription := newFakeCommandSubscription()
	bus := &fakeCommandBus{subscription: subscription}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	command.Event.TaskId = proto.String("status-before-command")
	terminal := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &fakeCommandDelivery{command: command}
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer lease.Release()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	received := make(chan connectReceive, 4)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true,
		)
	}()
	received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: terminal},
	}}
	time.Sleep(20 * time.Millisecond)
	bus.mu.Lock()
	if len(bus.published) != 0 {
		bus.mu.Unlock()
		t.Fatalf("unbound terminal was published before its command: %d", len(bus.published))
	}
	bus.mu.Unlock()
	select {
	case response := <-stream.sent:
		t.Fatalf("unbound terminal received response before command: %+v", response)
	case <-time.After(20 * time.Millisecond):
	}

	subscription.deliveries <- delivery
	select {
	case response := <-stream.sent:
		if !proto.Equal(response.GetDeploymentCommand(), command) {
			t.Fatalf("command response = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("authoritative command was not delivered")
	}
	received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 3, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: proto.Clone(terminal).(*agentv1.DeploymentStatus)},
	}}
	select {
	case response := <-stream.sent:
		ack := response.GetDeploymentStatusAck()
		if ack == nil || ack.StatusEventId != terminal.Event.EventId {
			t.Fatalf("replayed terminal acknowledgement = %+v", response)
		}
		if delivery.acks.Load() != 1 {
			t.Fatalf("command delivery ACKs = %d, want 1", delivery.acks.Load())
		}
		if len(bus.published) != 1 {
			t.Fatalf("authoritative replay publications = %d, want 1", len(bus.published))
		}
	case <-time.After(time.Second):
		t.Fatal("replayed authoritative terminal was not acknowledged")
	}
	cancel()
	<-done
}

func TestGatewayDoesNotAckHealthyUnknownIdentity(t *testing.T) {
	subscription := newFakeCommandSubscription()
	bus := &fakeCommandBus{subscription: subscription}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	command.Event.TaskId = proto.String("healthy-unknown")
	delivery := &fakeCommandDelivery{command: command}
	subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer lease.Release()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	received := make(chan connectReceive, 2)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true,
		)
	}()
	select {
	case response := <-stream.sent:
		if !proto.Equal(response.GetDeploymentCommand(), command) {
			t.Fatalf("command response = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("command was not delivered")
	}
	healthy := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	healthy.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	healthy.ActiveConfigIdentity = nil
	received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: healthy},
	}}
	waitForTest(t, time.Second, func() bool {
		bus.mu.Lock()
		defer bus.mu.Unlock()
		return len(bus.published) == 1
	})
	select {
	case response := <-stream.sent:
		t.Fatalf("HEALTHY UNKNOWN received an acknowledgement: %+v", response)
	case <-time.After(20 * time.Millisecond):
	}
	if delivery.acks.Load() != 0 {
		t.Fatalf("HEALTHY UNKNOWN acknowledged command delivery %d times", delivery.acks.Load())
	}
	cancel()
	<-done
}

func TestGatewayTerminalReceiptSurvivesEveryAckCrashWindow(t *testing.T) {
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	command.Event.TaskId = proto.String("durable-terminal-receipt")
	statusUpdate := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	failBrokerAck := true
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command, ack: func() error {
			if failBrokerAck {
				failBrokerAck = false
				return errors.New("broker ACK confirmation interrupted")
			}
			return nil
		}},
		identity: "stream:41",
	}
	bus := newTestTerminalReceiptBus(store)
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{delivery},
	}}

	store.saveErr = errors.New("receipt persistence interrupted")
	if receipt, err := gateway.persistStatusAndAckCommandReceipt(context.Background(), testNodeID, statusUpdate, pending, true, true); receipt != nil || grpcstatus.Code(err) != codes.Unavailable {
		t.Fatalf("persist crash = (%+v, %v), want unavailable without receipt", receipt, err)
	}
	if delivery.acks.Load() != 0 || len(pending) != 1 || store.count() != 0 || len(bus.published) != 1 {
		t.Fatalf("persist crash changed ownership: acks=%d pending=%d receipts=%d published=%d",
			delivery.acks.Load(), len(pending), store.count(), len(bus.published))
	}

	store.saveErr = nil
	receipt, err := gateway.persistStatusAndAckCommandReceipt(context.Background(), testNodeID, statusUpdate, pending, true, true)
	if receipt != nil || grpcstatus.Code(err) != codes.Unavailable || delivery.acks.Load() != 1 || len(pending) != 1 || store.count() != 1 {
		t.Fatalf("broker ACK crash = (%+v, %v), attempts=%d pending=%d receipts=%d",
			receipt, err, delivery.acks.Load(), len(pending), store.count())
	}
	receipt, err = gateway.persistStatusAndAckCommandReceipt(context.Background(), testNodeID, statusUpdate, pending, true, true)
	if err != nil || receipt == nil {
		t.Fatalf("terminal receipt retry = (%+v, %v)", receipt, err)
	}
	if delivery.acks.Load() != 2 || len(pending) != 0 || store.count() != 1 || len(bus.published) != 2 {
		t.Fatalf("receipt did not bridge broker ACK: acks=%d pending=%d receipts=%d published=%d",
			delivery.acks.Load(), len(pending), store.count(), len(bus.published))
	}

	failingBus := newTestTerminalReceiptBus(store)
	failingGateway := newCommandGateway(t, defaultFakeControl(), failingBus, nil)
	failingStream := &capturingBidiStream{
		ctx: context.Background(), sent: make(chan *agentv1.ConnectResponse, 1), sendErr: errors.New("ack send interrupted"),
	}
	failingReceived := make(chan connectReceive, 1)
	failingReceived <- connectReceive{request: &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{
			DeploymentStatus: proto.Clone(statusUpdate).(*agentv1.DeploymentStatus),
		},
	}}
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	err = failingGateway.serveSession(
		failingStream, failingReceived, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
		nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
		&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, true,
	)
	lease.Release()
	if err == nil || store.count() != 1 || store.deleteCount != 0 || len(failingBus.published) != 0 {
		t.Fatalf("failed send lost receipt: err=%v receipts=%d deletes=%d published=%d",
			err, store.count(), store.deleteCount, len(failingBus.published))
	}

	restartBus := newTestTerminalReceiptBus(store)
	restarted := newCommandGateway(t, defaultFakeControl(), restartBus, nil)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
	received := make(chan connectReceive, 1)
	received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{
			DeploymentStatus: proto.Clone(statusUpdate).(*agentv1.DeploymentStatus),
		},
	}}
	restartLease, err := NewMemorySessionCoordinator().Acquire(ctx, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- restarted.serveSession(
			stream, received, restartLease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, true,
		)
	}()
	var firstAck *agentv1.DeploymentStatusAck
	select {
	case response := <-stream.sent:
		firstAck = response.GetDeploymentStatusAck()
		if firstAck == nil || firstAck.StatusEventId != statusUpdate.Event.EventId || firstAck.PersistedTime == nil ||
			firstAck.PersistedTime.AsTime().UnixNano() != receipt.PersistedUnixNano {
			t.Fatalf("restarted receipt ACK = %+v, receipt=%+v", firstAck, receipt)
		}
	case <-time.After(time.Second):
		t.Fatal("restart did not resend the durable terminal receipt")
	}
	if store.count() != 1 || store.deleteCount != 0 || len(restartBus.published) != 0 {
		t.Fatalf("transport Send was treated as fsync proof: receipts=%d deletes=%d published=%d",
			store.count(), store.deleteCount, len(restartBus.published))
	}
	cancel()
	restartLease.Release()
	<-done

	confirmBus := newTestTerminalReceiptBus(store)
	confirmGateway := newCommandGateway(t, defaultFakeControl(), confirmBus, nil)
	confirmCtx, confirmCancel := context.WithCancel(context.Background())
	confirmStream := &capturingBidiStream{ctx: confirmCtx, sent: make(chan *agentv1.ConnectResponse, 1)}
	confirmReceived := make(chan connectReceive, 2)
	confirmReceived <- connectReceive{request: &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{
			DeploymentStatus: proto.Clone(statusUpdate).(*agentv1.DeploymentStatus),
		},
	}}
	confirmLease, err := NewMemorySessionCoordinator().Acquire(confirmCtx, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	confirmDone := make(chan error, 1)
	go func() {
		confirmDone <- confirmGateway.serveSession(
			confirmStream, confirmReceived, confirmLease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, true,
		)
	}()
	var replayedAck *agentv1.DeploymentStatusAck
	select {
	case response := <-confirmStream.sent:
		replayedAck = response.GetDeploymentStatusAck()
		if !proto.Equal(firstAck, replayedAck) {
			t.Fatalf("reconnect ACK changed: first=%+v replayed=%+v", firstAck, replayedAck)
		}
	case <-time.After(time.Second):
		t.Fatal("reconnect did not replay the exact durable ACK")
	}
	confirmReceived <- connectReceive{request: &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 3, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatusAckReceipt{DeploymentStatusAckReceipt: &agentv1.DeploymentStatusAckReceipt{
			StatusEventId: replayedAck.StatusEventId, DeploymentId: replayedAck.DeploymentId, Attempt: replayedAck.Attempt,
			ConfigVersionId: replayedAck.ConfigVersionId, TransitionSequence: replayedAck.TransitionSequence,
			PersistedTime:   timestamppb.New(replayedAck.PersistedTime.AsTime()),
			PublishedStream: replayedAck.PublishedStream, PublishedSequence: replayedAck.PublishedSequence,
		}},
	}}
	waitForTest(t, time.Second, func() bool { return store.confirmedCount() == 1 })
	if store.count() != 1 || store.deleteCount != 0 || len(confirmBus.published) != 0 {
		t.Fatalf("Agent confirmation was not retained durably: receipts=%d confirmations=%d deletes=%d published=%d",
			store.count(), store.confirmedCount(), store.deleteCount, len(confirmBus.published))
	}
	confirmCancel()
	confirmLease.Release()
	<-confirmDone

	mismatchBus := newTestTerminalReceiptBus(store)
	mismatchGateway := newCommandGateway(t, defaultFakeControl(), mismatchBus, nil)
	mismatchCtx, mismatchCancel := context.WithCancel(context.Background())
	mismatchStream := &capturingBidiStream{ctx: mismatchCtx, sent: make(chan *agentv1.ConnectResponse, 1)}
	mismatchReceived := make(chan connectReceive, 1)
	mismatchedReceipt := &agentv1.DeploymentStatusAckReceipt{
		StatusEventId: replayedAck.StatusEventId, DeploymentId: replayedAck.DeploymentId, Attempt: replayedAck.Attempt,
		ConfigVersionId: replayedAck.ConfigVersionId, TransitionSequence: replayedAck.TransitionSequence + 1,
		PersistedTime:   timestamppb.New(replayedAck.PersistedTime.AsTime()),
		PublishedStream: replayedAck.PublishedStream, PublishedSequence: replayedAck.PublishedSequence,
	}
	mismatchReceived <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatusAckReceipt{DeploymentStatusAckReceipt: mismatchedReceipt},
	}}
	mismatchLease, err := NewMemorySessionCoordinator().Acquire(mismatchCtx, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	err = mismatchGateway.serveSession(
		mismatchStream, mismatchReceived, mismatchLease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
		nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
		&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, true,
	)
	mismatchCancel()
	mismatchLease.Release()
	if grpcstatus.Code(err) != codes.FailedPrecondition || store.count() != 1 || store.confirmedCount() != 1 {
		t.Fatalf("mismatched confirmation replay = %v, receipts=%d confirmations=%d",
			err, store.count(), store.confirmedCount())
	}

	postCrashBus := newTestTerminalReceiptBus(store)
	postCrashGateway := newCommandGateway(t, defaultFakeControl(), postCrashBus, nil)
	postCrashCtx, postCrashCancel := context.WithCancel(context.Background())
	postCrashStream := &capturingBidiStream{ctx: postCrashCtx, sent: make(chan *agentv1.ConnectResponse, 4)}
	postCrashReceived := make(chan connectReceive, 3)
	exactReceipt := &agentv1.DeploymentStatusAckReceipt{
		StatusEventId: replayedAck.StatusEventId, DeploymentId: replayedAck.DeploymentId, Attempt: replayedAck.Attempt,
		ConfigVersionId: replayedAck.ConfigVersionId, TransitionSequence: replayedAck.TransitionSequence,
		PersistedTime:   timestamppb.New(replayedAck.PersistedTime.AsTime()),
		PublishedStream: replayedAck.PublishedStream, PublishedSequence: replayedAck.PublishedSequence,
	}
	postCrashReceived <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatusAckReceipt{DeploymentStatusAckReceipt: exactReceipt},
	}}
	postCrashLease, err := NewMemorySessionCoordinator().Acquire(postCrashCtx, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	postCrashDone := make(chan error, 1)
	go func() {
		postCrashDone <- postCrashGateway.serveSession(
			postCrashStream, postCrashReceived, postCrashLease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, true,
		)
	}()
	waitForTest(t, time.Second, func() bool {
		epoch, sequence := store.confirmedSession()
		return epoch == postCrashLease.Epoch() && sequence == 2
	})
	var heartbeatCausationID string
	for heartbeatSequence, streamSequence := range []uint64{3, 4} {
		heartbeat := validHeartbeatRequest(postCrashLease.Epoch(), uint64(heartbeatSequence+1), streamSequence, uuid.NewString(), uuid.NewString())
		heartbeat.GetHeartbeat().ActiveConfigIdentityCapability = testActiveIdentityCapability()
		if heartbeatCausationID != "" {
			heartbeat.GetHeartbeat().Event.CausationId = proto.String(heartbeatCausationID)
		}
		postCrashReceived <- connectReceive{request: heartbeat}
		select {
		case response := <-postCrashStream.sent:
			if response.GetHeartbeatAck() == nil {
				t.Fatalf("causal heartbeat response = %+v", response)
			}
		case <-time.After(time.Second):
			t.Fatal("causal heartbeat was not acknowledged")
		}
		heartbeatCausationID = heartbeat.GetHeartbeat().Event.EventId
		if streamSequence == 3 && (store.count() != 1 || store.confirmedCount() != 1) {
			t.Fatalf("first heartbeat removed receipt proof: receipts=%d confirmations=%d", store.count(), store.confirmedCount())
		}
	}
	waitForTest(t, time.Second, func() bool { return store.count() == 0 && store.confirmedCount() == 0 })
	if store.deleteCount != 1 || store.confirmationDeleteCount != 1 {
		t.Fatalf("causal cleanup = receipt deletes:%d confirmation deletes:%d", store.deleteCount, store.confirmationDeleteCount)
	}
	postCrashCancel()
	postCrashLease.Release()
	<-postCrashDone

	afterCompactionBus := newTestTerminalReceiptBus(store)
	afterCompaction := newCommandGateway(t, defaultFakeControl(), afterCompactionBus, nil)
	replayed, err := afterCompaction.persistStatusAndAckCommandReceipt(
		context.Background(), testNodeID, proto.Clone(statusUpdate).(*agentv1.DeploymentStatus), pendingCommandSet{}, true, true,
	)
	if err != nil || replayed != nil || store.deleteCount != 1 {
		t.Fatalf("compacted receipt replay = (%+v, %v), deletes=%d", replayed, err, store.deleteCount)
	}
}

func TestGatewayLegacyTerminalAckOutboxSurvivesReconnect(t *testing.T) {
	for _, test := range []struct {
		name                   string
		agentOffersReceipt     bool
		gatewaySupportsReceipt bool
	}{
		{name: "Agent19Gateway18", agentOffersReceipt: true, gatewaySupportsReceipt: false},
		{name: "Gateway19Agent18", agentOffersReceipt: false, gatewaySupportsReceipt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.agentOffersReceipt && test.gatewaySupportsReceipt {
				t.Fatal("test must exercise a capability-18-only negotiated session")
			}
			store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
			command := validDeploymentCommand()
			command.ConfigVersionId = uuid.NewString()
			command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
			command.Event.TaskId = proto.String("legacy-terminal-ack-outbox")
			terminal := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
			delivery := &testTerminalReceiptDelivery{
				fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:legacy-ack-outbox",
			}
			bus := newTestTerminalReceiptBus(store)
			gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
			pending := pendingCommandSet{commandKey(command): {
				command: command, deliveries: []CommandDelivery{delivery},
			}}
			receipt, err := gateway.persistStatusAndAckCommandReceipt(
				context.Background(), testNodeID, terminal, pending, true, false,
			)
			if err != nil || receipt == nil {
				t.Fatalf("legacy terminal persistence = (%+v, %v)", receipt, err)
			}
			if delivery.acks.Load() != 1 || len(pending) != 0 || store.count() != 1 || len(bus.published) != 1 {
				t.Fatalf("legacy terminal ownership = ACKs:%d pending:%d receipts:%d publications:%d",
					delivery.acks.Load(), len(pending), store.count(), len(bus.published))
			}
			exactAck := receipt.deploymentStatusAck()
			coordinator := NewMemorySessionCoordinator()

			beforeSendBus := newTestTerminalReceiptBus(store)
			beforeSendGateway := newCommandGateway(t, defaultFakeControl(), beforeSendBus, nil)
			beforeSendStream := &capturingBidiStream{
				ctx: context.Background(), sent: make(chan *agentv1.ConnectResponse, 1), sendErr: errors.New("disconnect before terminal ACK send"),
			}
			beforeSendReceived := make(chan connectReceive, 1)
			beforeSendReceived <- connectReceive{request: &agentv1.ConnectRequest{
				Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
				Payload: &agentv1.ConnectRequest_DeploymentStatus{
					DeploymentStatus: proto.Clone(terminal).(*agentv1.DeploymentStatus),
				},
			}}
			beforeSendLease, err := coordinator.Acquire(context.Background(), testNodeID)
			if err != nil {
				t.Fatal(err)
			}
			err = beforeSendGateway.serveSession(
				beforeSendStream, beforeSendReceived, beforeSendLease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
				nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
				&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, false,
			)
			beforeSendLease.Release()
			if err == nil || store.count() != 1 || store.confirmedCount() != 1 || store.deleteCount != 0 || len(beforeSendBus.published) != 0 {
				t.Fatalf("pre-send disconnect state = err:%v receipts:%d confirmations:%d deletes:%d publications:%d",
					err, store.count(), store.confirmedCount(), store.deleteCount, len(beforeSendBus.published))
			}

			sentBus := newTestTerminalReceiptBus(store)
			sentGateway := newCommandGateway(t, defaultFakeControl(), sentBus, nil)
			sentCtx, sentCancel := context.WithCancel(context.Background())
			sentStream := &capturingBidiStream{ctx: sentCtx, sent: make(chan *agentv1.ConnectResponse, 1)}
			sentReceived := make(chan connectReceive, 1)
			sentReceived <- connectReceive{request: &agentv1.ConnectRequest{
				Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
				Payload: &agentv1.ConnectRequest_DeploymentStatus{
					DeploymentStatus: proto.Clone(terminal).(*agentv1.DeploymentStatus),
				},
			}}
			sentLease, err := coordinator.Acquire(sentCtx, testNodeID)
			if err != nil {
				t.Fatal(err)
			}
			sentDone := make(chan error, 1)
			go func() {
				sentDone <- sentGateway.serveSession(
					sentStream, sentReceived, sentLease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
					nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
					&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, false,
				)
			}()
			select {
			case response := <-sentStream.sent:
				if !proto.Equal(response.GetDeploymentStatusAck(), exactAck) {
					t.Fatalf("sent-but-unpersisted ACK = %+v, want %+v", response.GetDeploymentStatusAck(), exactAck)
				}
			case <-time.After(time.Second):
				t.Fatal("durable legacy ACK was not sent")
			}
			if store.count() != 1 || store.confirmedCount() != 1 || store.deleteCount != 0 || len(sentBus.published) != 0 {
				t.Fatalf("Send was treated as durable client proof: receipts:%d confirmations:%d deletes:%d publications:%d",
					store.count(), store.confirmedCount(), store.deleteCount, len(sentBus.published))
			}
			sentCancel()
			sentLease.Release()
			<-sentDone

			restartBus := newTestTerminalReceiptBus(store)
			restarted := newCommandGateway(t, defaultFakeControl(), restartBus, nil)
			restartCtx, restartCancel := context.WithCancel(context.Background())
			restartStream := &capturingBidiStream{ctx: restartCtx, sent: make(chan *agentv1.ConnectResponse, 4)}
			restartReceived := make(chan connectReceive, 3)
			restartReceived <- connectReceive{request: &agentv1.ConnectRequest{
				Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
				Payload: &agentv1.ConnectRequest_DeploymentStatus{
					DeploymentStatus: proto.Clone(terminal).(*agentv1.DeploymentStatus),
				},
			}}
			restartLease, err := coordinator.Acquire(restartCtx, testNodeID)
			if err != nil {
				t.Fatal(err)
			}
			restartDone := make(chan error, 1)
			go func() {
				restartDone <- restarted.serveSession(
					restartStream, restartReceived, restartLease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
					nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
					&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, false,
				)
			}()
			select {
			case response := <-restartStream.sent:
				if !proto.Equal(response.GetDeploymentStatusAck(), exactAck) {
					t.Fatalf("restart ACK = %+v, want %+v", response.GetDeploymentStatusAck(), exactAck)
				}
			case <-time.After(time.Second):
				t.Fatal("Gateway restart did not replay the exact durable legacy ACK")
			}
			var heartbeatCausationID string
			for heartbeatSequence, streamSequence := range []uint64{3, 4} {
				heartbeat := validHeartbeatRequest(restartLease.Epoch(), uint64(heartbeatSequence+1), streamSequence, uuid.NewString(), uuid.NewString())
				heartbeat.GetHeartbeat().ActiveConfigIdentityCapability = testActiveIdentityCapability()
				if heartbeatCausationID != "" {
					heartbeat.GetHeartbeat().Event.CausationId = proto.String(heartbeatCausationID)
				}
				restartReceived <- connectReceive{request: heartbeat}
				select {
				case response := <-restartStream.sent:
					if response.GetHeartbeatAck() == nil {
						t.Fatalf("legacy causal heartbeat response = %+v", response)
					}
				case <-time.After(time.Second):
					t.Fatal("legacy causal heartbeat was not acknowledged")
				}
				heartbeatCausationID = heartbeat.GetHeartbeat().Event.EventId
				if streamSequence == 3 && (store.count() != 1 || store.confirmedCount() != 1) {
					t.Fatalf("first causal heartbeat cleaned legacy outbox early: receipts:%d confirmations:%d",
						store.count(), store.confirmedCount())
				}
			}
			waitForTest(t, time.Second, func() bool { return store.count() == 0 && store.confirmedCount() == 0 })
			if store.deleteCount != 1 || store.confirmationDeleteCount != 1 || delivery.acks.Load() != 1 || len(bus.published) != 1 || len(restartBus.published) != 0 {
				t.Fatalf("legacy outbox cleanup = receipt deletes:%d confirmation deletes:%d delivery ACKs:%d publications:%d replay publications:%d",
					store.deleteCount, store.confirmationDeleteCount, delivery.acks.Load(), len(bus.published), len(restartBus.published))
			}
			restartCancel()
			restartLease.Release()
			<-restartDone
		})
	}
}

func TestGatewayLegacyTerminalAckOutboxRequiresCausalHeartbeatProof(t *testing.T) {
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	terminal := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:legacy-causal-proof",
	}
	receipt, err := newTerminalCommandReceipt(testNodeID, command, terminal, []CommandDelivery{delivery}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := &terminalCommandReceiptConfirmation{
		Version: terminalCommandReceiptConfirmationVersion, Receipt: *receipt,
		SessionEpoch: 7, ReceiptStreamSequence: 2,
	}
	store := &testTerminalReceiptStore{
		receipts: map[deploymentKey]*terminalCommandReceipt{receipt.deploymentKey(): receipt},
		confirmations: map[deploymentKey]*terminalCommandReceiptConfirmation{
			receipt.deploymentKey(): confirmation,
		},
	}
	gateway := newCommandGateway(t, defaultFakeControl(), newTestTerminalReceiptBus(store), nil)
	pending := map[deploymentKey]bool{receipt.deploymentKey(): false}

	firstHeartbeat := validHeartbeatRequest(7, 1, 3, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	if err := gateway.advanceTerminalCommandReceiptConfirmations(context.Background(), testNodeID, 7, 3, firstHeartbeat, pending); err != nil {
		t.Fatal(err)
	}
	secondHeartbeat := validHeartbeatRequest(7, 2, 4, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	if err := gateway.advanceTerminalCommandReceiptConfirmations(context.Background(), testNodeID, 7, 4, secondHeartbeat, pending); err != nil {
		t.Fatal(err)
	}
	if store.count() != 1 || store.confirmedCount() != 1 || store.deleteCount != 0 {
		t.Fatalf("pipelined heartbeat requests proved response processing: receipts=%d confirmations=%d deletes=%d",
			store.count(), store.confirmedCount(), store.deleteCount)
	}
	thirdHeartbeat := validHeartbeatRequest(7, 3, 5, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	thirdHeartbeat.Event.CausationId = proto.String(secondHeartbeat.Event.EventId)
	if err := gateway.advanceTerminalCommandReceiptConfirmations(context.Background(), testNodeID, 7, 5, thirdHeartbeat, pending); err != nil {
		t.Fatal(err)
	}
	if store.count() != 0 || store.confirmedCount() != 0 || store.deleteCount != 1 || store.confirmationDeleteCount != 1 {
		t.Fatalf("causal heartbeat proof did not clean exact outbox: receipts=%d confirmations=%d deletes=%d confirmation_deletes=%d",
			store.count(), store.confirmedCount(), store.deleteCount, store.confirmationDeleteCount)
	}
}

func TestGatewayRecoveredLegacyTerminalAckOutboxWaitsForStatusReplay(t *testing.T) {
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	terminal := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:legacy-restart-proof",
	}
	receipt, err := newTerminalCommandReceipt(testNodeID, command, terminal, []CommandDelivery{delivery}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	store := &testTerminalReceiptStore{
		receipts: map[deploymentKey]*terminalCommandReceipt{receipt.deploymentKey(): receipt},
		confirmations: map[deploymentKey]*terminalCommandReceiptConfirmation{
			receipt.deploymentKey(): {
				Version: terminalCommandReceiptConfirmationVersion, Receipt: *receipt,
				SessionEpoch: 6, ReceiptStreamSequence: 2, HeartbeatBarrierSequence: 3,
			},
		},
	}
	gateway := newCommandGateway(t, defaultFakeControl(), newTestTerminalReceiptBus(store), nil)
	pending := map[deploymentKey]bool{receipt.deploymentKey(): true}

	firstHeartbeat := validHeartbeatRequest(7, 1, 2, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	if err := gateway.advanceTerminalCommandReceiptConfirmations(context.Background(), testNodeID, 7, 2, firstHeartbeat, pending); err != nil {
		t.Fatal(err)
	}
	secondHeartbeat := validHeartbeatRequest(7, 2, 3, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	secondHeartbeat.Event.CausationId = proto.String(firstHeartbeat.Event.EventId)
	if err := gateway.advanceTerminalCommandReceiptConfirmations(context.Background(), testNodeID, 7, 3, secondHeartbeat, pending); err != nil {
		t.Fatal(err)
	}
	if store.count() != 1 || store.confirmedCount() != 1 || store.deleteCount != 0 {
		t.Fatalf("restart heartbeat requests replaced the missing terminal ACK replay: receipts=%d confirmations=%d deletes=%d",
			store.count(), store.confirmedCount(), store.deleteCount)
	}
	if err := gateway.confirmTerminalCommandReceipt(
		context.Background(), testNodeID, receipt.deploymentStatusAckReceipt(), 7, 4, false,
	); err != nil {
		t.Fatal(err)
	}
	pending[receipt.deploymentKey()] = false
	barrier := validHeartbeatRequest(7, 3, 5, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	if err := gateway.advanceTerminalCommandReceiptConfirmations(context.Background(), testNodeID, 7, 5, barrier, pending); err != nil {
		t.Fatal(err)
	}
	proof := validHeartbeatRequest(7, 4, 6, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	proof.Event.CausationId = proto.String(barrier.Event.EventId)
	if err := gateway.advanceTerminalCommandReceiptConfirmations(context.Background(), testNodeID, 7, 6, proof, pending); err != nil {
		t.Fatal(err)
	}
	if store.count() != 0 || store.confirmedCount() != 0 || store.deleteCount != 1 || store.confirmationDeleteCount != 1 {
		t.Fatalf("replayed terminal ACK did not restore causal cleanup: receipts=%d confirmations=%d deletes=%d confirmation_deletes=%d",
			store.count(), store.confirmedCount(), store.deleteCount, store.confirmationDeleteCount)
	}
}

func TestTerminalCommandReceiptMessageIdentityIgnoresPersistenceTime(t *testing.T) {
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	statusUpdate := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:73",
	}
	first, err := newTerminalCommandReceipt(testNodeID, command, statusUpdate, []CommandDelivery{delivery}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	second := *first
	second.PersistedUnixNano = time.Unix(200, 0).UnixNano()
	subject := terminalCommandReceiptSubject("cdnca.agent.deployment-status", testNodeID, first.deploymentKey())
	firstWire, firstID, err := terminalCommandReceiptWireIdentity(subject, first)
	if err != nil {
		t.Fatal(err)
	}
	secondWire, secondID, err := terminalCommandReceiptWireIdentity(subject, &second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstWire, secondWire) || firstID != secondID {
		t.Fatalf("wall time changed receipt identity: wire_equal=%t first=%q second=%q", bytes.Equal(firstWire, secondWire), firstID, secondID)
	}
	_, otherSubjectID, err := terminalCommandReceiptWireIdentity(subject+".other", first)
	if err != nil {
		t.Fatal(err)
	}
	if otherSubjectID == firstID {
		t.Fatal("receipt Msg-Id did not bind the exact subject")
	}
	confirmation := &terminalCommandReceiptConfirmation{
		Version: terminalCommandReceiptConfirmationVersion, Receipt: *first,
		SessionEpoch: 7, ReceiptStreamSequence: 2,
	}
	confirmationSubject := terminalCommandReceiptConfirmationSubject("cdnca.agent.deployment-status", testNodeID, first.deploymentKey())
	confirmationWire, confirmationID, err := terminalCommandReceiptConfirmationWireIdentity(confirmationSubject, confirmation, 41)
	if err != nil {
		t.Fatal(err)
	}
	retryWire, retryID, err := terminalCommandReceiptConfirmationWireIdentity(confirmationSubject, confirmation, 41)
	if err != nil {
		t.Fatal(err)
	}
	_, nextTransitionID, err := terminalCommandReceiptConfirmationWireIdentity(confirmationSubject, confirmation, 42)
	if err != nil {
		t.Fatal(err)
	}
	decodedConfirmation, err := decodeTerminalCommandReceiptConfirmation(confirmationWire)
	if err != nil || *decodedConfirmation != *confirmation || !bytes.Equal(confirmationWire, retryWire) || confirmationID != retryID {
		t.Fatalf("confirmation retry identity = decoded:%+v err:%v wire_equal:%t id_equal:%t",
			decodedConfirmation, err, bytes.Equal(confirmationWire, retryWire), confirmationID == retryID)
	}
	if nextTransitionID == confirmationID {
		t.Fatal("confirmation Msg-Id did not bind its durable predecessor sequence")
	}
}

func TestJetStreamTerminalReceiptSaveLoadConflictAndReopen(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ACTIVE_IDENTITY_RECEIPT_" + suffix
	statusPrefix := "cdnca.test." + suffix + ".status"

	admin := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(admin.Close)
	js, err := admin.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{statusPrefix + ".terminal-receipt.*.*"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(streamName) })

	connection := connectActiveIdentityNATS(t, natsURL)
	busConfig := DefaultNATSCommandBusConfig()
	busConfig.StatusStream = streamName
	busConfig.StatusSubjectPrefix = statusPrefix
	busConfig.OperationTimeout = 2 * time.Second
	bus, err := NewNATSCommandBus(connection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	receipt := activeIdentityNATSConfirmation(t, testNodeID, "receipt-save-load").Receipt
	persisted, err := bus.saveTerminalCommandReceipt(t.Context(), &receipt)
	if err != nil || persisted == nil || !sameTerminalCommandReceiptBinding(persisted, &receipt) {
		t.Fatalf("save terminal receipt = (%+v, %v)", persisted, err)
	}
	loaded, sequence, err := bus.loadTerminalCommandReceiptMessage(t.Context(), testNodeID, receipt.deploymentKey())
	if err != nil || loaded == nil || sequence == 0 || !sameTerminalCommandReceiptBinding(loaded, &receipt) {
		t.Fatalf("load terminal receipt = (%+v, %d, %v)", loaded, sequence, err)
	}
	subject := terminalCommandReceiptSubject(statusPrefix, testNodeID, receipt.deploymentKey())
	message, err := js.GetMsg(streamName, sequence)
	wire, messageID, identityErr := terminalCommandReceiptWireIdentity(subject, &receipt)
	if err != nil || identityErr != nil || message == nil || message.Subject != subject ||
		!bytes.Equal(message.Data, wire) || message.Header.Get(nats.MsgIdHdr) != messageID {
		t.Fatalf("terminal receipt wire identity changed: message=%+v get_err=%v identity_err=%v", message, err, identityErr)
	}
	if _, err := bus.saveTerminalCommandReceipt(t.Context(), &receipt); err != nil {
		t.Fatal(err)
	}
	_, retrySequence, err := bus.loadTerminalCommandReceiptMessage(t.Context(), testNodeID, receipt.deploymentKey())
	if err != nil || retrySequence != sequence {
		t.Fatalf("idempotent terminal receipt retry changed sequence = (%d, %v), want %d", retrySequence, err, sequence)
	}
	conflicting := receipt
	conflicting.StatusSHA256 = strings.Repeat("f", 64)
	if conflicting.StatusSHA256 == receipt.StatusSHA256 {
		conflicting.StatusSHA256 = strings.Repeat("e", 64)
	}
	if _, err := bus.saveTerminalCommandReceipt(t.Context(), &conflicting); err == nil {
		t.Fatal("conflicting terminal receipt replaced durable state")
	}

	connection.Close()
	reopenedConnection := connectActiveIdentityNATS(t, natsURL)
	defer reopenedConnection.Close()
	reopenedBus, err := NewNATSCommandBus(reopenedConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopenedBus.loadTerminalCommandReceipt(t.Context(), testNodeID, receipt.deploymentKey())
	if err != nil || recovered == nil || !sameTerminalCommandReceiptBinding(recovered, &receipt) {
		t.Fatalf("reopened terminal receipt = (%+v, %v)", recovered, err)
	}
}

func TestJetStreamTerminalConfirmationCASRecoveryAndReopen(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ACTIVE_IDENTITY_STATUS_" + suffix
	statusPrefix := "cdnca.test." + suffix + ".status"

	admin := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(admin.Close)
	js, err := admin.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(streamName) })

	firstConnection := connectActiveIdentityNATS(t, natsURL)
	secondConnection := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(firstConnection.Close)
	t.Cleanup(secondConnection.Close)
	busConfig := DefaultNATSCommandBusConfig()
	busConfig.StatusStream = streamName
	busConfig.StatusSubjectPrefix = statusPrefix
	busConfig.OperationTimeout = 2 * time.Second
	firstBus, err := NewNATSCommandBus(firstConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	secondBus, err := NewNATSCommandBus(secondConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}

	firstConfirmation := activeIdentityNATSConfirmation(t, testNodeID, "concurrent-one")
	secondConfirmation := activeIdentityNATSConfirmation(t, testNodeID, "concurrent-two")
	indexSubject := terminalCommandReceiptConfirmationIndexSubject(statusPrefix, testNodeID)
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	firstWriter := *firstBus
	firstWriter.js = &blockingPublishJetStream{
		JetStreamContext: firstBus.js, subject: indexSubject, arrived: arrived, release: release,
	}
	secondWriter := *secondBus
	secondWriter.js = &blockingPublishJetStream{
		JetStreamContext: secondBus.js, subject: indexSubject, arrived: arrived, release: release,
	}
	type saveResult struct {
		confirmation *terminalCommandReceiptConfirmation
		persisted    *terminalCommandReceiptConfirmation
		err          error
	}
	results := make(chan saveResult, 2)
	go func() {
		persisted, saveErr := firstWriter.saveTerminalCommandReceiptConfirmation(t.Context(), firstConfirmation)
		results <- saveResult{confirmation: firstConfirmation, persisted: persisted, err: saveErr}
	}()
	go func() {
		persisted, saveErr := secondWriter.saveTerminalCommandReceiptConfirmation(t.Context(), secondConfirmation)
		results <- saveResult{confirmation: secondConfirmation, persisted: persisted, err: saveErr}
	}()
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent confirmation writers did not reach the index CAS barrier")
		}
	}
	close(release)
	var winner, loser saveResult
	for range 2 {
		result := <-results
		if result.err == nil {
			if winner.confirmation != nil {
				t.Fatal("both concurrent confirmation writers bypassed subject CAS")
			}
			winner = result
		} else {
			loser = result
		}
	}
	if winner.confirmation == nil || loser.confirmation == nil || winner.persisted == nil || *winner.persisted != *winner.confirmation {
		t.Fatalf("concurrent CAS results = winner:%+v loser:%+v", winner, loser)
	}
	index, _, err := firstBus.loadTerminalCommandReceiptConfirmationIndexMessage(t.Context(), testNodeID)
	if err != nil || index == nil || len(index.Entries) != 1 || index.Entries[0].deploymentKey() != winner.confirmation.deploymentKey() {
		t.Fatalf("CAS conflict changed the current index = (%+v, %v)", index, err)
	}
	if current, err := firstBus.loadTerminalCommandReceiptConfirmation(t.Context(), testNodeID, loser.confirmation.deploymentKey()); err != nil || current != nil {
		t.Fatalf("losing writer created confirmation state = (%+v, %v)", current, err)
	}
	loser.persisted, loser.err = secondBus.saveTerminalCommandReceiptConfirmation(t.Context(), loser.confirmation)
	if loser.err != nil || loser.persisted == nil || *loser.persisted != *loser.confirmation {
		t.Fatalf("CAS loser retry = (%+v, %v)", loser.persisted, loser.err)
	}

	current, currentSequence, currentPrevious, err := firstBus.loadTerminalCommandReceiptConfirmationMessage(
		t.Context(), testNodeID, winner.confirmation.deploymentKey(),
	)
	if err != nil || current == nil || *current != *winner.confirmation || currentSequence == 0 {
		t.Fatalf("load current confirmation = (%+v, %d, %d, %v)", current, currentSequence, currentPrevious, err)
	}
	confirmationSubject := terminalCommandReceiptConfirmationSubject(statusPrefix, testNodeID, current.deploymentKey())
	assertTerminalConfirmationMessageIdentity(t, js, streamName, confirmationSubject, current, currentSequence, currentPrevious)
	updated := *current
	updated.HeartbeatBarrierSequence = updated.ReceiptStreamSequence + 1
	updated.HeartbeatBarrierEventID = uuid.NewString()
	persisted, err := firstBus.saveTerminalCommandReceiptConfirmation(t.Context(), &updated)
	if err != nil || persisted == nil || *persisted != updated {
		t.Fatalf("confirmation update = (%+v, %v)", persisted, err)
	}
	updatedCurrent, updatedSequence, updatedPrevious, err := firstBus.loadTerminalCommandReceiptConfirmationMessage(
		t.Context(), testNodeID, updated.deploymentKey(),
	)
	if err != nil || updatedCurrent == nil || *updatedCurrent != updated || updatedPrevious != currentSequence {
		t.Fatalf("predecessor-bound confirmation = (%+v, %d, %d, %v)", updatedCurrent, updatedSequence, updatedPrevious, err)
	}
	assertTerminalConfirmationMessageIdentity(t, js, streamName, confirmationSubject, updatedCurrent, updatedSequence, updatedPrevious)
	if message, err := js.GetMsg(streamName, currentSequence); err != nil || message == nil {
		t.Fatalf("confirmation predecessor was not retained as non-authoritative history: (%+v, %v)", message, err)
	}
	if _, err := firstBus.saveTerminalCommandReceiptConfirmation(t.Context(), &updated); err != nil {
		t.Fatal(err)
	}
	_, retrySequence, _, err := firstBus.loadTerminalCommandReceiptConfirmationMessage(t.Context(), testNodeID, updated.deploymentKey())
	if err != nil || retrySequence != updatedSequence {
		t.Fatalf("idempotent confirmation retry changed sequence = (%d, %v), want %d", retrySequence, err, updatedSequence)
	}

	conflicting := updated
	conflicting.Receipt.StatusSHA256 = strings.Repeat("f", 64)
	if _, err := secondBus.saveTerminalCommandReceiptConfirmation(t.Context(), &conflicting); err == nil {
		t.Fatal("conflicting confirmation replaced the current durable value")
	}
	preserved, _, _, err := firstBus.loadTerminalCommandReceiptConfirmationMessage(t.Context(), testNodeID, updated.deploymentKey())
	if err != nil || preserved == nil || *preserved != updated {
		t.Fatalf("confirmation conflict did not preserve current value = (%+v, %v)", preserved, err)
	}

	uncertain := updated
	uncertain.HeartbeatBarrierSequence++
	uncertain.HeartbeatBarrierEventID = uuid.NewString()
	confirmationInjected := make(chan struct{})
	uncertainWriter := *firstBus
	uncertainWriter.js = &uncertainPubAckJetStream{
		JetStreamContext: firstBus.js, subject: confirmationSubject, injected: confirmationInjected,
	}
	persisted, err = uncertainWriter.saveTerminalCommandReceiptConfirmation(t.Context(), &uncertain)
	if err != nil || persisted == nil || *persisted != uncertain {
		t.Fatalf("uncertain confirmation PubAck recovery = (%+v, %v)", persisted, err)
	}
	select {
	case <-confirmationInjected:
	default:
		t.Fatal("confirmation PubAck loss was not injected")
	}
	latest, latestSequence, latestPrevious, err := firstBus.loadTerminalCommandReceiptConfirmationMessage(
		t.Context(), testNodeID, uncertain.deploymentKey(),
	)
	if err != nil || latest == nil || *latest != uncertain || latestPrevious != updatedSequence {
		t.Fatalf("uncertain confirmation current value = (%+v, %d, %d, %v)", latest, latestSequence, latestPrevious, err)
	}
	assertTerminalConfirmationMessageIdentity(t, js, streamName, confirmationSubject, latest, latestSequence, latestPrevious)
	if message, err := js.GetMsg(streamName, updatedSequence); err != nil || message == nil {
		t.Fatalf("uncertain confirmation predecessor was not retained as non-authoritative history: (%+v, %v)", message, err)
	}

	indexBefore, indexSequenceBefore, err := firstBus.loadTerminalCommandReceiptConfirmationIndexMessage(t.Context(), testNodeID)
	if err != nil || indexBefore == nil || len(indexBefore.Entries) != 2 || indexSequenceBefore == 0 {
		t.Fatalf("index before uncertain write = (%+v, %d, %v)", indexBefore, indexSequenceBefore, err)
	}
	thirdConfirmation := activeIdentityNATSConfirmation(t, testNodeID, "uncertain-index")
	indexInjected := make(chan struct{})
	uncertainIndexWriter := *secondBus
	uncertainIndexWriter.js = &uncertainPubAckJetStream{
		JetStreamContext: secondBus.js, subject: indexSubject, injected: indexInjected,
	}
	thirdPersisted, err := uncertainIndexWriter.saveTerminalCommandReceiptConfirmation(t.Context(), thirdConfirmation)
	if err != nil || thirdPersisted == nil || *thirdPersisted != *thirdConfirmation {
		t.Fatalf("uncertain index PubAck recovery = (%+v, %v)", thirdPersisted, err)
	}
	select {
	case <-indexInjected:
	default:
		t.Fatal("index PubAck loss was not injected")
	}
	indexAfter, indexSequenceAfter, err := firstBus.loadTerminalCommandReceiptConfirmationIndexMessage(t.Context(), testNodeID)
	if err != nil || indexAfter == nil || len(indexAfter.Entries) != 3 || indexAfter.PreviousSequence != indexSequenceBefore {
		t.Fatalf("predecessor-bound index = (%+v, %d, %v)", indexAfter, indexSequenceAfter, err)
	}
	assertTerminalConfirmationIndexMessageIdentity(t, js, streamName, indexSubject, indexAfter, indexSequenceAfter)
	if message, err := js.GetMsg(streamName, indexSequenceBefore); err != nil || message == nil {
		t.Fatalf("index predecessor was not retained as non-authoritative history: (%+v, %v)", message, err)
	}

	firstConnection.Close()
	secondConnection.Close()
	reopenedConnection := connectActiveIdentityNATS(t, natsURL)
	defer reopenedConnection.Close()
	reopenedBus, err := NewNATSCommandBus(reopenedConnection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopenedBus.listTerminalCommandReceiptConfirmations(t.Context(), testNodeID, 3)
	if err != nil || len(recovered) != 3 {
		t.Fatalf("reopened confirmation recovery = (%+v, %v)", recovered, err)
	}
	want := map[deploymentKey]terminalCommandReceiptConfirmation{
		uncertain.deploymentKey():          uncertain,
		loser.confirmation.deploymentKey(): *loser.persisted,
		thirdConfirmation.deploymentKey():  *thirdConfirmation,
	}
	for _, confirmation := range recovered {
		expected, exists := want[confirmation.deploymentKey()]
		if !exists || expected != *confirmation {
			t.Fatalf("reopened confirmation changed = %+v", confirmation)
		}
		delete(want, confirmation.deploymentKey())
	}
	if len(want) != 0 {
		t.Fatalf("reopened confirmation recovery missed %d values", len(want))
	}
}

func TestJetStreamTerminalConfirmationCompactionDeindexesPredecessors(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ACTIVE_IDENTITY_COMPACTION_" + suffix
	statusPrefix := "cdnca.test." + suffix + ".status"

	connection := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(streamName) })

	config := DefaultNATSCommandBusConfig()
	config.StatusStream = streamName
	config.StatusSubjectPrefix = statusPrefix
	config.OperationTimeout = 2 * time.Second
	bus, err := NewNATSCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	confirmation := activeIdentityNATSConfirmation(t, testNodeID, "terminal-compaction")
	persisted, err := bus.saveTerminalCommandReceiptConfirmation(t.Context(), confirmation)
	if err != nil || persisted == nil || *persisted != *confirmation {
		t.Fatalf("initial confirmation = (%+v, %v)", persisted, err)
	}
	updated := *confirmation
	updated.HeartbeatBarrierSequence = confirmation.ReceiptStreamSequence + 1
	updated.HeartbeatBarrierEventID = uuid.NewString()
	persisted, err = bus.saveTerminalCommandReceiptConfirmation(t.Context(), &updated)
	if err != nil || persisted == nil || *persisted != updated {
		t.Fatalf("updated confirmation = (%+v, %v)", persisted, err)
	}
	_, updatedSequence, predecessorSequence, err := bus.loadTerminalCommandReceiptConfirmationMessage(
		t.Context(), testNodeID, updated.deploymentKey(),
	)
	if err != nil || updatedSequence == 0 || predecessorSequence == 0 {
		t.Fatalf("updated confirmation sequences = (%d, %d, %v)", updatedSequence, predecessorSequence, err)
	}

	if err := bus.deleteTerminalCommandReceiptConfirmation(t.Context(), &updated); err != nil {
		t.Fatalf("confirmation compaction = %v", err)
	}
	current, currentSequence, _, err := bus.loadTerminalCommandReceiptConfirmationMessage(t.Context(), testNodeID, updated.deploymentKey())
	if err != nil || current == nil || currentSequence != predecessorSequence {
		t.Fatalf("non-authoritative predecessor head = (%+v, %d, %v), want sequence %d", current, currentSequence, err, predecessorSequence)
	}
	index, _, err := bus.loadTerminalCommandReceiptConfirmationIndexMessage(t.Context(), testNodeID)
	if err != nil || index == nil || len(index.Entries) != 0 {
		t.Fatalf("compacted confirmation index = (%+v, %v)", index, err)
	}
	if recovered, err := bus.listTerminalCommandReceiptConfirmations(t.Context(), testNodeID, 1); err != nil || len(recovered) != 0 {
		t.Fatalf("compacted confirmation remained recoverable = (%+v, %v)", recovered, err)
	}
	if message, err := js.GetMsg(streamName, predecessorSequence); err != nil || message == nil {
		t.Fatalf("non-authoritative confirmation predecessor %d changed: (%+v, %v)", predecessorSequence, message, err)
	}
	if _, err := js.GetMsg(streamName, updatedSequence); !errors.Is(err, nats.ErrMsgNotFound) {
		t.Fatalf("authoritative confirmation head %d was not deleted: %v", updatedSequence, err)
	}
	if err := bus.deleteTerminalCommandReceiptConfirmation(t.Context(), &updated); err != nil {
		t.Fatalf("idempotent confirmation compaction = %v", err)
	}
}

func TestJetStreamTerminalConfirmationPredecessorBudgets(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ACTIVE_IDENTITY_BUDGET_" + suffix
	statusPrefix := "cdnca.test." + suffix + ".status"
	connection := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(streamName) })
	config := DefaultNATSCommandBusConfig()
	config.StatusStream = streamName
	config.StatusSubjectPrefix = statusPrefix
	config.MaxAckPending = 3
	config.OperationTimeout = 2 * time.Second
	bus, err := NewNATSCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}

	for _, index := range []bool{false, true} {
		name := "confirmation"
		if index {
			name = "index"
		}
		t.Run(name, func(t *testing.T) {
			for _, count := range []int{config.MaxAckPending, config.MaxAckPending + 1} {
				t.Run(fmt.Sprintf("history-%d", count), func(t *testing.T) {
					subject, predecessors, current := publishTerminalPredecessorHistory(t, js, statusPrefix, index, count)
					var err error
					if index {
						err = bus.deleteTerminalCommandReceiptConfirmationIndexPredecessors(t.Context(), subject, predecessors[len(predecessors)-1])
					} else {
						err = bus.deleteTerminalCommandReceiptConfirmationPredecessors(t.Context(), subject, predecessors[len(predecessors)-1])
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, sequence := range predecessors {
						if _, getErr := js.GetMsg(streamName, sequence); getErr != nil {
							t.Fatalf("predecessor validation changed sequence %d: %v", sequence, getErr)
						}
					}
					message, getErr := js.GetMsg(streamName, current)
					if getErr != nil || message == nil || message.Subject != subject {
						t.Fatalf("predecessor cleanup changed current value %d: (%+v, %v)", current, message, getErr)
					}
				})
			}
		})
	}
}

func TestJetStreamTerminalConfirmationPredecessorPartialDeleteRecovery(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ACTIVE_IDENTITY_DELETE_RECOVERY_" + suffix
	statusPrefix := "cdnca.test." + suffix + ".status"
	connection := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(streamName) })
	config := DefaultNATSCommandBusConfig()
	config.StatusStream = streamName
	config.StatusSubjectPrefix = statusPrefix
	config.MaxAckPending = 4
	config.OperationTimeout = 2 * time.Second

	for _, index := range []bool{false, true} {
		name := "confirmation"
		if index {
			name = "index"
		}
		t.Run(name, func(t *testing.T) {
			subject, predecessors, current := publishTerminalPredecessorHistory(t, js, statusPrefix, index, 3)
			bus, err := NewNATSCommandBus(connection, config)
			if err != nil {
				t.Fatal(err)
			}
			cleanup := bus.deleteTerminalCommandReceiptConfirmationPredecessors
			if index {
				cleanup = bus.deleteTerminalCommandReceiptConfirmationIndexPredecessors
			}
			if err := cleanup(t.Context(), subject, predecessors[len(predecessors)-1]); err != nil {
				t.Fatal(err)
			}
			reopenedConnection := connectActiveIdentityNATS(t, natsURL)
			t.Cleanup(reopenedConnection.Close)
			reopened, err := NewNATSCommandBus(reopenedConnection, config)
			if err != nil {
				t.Fatal(err)
			}
			cleanup = reopened.deleteTerminalCommandReceiptConfirmationPredecessors
			if index {
				cleanup = reopened.deleteTerminalCommandReceiptConfirmationIndexPredecessors
			}
			if err := cleanup(t.Context(), subject, predecessors[len(predecessors)-1]); err != nil {
				t.Fatalf("reopened predecessor validation failed: %v", err)
			}
			for _, sequence := range predecessors {
				if _, err := js.GetMsg(streamName, sequence); err != nil {
					t.Fatalf("reopened predecessor validation changed sequence %d: %v", sequence, err)
				}
			}
			if message, err := js.GetMsg(streamName, current); err != nil || message == nil || message.Subject != subject {
				t.Fatalf("partial-delete recovery changed current head: (%+v, %v)", message, err)
			}
		})
	}
}

func TestJetStreamTerminalConfirmationPredecessorCleanupDoesNotCrossStreamIncarnations(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	for _, index := range []bool{false, true} {
		name := "confirmation"
		if index {
			name = "index"
		}
		t.Run(name, func(t *testing.T) {
			suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
			streamName := "ACTIVE_IDENTITY_RECREATE_" + suffix
			statusPrefix := "cdnca.test." + suffix + ".status"
			connection := connectActiveIdentityNATS(t, natsURL)
			t.Cleanup(connection.Close)
			js, err := connection.JetStream(nats.MaxWait(2 * time.Second))
			if err != nil {
				t.Fatal(err)
			}
			streamConfig := &nats.StreamConfig{
				Name: streamName, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy,
				Storage: nats.FileStorage, Duplicates: time.Minute,
			}
			if _, err := js.AddStream(streamConfig); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = js.DeleteStream(streamName) })
			subject, predecessors, _ := publishTerminalPredecessorHistory(t, js, statusPrefix, index, 3)
			replacementConnection := connectActiveIdentityNATS(t, natsURL)
			t.Cleanup(replacementConnection.Close)
			replacementJS, err := replacementConnection.JetStream(nats.MaxWait(2 * time.Second))
			if err != nil {
				t.Fatal(err)
			}
			config := DefaultNATSCommandBusConfig()
			config.StatusStream = streamName
			config.StatusSubjectPrefix = statusPrefix
			config.MaxAckPending = 4
			config.OperationTimeout = 2 * time.Second
			bus, err := NewNATSCommandBus(connection, config)
			if err != nil {
				t.Fatal(err)
			}

			var replacement []byte
			bus.js = &recreatingStreamJetStream{
				JetStreamContext:   js,
				replacementContext: replacementJS,
				sequence:           predecessors[0],
				recreate: func() {
					if err := replacementJS.DeleteStream(streamName); err != nil {
						t.Fatal(err)
					}
					if _, err := replacementJS.AddStream(streamConfig); err != nil {
						t.Fatal(err)
					}
					replacement = []byte("different stream incarnation wire")
					message := nats.NewMsg(subject)
					message.Data = replacement
					message.Header.Set(nats.MsgIdHdr, "new-incarnation-message")
					ack, err := replacementJS.PublishMsg(message)
					if err != nil || ack == nil || ack.Sequence != predecessors[0] {
						t.Fatalf("publish reused stream sequence = (%+v, %v), want %d", ack, err, predecessors[0])
					}
				},
			}
			cleanup := bus.deleteTerminalCommandReceiptConfirmationPredecessors
			if index {
				cleanup = bus.deleteTerminalCommandReceiptConfirmationIndexPredecessors
			}
			if err := cleanup(t.Context(), subject, predecessors[len(predecessors)-1]); err != nil &&
				!strings.Contains(err.Error(), "stream store EOF") {
				t.Fatal(err)
			}
			assertReplacement := func() {
				message, err := js.GetMsg(streamName, predecessors[0])
				if err != nil || message == nil || !bytes.Equal(message.Data, replacement) {
					t.Fatalf("old stream cleanup authorization changed reused sequence: (%+v, %v)", message, err)
				}
			}
			assertReplacement()
			if err := cleanup(t.Context(), subject, predecessors[len(predecessors)-1]); err != nil {
				t.Fatalf("safe retry after stream replacement: %v", err)
			}
			assertReplacement()
		})
	}
}

func TestJetStreamTerminalConfirmationPredecessorsRejectWrongIdentityAndMessageID(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ACTIVE_IDENTITY_BINDING_" + suffix
	statusPrefix := "cdnca.test." + suffix + ".status"
	connection := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(streamName) })
	config := DefaultNATSCommandBusConfig()
	config.StatusStream = streamName
	config.StatusSubjectPrefix = statusPrefix
	config.OperationTimeout = 2 * time.Second
	bus, err := NewNATSCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}

	for _, index := range []bool{false, true} {
		for _, tamper := range []string{"identity", "message-id"} {
			name := "confirmation"
			if index {
				name = "index"
			}
			t.Run(name+"/"+tamper, func(t *testing.T) {
				nodeID := uuid.NewString()
				confirmation := activeIdentityNATSConfirmation(t, nodeID, "real-invalid-predecessor")
				subject := terminalCommandReceiptConfirmationSubject(statusPrefix, nodeID, confirmation.deploymentKey())
				if index {
					subject = terminalCommandReceiptConfirmationIndexSubject(statusPrefix, nodeID)
				}
				var predecessorWire []byte
				var predecessorID string
				if index {
					value := &terminalCommandReceiptConfirmationIndex{
						Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID,
					}
					if tamper == "identity" {
						value.NodeID = uuid.NewString()
					}
					predecessorWire, predecessorID, err = terminalCommandReceiptConfirmationIndexWireIdentity(subject, value)
				} else {
					value := confirmation
					if tamper == "identity" {
						value = activeIdentityNATSConfirmation(t, uuid.NewString(), "real-wrong-identity")
					}
					predecessorWire, predecessorID, err = terminalCommandReceiptConfirmationWireIdentity(subject, value, 0)
				}
				if err != nil {
					t.Fatal(err)
				}
				if tamper == "message-id" {
					predecessorID = "wrong-message-id"
				}
				predecessorMessage := nats.NewMsg(subject)
				predecessorMessage.Data = predecessorWire
				predecessorMessage.Header.Set(nats.MsgIdHdr, predecessorID)
				predecessorAck, err := js.PublishMsg(predecessorMessage)
				if err != nil || predecessorAck == nil || predecessorAck.Sequence == 0 {
					t.Fatalf("publish invalid predecessor = (%+v, %v)", predecessorAck, err)
				}
				var currentWire []byte
				var currentID string
				if index {
					currentWire, currentID, err = terminalCommandReceiptConfirmationIndexWireIdentity(subject, &terminalCommandReceiptConfirmationIndex{
						Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID,
						PreviousSequence: predecessorAck.Sequence,
					})
				} else {
					currentWire, currentID, err = terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, predecessorAck.Sequence)
				}
				if err != nil {
					t.Fatal(err)
				}
				currentMessage := nats.NewMsg(subject)
				currentMessage.Data = currentWire
				currentMessage.Header.Set(nats.MsgIdHdr, currentID)
				currentAck, err := js.PublishMsg(currentMessage)
				if err != nil || currentAck == nil || currentAck.Sequence == 0 {
					t.Fatalf("publish current value = (%+v, %v)", currentAck, err)
				}
				if index {
					err = bus.deleteTerminalCommandReceiptConfirmationIndexPredecessors(t.Context(), subject, predecessorAck.Sequence)
				} else {
					err = bus.deleteTerminalCommandReceiptConfirmationPredecessors(t.Context(), subject, predecessorAck.Sequence)
				}
				if err == nil {
					t.Fatal("predecessor cleanup accepted invalid embedded identity or Msg-Id")
				}
				for _, sequence := range []uint64{predecessorAck.Sequence, currentAck.Sequence} {
					if _, getErr := js.GetMsg(streamName, sequence); getErr != nil {
						t.Fatalf("fail-closed cleanup changed sequence %d: %v", sequence, getErr)
					}
				}
			})
		}
	}
}

func TestJetStreamTerminalConfirmationCurrentHeadsRejectWrongMessageID(t *testing.T) {
	natsURL := os.Getenv("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_ACTIVE_IDENTITY_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ACTIVE_IDENTITY_CURRENT_HEAD_" + suffix
	statusPrefix := "cdnca.test." + suffix + ".status"
	connection := connectActiveIdentityNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: streamName, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(streamName) })
	config := DefaultNATSCommandBusConfig()
	config.StatusStream = streamName
	config.StatusSubjectPrefix = statusPrefix
	config.OperationTimeout = 2 * time.Second
	bus, err := NewNATSCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(subject string, wire []byte, messageID string) uint64 {
		message := nats.NewMsg(subject)
		message.Data = wire
		if messageID != "" {
			message.Header.Set(nats.MsgIdHdr, messageID)
		}
		ack, err := js.PublishMsg(message)
		if err != nil || ack == nil || ack.Sequence == 0 {
			t.Fatalf("publish current-head fixture = (%+v, %v)", ack, err)
		}
		return ack.Sequence
	}

	for _, index := range []bool{false, true} {
		for _, tamper := range []string{"missing", "wrong"} {
			name := "confirmation"
			if index {
				name = "index"
			}
			t.Run(name+"/"+tamper, func(t *testing.T) {
				nodeID := uuid.NewString()
				confirmation := activeIdentityNATSConfirmation(t, nodeID, "invalid-current-head")
				preserved := make([]uint64, 0, 3)
				if index {
					subject := terminalCommandReceiptConfirmationIndexSubject(statusPrefix, nodeID)
					predecessor := &terminalCommandReceiptConfirmationIndex{
						Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID,
					}
					wire, messageID, err := terminalCommandReceiptConfirmationIndexWireIdentity(subject, predecessor)
					if err != nil {
						t.Fatal(err)
					}
					previousSequence := publish(subject, wire, messageID)
					preserved = append(preserved, previousSequence)
					current := *predecessor
					current.PreviousSequence = previousSequence
					wire, messageID, err = terminalCommandReceiptConfirmationIndexWireIdentity(subject, &current)
					if err != nil {
						t.Fatal(err)
					}
					if tamper == "missing" {
						messageID = ""
					} else {
						messageID += "-wrong"
					}
					preserved = append(preserved, publish(subject, wire, messageID))
					if err := bus.saveTerminalCommandReceiptConfirmationIndex(t.Context(), &current); err == nil {
						t.Fatal("index save accepted an invalid current-head Nats-Msg-Id")
					}
				} else {
					indexSubject := terminalCommandReceiptConfirmationIndexSubject(statusPrefix, nodeID)
					index := &terminalCommandReceiptConfirmationIndex{
						Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID,
						Entries: []terminalCommandReceiptConfirmationIndexEntry{terminalCommandReceiptConfirmationIndexEntryForKey(confirmation.deploymentKey())},
					}
					indexWire, indexID, err := terminalCommandReceiptConfirmationIndexWireIdentity(indexSubject, index)
					if err != nil {
						t.Fatal(err)
					}
					preserved = append(preserved, publish(indexSubject, indexWire, indexID))
					subject := terminalCommandReceiptConfirmationSubject(statusPrefix, nodeID, confirmation.deploymentKey())
					wire, messageID, err := terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, 0)
					if err != nil {
						t.Fatal(err)
					}
					previousSequence := publish(subject, wire, messageID)
					preserved = append(preserved, previousSequence)
					wire, messageID, err = terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, previousSequence)
					if err != nil {
						t.Fatal(err)
					}
					if tamper == "missing" {
						messageID = ""
					} else {
						messageID += "-wrong"
					}
					preserved = append(preserved, publish(subject, wire, messageID))
					if _, err := bus.saveTerminalCommandReceiptConfirmation(t.Context(), confirmation); err == nil {
						t.Fatal("confirmation save accepted an invalid current-head Nats-Msg-Id")
					}
					if err := bus.deleteTerminalCommandReceiptConfirmation(t.Context(), confirmation); err == nil {
						t.Fatal("confirmation cleanup accepted an invalid current-head Nats-Msg-Id")
					}
				}
				for _, sequence := range preserved {
					if _, err := js.GetMsg(streamName, sequence); err != nil {
						t.Fatalf("fail-closed current-head validation changed sequence %d: %v", sequence, err)
					}
				}
			})
		}
	}
}

func publishTerminalPredecessorHistory(
	t *testing.T,
	js nats.JetStreamContext,
	statusPrefix string,
	index bool,
	count int,
) (string, []uint64, uint64) {
	t.Helper()
	nodeID := uuid.NewString()
	confirmation := activeIdentityNATSConfirmation(t, nodeID, "real-predecessor-budget")
	subject := terminalCommandReceiptConfirmationSubject(statusPrefix, nodeID, confirmation.deploymentKey())
	if index {
		subject = terminalCommandReceiptConfirmationIndexSubject(statusPrefix, nodeID)
	}
	sequences := make([]uint64, 0, count)
	previous := uint64(0)
	publish := func(_ bool) uint64 {
		var encoded []byte
		var messageID string
		var err error
		if index {
			value := &terminalCommandReceiptConfirmationIndex{
				Version: terminalCommandReceiptConfirmationIndexVersion, NodeID: nodeID,
				PreviousSequence: previous,
			}
			encoded, messageID, err = terminalCommandReceiptConfirmationIndexWireIdentity(subject, value)
		} else {
			encoded, messageID, err = terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, previous)
		}
		if err != nil {
			t.Fatal(err)
		}
		message := nats.NewMsg(subject)
		message.Data = encoded
		message.Header.Set(nats.MsgIdHdr, messageID)
		ack, err := js.PublishMsg(message)
		if err != nil || ack == nil || ack.Sequence == 0 {
			t.Fatalf("publish predecessor = (%+v, %v)", ack, err)
		}
		return ack.Sequence
	}
	for range count {
		previous = publish(false)
		sequences = append(sequences, previous)
	}
	current := publish(true)
	return subject, sequences, current
}

func activeIdentityNATSConfirmation(t *testing.T, nodeID, deliveryID string) *terminalCommandReceiptConfirmation {
	t.Helper()
	command := validDeploymentCommand()
	command.Event.EventId = uuid.NewString()
	command.Event.RequestId = uuid.NewString()
	command.DeploymentId = uuid.NewString()
	command.ConfigVersionId = uuid.NewString()
	statusUpdate := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:" + deliveryID,
	}
	receipt, err := newTerminalCommandReceipt(nodeID, command, statusUpdate, []CommandDelivery{delivery}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	return &terminalCommandReceiptConfirmation{
		Version: terminalCommandReceiptConfirmationVersion, Receipt: *receipt,
		SessionEpoch: 7, ReceiptStreamSequence: 2, AgentReceiptPersisted: true,
	}
}

func connectActiveIdentityNATS(t *testing.T, url string) *nats.Conn {
	t.Helper()
	connection, err := nats.Connect(url, nats.Name("cdnca-active-identity-test"), nats.Timeout(2*time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func assertTerminalConfirmationMessageIdentity(
	t *testing.T,
	js nats.JetStreamContext,
	streamName string,
	subject string,
	confirmation *terminalCommandReceiptConfirmation,
	sequence uint64,
	previousSequence uint64,
) {
	t.Helper()
	message, err := js.GetMsg(streamName, sequence)
	if err != nil {
		t.Fatal(err)
	}
	wire, messageID, err := terminalCommandReceiptConfirmationWireIdentity(subject, confirmation, previousSequence)
	if err != nil {
		t.Fatal(err)
	}
	if message.Subject != subject || !bytes.Equal(message.Data, wire) || message.Header.Get(nats.MsgIdHdr) != messageID {
		t.Fatalf("confirmation wire identity changed: subject=%q msg_id=%q", message.Subject, message.Header.Get(nats.MsgIdHdr))
	}
}

func assertTerminalConfirmationIndexMessageIdentity(
	t *testing.T,
	js nats.JetStreamContext,
	streamName string,
	subject string,
	index *terminalCommandReceiptConfirmationIndex,
	sequence uint64,
) {
	t.Helper()
	message, err := js.GetMsg(streamName, sequence)
	if err != nil {
		t.Fatal(err)
	}
	wire, messageID, err := terminalCommandReceiptConfirmationIndexWireIdentity(subject, index)
	if err != nil {
		t.Fatal(err)
	}
	if message.Subject != subject || !bytes.Equal(message.Data, wire) || message.Header.Get(nats.MsgIdHdr) != messageID {
		t.Fatalf("confirmation index wire identity changed: subject=%q msg_id=%q", message.Subject, message.Header.Get(nats.MsgIdHdr))
	}
}

func TestGatewayRecoversDurableReceiptCleanupAfterRestartAndDowngrade(t *testing.T) {
	for _, test := range []struct {
		name              string
		ackReceiptCapable bool
	}{
		{name: "Capability19Restart", ackReceiptCapable: true},
		{name: "Capability18Downgrade", ackReceiptCapable: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := validDeploymentCommand()
			command.ConfigVersionId = uuid.NewString()
			statusUpdate := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
			delivery := &testTerminalReceiptDelivery{
				fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:91",
			}
			receipt, err := newTerminalCommandReceipt(testNodeID, command, statusUpdate, []CommandDelivery{delivery}, time.Unix(100, 0))
			if err != nil {
				t.Fatal(err)
			}
			store := &testTerminalReceiptStore{
				receipts: map[deploymentKey]*terminalCommandReceipt{receipt.deploymentKey(): receipt},
				confirmations: map[deploymentKey]*terminalCommandReceiptConfirmation{
					receipt.deploymentKey(): {
						Version: terminalCommandReceiptConfirmationVersion, Receipt: *receipt,
						SessionEpoch: 7, ReceiptStreamSequence: 2, AgentReceiptPersisted: true,
						HeartbeatBarrierSequence: 3,
					},
				},
			}
			bus := newTestTerminalReceiptBus(store)
			gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
			ctx, cancel := context.WithCancel(context.Background())
			stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
			received := make(chan connectReceive, 2)
			lease, err := NewMemorySessionCoordinator().Acquire(ctx, testNodeID)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- gateway.serveSession(
					stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
					nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
					&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false,
					true, test.ackReceiptCapable,
				)
			}()
			var heartbeatCausationID string
			for index, streamSequence := range []uint64{2, 3} {
				heartbeat := validHeartbeatRequest(lease.Epoch(), uint64(index+1), streamSequence, uuid.NewString(), uuid.NewString())
				heartbeat.GetHeartbeat().ActiveConfigIdentityCapability = testActiveIdentityCapability()
				if heartbeatCausationID != "" {
					heartbeat.GetHeartbeat().Event.CausationId = proto.String(heartbeatCausationID)
				}
				received <- connectReceive{request: heartbeat}
				select {
				case response := <-stream.sent:
					if response.GetHeartbeatAck() == nil {
						t.Fatalf("causal heartbeat response = %+v", response)
					}
				case <-time.After(time.Second):
					t.Fatal("causal heartbeat was not acknowledged")
				}
				heartbeatCausationID = heartbeat.GetHeartbeat().Event.EventId
				if streamSequence == 2 && (store.count() != 1 || store.confirmedCount() != 1) {
					t.Fatalf("restart rebound cleanup too early: receipts=%d confirmations=%d", store.count(), store.confirmedCount())
				}
			}
			waitForTest(t, time.Second, func() bool { return store.count() == 0 && store.confirmedCount() == 0 })
			if store.deleteCount != 1 || store.confirmationDeleteCount != 1 {
				t.Fatalf("recovered cleanup = receipt deletes:%d confirmation deletes:%d", store.deleteCount, store.confirmationDeleteCount)
			}
			cancel()
			lease.Release()
			<-done
		})
	}
}

type testTerminalReceiptStore struct {
	mu                      sync.Mutex
	receipts                map[deploymentKey]*terminalCommandReceipt
	confirmations           map[deploymentKey]*terminalCommandReceiptConfirmation
	saveErr                 error
	deleteCount             int
	confirmationDeleteCount int
}

func (s *testTerminalReceiptStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.receipts)
}

func (s *testTerminalReceiptStore) confirmedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.confirmations)
}

func (s *testTerminalReceiptStore) confirmedSession() (uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, confirmation := range s.confirmations {
		return confirmation.SessionEpoch, confirmation.ReceiptStreamSequence
	}
	return 0, 0
}

type testTerminalReceiptBus struct {
	*fakeCommandBus
	store *testTerminalReceiptStore
}

func newTestTerminalReceiptBus(store *testTerminalReceiptStore) *testTerminalReceiptBus {
	return &testTerminalReceiptBus{
		fakeCommandBus: &fakeCommandBus{subscription: newFakeCommandSubscription()},
		store:          store,
	}
}

func (b *testTerminalReceiptBus) loadTerminalCommandReceipt(_ context.Context, _ string, key deploymentKey) (*terminalCommandReceipt, error) {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	receipt := b.store.receipts[key]
	if receipt == nil {
		return nil, nil
	}
	copy := *receipt
	return &copy, nil
}

func (b *testTerminalReceiptBus) saveTerminalCommandReceipt(_ context.Context, receipt *terminalCommandReceipt) (*terminalCommandReceipt, error) {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	if b.store.saveErr != nil {
		return nil, b.store.saveErr
	}
	key := receipt.deploymentKey()
	if existing := b.store.receipts[key]; existing != nil {
		copy := *existing
		return &copy, nil
	}
	copy := *receipt
	b.store.receipts[key] = &copy
	return &copy, nil
}

func (b *testTerminalReceiptBus) deleteTerminalCommandReceipt(_ context.Context, receipt *terminalCommandReceipt) error {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	key := receipt.deploymentKey()
	if existing := b.store.receipts[key]; existing != nil {
		delete(b.store.receipts, key)
		b.store.deleteCount++
	}
	return nil
}

func (b *testTerminalReceiptBus) loadTerminalCommandReceiptConfirmation(_ context.Context, _ string, key deploymentKey) (*terminalCommandReceiptConfirmation, error) {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	confirmation := b.store.confirmations[key]
	if confirmation == nil {
		return nil, nil
	}
	copy := *confirmation
	return &copy, nil
}

func (b *testTerminalReceiptBus) listTerminalCommandReceiptConfirmations(_ context.Context, nodeID string, limit int) ([]*terminalCommandReceiptConfirmation, error) {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	if limit <= 0 || len(b.store.confirmations) > limit {
		return nil, errors.New("terminal command receipt confirmations exceed their recovery limit")
	}
	result := make([]*terminalCommandReceiptConfirmation, 0, len(b.store.confirmations))
	for _, confirmation := range b.store.confirmations {
		if confirmation.Receipt.NodeID != nodeID {
			return nil, errors.New("terminal command receipt confirmation belongs to another node")
		}
		copy := *confirmation
		result = append(result, &copy)
	}
	return result, nil
}

func (b *testTerminalReceiptBus) saveTerminalCommandReceiptConfirmation(_ context.Context, confirmation *terminalCommandReceiptConfirmation) (*terminalCommandReceiptConfirmation, error) {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	if b.store.confirmations == nil {
		b.store.confirmations = make(map[deploymentKey]*terminalCommandReceiptConfirmation)
	}
	copy := *confirmation
	b.store.confirmations[confirmation.deploymentKey()] = &copy
	return &copy, nil
}

func (b *testTerminalReceiptBus) deleteTerminalCommandReceiptConfirmation(_ context.Context, confirmation *terminalCommandReceiptConfirmation) error {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	key := confirmation.deploymentKey()
	if existing := b.store.confirmations[key]; existing != nil {
		delete(b.store.confirmations, key)
		b.store.confirmationDeleteCount++
	}
	return nil
}

type testTerminalReceiptDelivery struct {
	*fakeCommandDelivery
	identity string
}

func (d *testTerminalReceiptDelivery) terminalCommandDeliveryIdentity() (string, error) {
	return d.identity, nil
}

func TestGatewayRejectsUnboundIdentityWithoutWaitingState(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	statusUpdate := validDeploymentStatus(command)
	bindDeploymentStatusEvent(t, statusUpdate, command)
	statusUpdate.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
	statusUpdate.TransitionSequence = 5
	statusUpdate.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	statusUpdate.ActiveConfigIdentity = testActiveIdentity(command.ConfigVersionId, command.Artifacts[0].Sha256)
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer lease.Release()
	stream := &heartbeatTestStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	received := make(chan connectReceive)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true,
		)
	}()
	received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: statusUpdate},
	}}
	select {
	case err := <-done:
		if grpcstatus.Code(err) != codes.FailedPrecondition {
			t.Fatalf("unbound identity code = %v, want FailedPrecondition", grpcstatus.Code(err))
		}
	case <-time.After(time.Second):
		t.Fatal("unbound identity was retained waiting for a future command")
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 0 {
		t.Fatalf("unbound identity was published: %d", len(bus.published))
	}
}

func assertActiveIdentityFields(t *testing.T, descriptor protoreflect.MessageDescriptor, fields map[string]protoreflect.FieldNumber) {
	t.Helper()
	for name, number := range fields {
		field := descriptor.Fields().ByName(protoreflect.Name(name))
		if field == nil || field.Number() != number {
			t.Fatalf("%s.%s = %v, want field %d", descriptor.FullName(), name, field, number)
		}
	}
}

func testActiveIdentityCapability() *agentv1.Capability {
	return &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY, ApiVersion: 1}
}

func testActiveIdentity(configVersionID string, digest []byte) *agentv1.ActiveConfigIdentity {
	return &agentv1.ActiveConfigIdentity{
		ConfigVersionId: configVersionID, ArtifactSha256: append([]byte(nil), digest...),
		Schema: agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
	}
}

func bindDeploymentStatusEvent(t *testing.T, status *agentv1.DeploymentStatus, command *agentv1.DeploymentCommand) {
	t.Helper()
	if status == nil || status.Event == nil || command == nil || command.Event == nil {
		t.Fatal("status and command event metadata are required")
	}
	status.Event.RequestId = command.Event.RequestId
	status.Event.Traceparent = command.Event.Traceparent
	status.Event.CausationId = proto.String(command.Event.EventId)
	status.Event.CorrelationId = command.Event.CorrelationId
	if command.Event.TaskId == nil {
		status.Event.TaskId = nil
	} else {
		status.Event.TaskId = proto.String(command.Event.GetTaskId())
	}
}

func terminalStatusForCommand(t *testing.T, command *agentv1.DeploymentCommand, state agentv1.NodeDeploymentState) *agentv1.DeploymentStatus {
	t.Helper()
	value := validDeploymentStatus(command)
	bindDeploymentStatusEvent(t, value, command)
	value.State = state
	value.TransitionSequence = 5
	switch state {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED:
		value.RunningConfigUnchanged = true
		value.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "deployment failed"}
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED:
		value.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "rollback failed"}
	}
	return value
}

func connectWithActiveIdentityHello(t *testing.T, servers testServers, active bool) (grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], *agentv1.GatewayHello, func()) {
	t.Helper()
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		cancel()
		connection.Close()
		t.Fatal(err)
	}
	request := validHello(testNodeID, versionRange(1, 0), 1)
	if active {
		currentID := uuid.NewString()
		request.GetHello().Capabilities.Features = []*agentv1.Capability{testActiveIdentityCapability()}
		request.GetHello().CurrentConfigVersionId = &currentID
		request.GetHello().CurrentConfigIdentity = testActiveIdentity(currentID, bytes.Repeat([]byte{0x51}, 32))
	}
	if err := stream.Send(request); err != nil {
		cancel()
		connection.Close()
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || response.GetHello() == nil {
		cancel()
		connection.Close()
		t.Fatalf("GatewayHello = (%+v, %v)", response, err)
	}
	return stream, response.GetHello(), func() { cancel(); _ = connection.Close() }
}

func startActiveIdentityHeartbeatSession(t *testing.T, gateway *Gateway) (chan connectReceive, *heartbeatTestStream, chan error) {
	t.Helper()
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); lease.Release() })
	stream := &heartbeatTestStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	received := make(chan connectReceive, 4)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), false, false, false, true,
		)
	}()
	return received, stream, done
}
