//go:build integration

package gateway

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGatewayPortTransitionNATSAuthorizationLifecycle(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Fatal("CDNCA_TEST_NATS_URL must point to an isolated test NATS server")
	}
	for _, scenario := range []string{"restore", "late status", "disconnect"} {
		t.Run(scenario, func(t *testing.T) {
			connection := connectIntegrationNATS(t, natsURL)
			t.Cleanup(connection.Close)
			js, err := connection.JetStream(nats.MaxWait(2 * time.Second))
			if err != nil {
				t.Fatal(err)
			}
			suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
			config := DefaultNATSCommandBusConfig()
			config.CommandStream, config.StatusStream = "PORT_COMMANDS_"+suffix, "PORT_STATUS_"+suffix
			config.PortTransitionCommandSubjectPrefix = "cdnca.test." + suffix + ".commands"
			config.PortTransitionStatusSubjectPrefix = "cdnca.test." + suffix + ".status"
			config.PortTransitionConsumerPrefix = "port_" + suffix
			config.AckWait, config.OperationTimeout = time.Minute, time.Second
			for _, stream := range []*nats.StreamConfig{
				{Name: config.CommandStream, Subjects: []string{config.PortTransitionCommandSubjectPrefix + ".>"}, Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage},
				{Name: config.StatusStream, Subjects: []string{config.PortTransitionStatusSubjectPrefix + ".>"}, Retention: nats.LimitsPolicy, Storage: nats.FileStorage},
			} {
				if _, err := js.AddStream(stream); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := js.DeleteStream(stream.Name); err != nil {
						t.Errorf("delete task stream: %v", err)
					}
				})
			}
			bus, err := NewNATSCommandBus(connection, config)
			if err != nil {
				t.Fatal(err)
			}
			observed := &portNATSObserver{NATSCommandBus: bus, subscribed: make(chan *portNATSSubscription, 4), fetched: make(chan PortTransitionCommandDelivery, 8)}
			s := newPortAuthorizationSession(t, "incoming", true, true, observed)
			initialSubscription := portTestReceive(t, observed.subscribed)
			command := validPortTransitionCommand()
			command.NodeId, command.CertificateSha256 = testNodeID, certificateIdentityHex(nodeIdentity{})
			command.CompatibilityDeadline = timestamppb.New(s.now().Add(12 * time.Hour))
			command.RollbackDeadline = timestamppb.New(s.now().Add(24 * time.Hour))
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
			if err != nil {
				t.Fatal(err)
			}
			publish := func() {
				t.Helper()
				if _, err := js.Publish(config.PortTransitionCommandSubjectPrefix+"."+testNodeID, payload, nats.ExpectStream(config.CommandStream)); err != nil {
					t.Fatal(err)
				}
			}
			publish()
			portTestReceive(t, observed.fetched)
			if response := portTestReceive(t, s.stream.sent); !proto.Equal(response.GetGatewayPortTransitionCommand(), command) {
				t.Fatalf("first Gateway delivery changed protobuf: %v", response)
			}
			s.offset.Add(int64(time.Hour))
			s.heartbeat()
			reply := portTestReceive(t, s.control.refreshes)
			publish()
			// The observer only reports after the production NATS subscription returns
			// the delivery; it does not replace Next, Retry, Ack, or Close behavior.
			portTestReceive(t, observed.fetched)
			stoppedAt := time.Now()
			if scenario == "disconnect" {
				s.cancel()
				portTestReceive(t, s.done)
				if status.Code(s.err) != codes.Canceled {
					t.Fatalf("disconnected session = %v", s.err)
				}
			} else {
				reply <- s.authorization(controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING)
				portTestReceive(t, initialSubscription.closed)
				if response := portTestReceive(t, s.stream.sent); response.GetHeartbeatAck() == nil {
					t.Fatalf("revoked session delivered a command: %v", response)
				}
				if scenario == "late status" {
					s.sendStatus(command)
					portTestReceive(t, s.done)
					if status.Code(s.err) != codes.PermissionDenied {
						t.Fatalf("revoked status = %v", s.err)
					}
				}
			}
			portTestReceive(t, initialSubscription.closed)
			statusInfo, err := js.StreamInfo(config.StatusStream)
			if err != nil || statusInfo.State.Msgs != 0 {
				t.Fatalf("old session published a status: info=%v err=%v", statusInfo, err)
			}
			commandInfo, err := js.StreamInfo(config.CommandStream)
			if err != nil || commandInfo.State.Msgs != 2 {
				t.Fatalf("unacknowledged commands were removed: info=%v err=%v", commandInfo, err)
			}
			if scenario == "restore" {
				s.offset.Add(int64(time.Hour))
				s.heartbeat()
				reply = portTestReceive(t, s.control.refreshes)
				reply <- s.authorization(controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE)
				portTestReceive(t, observed.subscribed)
				if response := portTestReceive(t, s.stream.sent); response.GetHeartbeatAck() == nil {
					t.Fatalf("restored session heartbeat = %v", response)
				}
			} else {
				s = newPortAuthorizationSession(t, "incoming", true, true, observed)
				portTestReceive(t, observed.subscribed)
			}
			for i := 0; i < 2; i++ {
				delivery := portTestReceive(t, observed.fetched)
				metadata, err := delivery.(*natsPortTransitionDelivery).message.Metadata()
				if err != nil || metadata.NumDelivered < 2 || !proto.Equal(delivery.Command(), command) {
					t.Fatalf("broker did not redeliver the original protobuf: metadata=%v err=%v", metadata, err)
				}
				if response := portTestReceive(t, s.stream.sent); !proto.Equal(response.GetGatewayPortTransitionCommand(), command) {
					t.Fatalf("redelivered Gateway protobuf changed: %v", response)
				}
				t.Logf("broker redelivery: stream_sequence=%d num_delivered=%d elapsed=%s AckWait=%s", metadata.Sequence.Stream, metadata.NumDelivered, time.Since(stoppedAt), config.AckWait)
			}
			if elapsed := time.Since(stoppedAt); elapsed >= config.AckWait/2 {
				t.Fatalf("redelivery took %s; explicit Retry was not demonstrated before AckWait", elapsed)
			}
			s.sendStatus(command)
			eventually(t, 3*time.Second, func() bool {
				commands, err := js.StreamInfo(config.CommandStream)
				return err == nil && commands.State.Msgs == 0
			}, "accepted status did not acknowledge both real NATS deliveries")
			stored, err := js.GetMsg(config.StatusStream, 1)
			if err != nil {
				t.Fatal(err)
			}
			value := new(agentv1.GatewayPortTransitionStatus)
			if err := proto.Unmarshal(stored.Data, value); err != nil || value.TransitionId != command.TransitionId ||
				value.CertificateSha256 != command.CertificateSha256 || value.State != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED {
				t.Fatalf("persisted real status = %v, err=%v", value, err)
			}
			statusInfo, err = js.StreamInfo(config.StatusStream)
			if err != nil || statusInfo.State.Msgs != 1 {
				t.Fatalf("unexpected status count: info=%v err=%v", statusInfo, err)
			}
		})
	}
}

type portNATSObserver struct {
	*NATSCommandBus
	subscribed chan *portNATSSubscription
	fetched    chan PortTransitionCommandDelivery
}

func (b *portNATSObserver) SubscribePortTransitions(ctx context.Context, nodeID string) (PortTransitionCommandSubscription, error) {
	subscription, err := b.NATSCommandBus.SubscribePortTransitions(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	observed := &portNATSSubscription{PortTransitionCommandSubscription: subscription, fetched: b.fetched, closed: make(chan struct{})}
	b.subscribed <- observed
	return observed, nil
}

type portNATSSubscription struct {
	PortTransitionCommandSubscription
	fetched chan<- PortTransitionCommandDelivery
	closed  chan struct{}
	once    sync.Once
}

func (s *portNATSSubscription) Next(ctx context.Context) (PortTransitionCommandDelivery, error) {
	delivery, err := s.PortTransitionCommandSubscription.Next(ctx)
	if delivery != nil {
		s.fetched <- delivery
	}
	return delivery, err
}

func (s *portNATSSubscription) Close() error {
	err := s.PortTransitionCommandSubscription.Close()
	s.once.Do(func() { close(s.closed) })
	return err
}
