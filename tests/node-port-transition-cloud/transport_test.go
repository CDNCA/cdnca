package porttransition_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	gateway "github.com/cdnca/cdnca/services/agent-gateway"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This deliberately tests public Gateway components, not Agent.Connect or the
// Control API. Commands/statuses below are explicit protocol fixtures.
func TestGatewayPortTransport(t *testing.T) {
	for _, action := range []agentv1.GatewayPortTransitionAction{
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE,
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK,
	} {
		t.Run(action.String(), func(t *testing.T) {
			f := newFixture(t)
			f.switchPort(t)
			delivery := f.complete(t, action)
			if err := delivery.Ack(t.Context()); err != nil {
				t.Fatal(err)
			}
			if action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
				f.checkHealth(t, f.command.NewEndpoint.Address)
				assertClosed(t, f.command.OldEndpoint.Address)
			} else {
				f.checkHealth(t, f.command.OldEndpoint.Address)
				assertClosed(t, f.command.NewEndpoint.Address)
			}
		})
	}
}

// Terminal listener mutation precedes broker acknowledgement. An exact broker
// redelivery must still be admitted so the Agent can replay its durable status.
func TestGatewayTerminalCommandRedelivery(t *testing.T) {
	for _, action := range []agentv1.GatewayPortTransitionAction{
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE,
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK,
	} {
		t.Run(action.String(), func(t *testing.T) {
			f := newFixture(t)
			f.switchPort(t)
			delivery := f.complete(t, action)
			// Exercise real JetStream redelivery at the post-mutation/pre-ACK
			// boundary without substituting an in-memory bus.
			if err := delivery.Retry(t.Context(), 10*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			replayed := f.next(t)
			if !proto.Equal(delivery.Command(), replayed.Command()) {
				t.Fatal("broker changed terminal command on redelivery")
			}
			if _, err := f.manager.ValidateAction(replayed.Command()); err != nil {
				t.Fatalf("terminal command rejected before Agent receipt replay: %v", err)
			}
			publication, err := f.bus.PublishPortTransitionStatus(t.Context(), f.command.NodeId, f.lastStatus)
			if err != nil || !publication.Replayed {
				t.Fatalf("post-mutation status replay: %+v %v", publication, err)
			}
			f.applyTerminal(t, replayed.Command())
			if err := replayed.Ack(t.Context()); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*agentv1.GatewayPortTransitionCommand){
				"node":              func(c *agentv1.GatewayPortTransitionCommand) { c.NodeId = uuid.NewString() },
				"certificate":       func(c *agentv1.GatewayPortTransitionCommand) { c.CertificateSha256 = strings.Repeat("0", 64) },
				"event":             func(c *agentv1.GatewayPortTransitionCommand) { c.Event.EventId = uuid.NewString() },
				"request":           func(c *agentv1.GatewayPortTransitionCommand) { c.Event.RequestId = uuid.NewString() },
				"revision":          func(c *agentv1.GatewayPortTransitionCommand) { c.Revision++ },
				"expected-revision": func(c *agentv1.GatewayPortTransitionCommand) { c.ExpectedNodeRevision++ },
				"endpoint":          func(c *agentv1.GatewayPortTransitionCommand) { c.NewEndpoint.ListenAddress = "127.0.0.1:12345" },
				"action": func(c *agentv1.GatewayPortTransitionCommand) {
					c.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH
				},
			} {
				changed := proto.Clone(replayed.Command()).(*agentv1.GatewayPortTransitionCommand)
				mutate(changed)
				if _, err := f.manager.ValidateAction(changed); err == nil {
					t.Fatalf("accepted terminal %s drift", name)
				}
			}
			f.nextTransition(t, replayed.Command())
		})
	}
}

type fixture struct {
	command    *agentv1.GatewayPortTransitionCommand
	manager    *gateway.PortTransitionManager
	bus        *gateway.NATSCommandBus
	js         nats.JetStreamContext
	config     gateway.NATSCommandBusConfig
	sub        gateway.PortTransitionCommandSubscription
	clientTLS  *tls.Config
	peerHashes chan string
	lastStatus *agentv1.GatewayPortTransitionStatus
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := os.Getenv("PORT_TRANSITION_TEST_NATS_URL")
	if url == "" {
		t.Skip("PORT_TRANSITION_TEST_NATS_URL must point to a task-owned JetStream")
	}
	connection, err := nats.Connect(url, nats.Timeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	config := gateway.DefaultNATSCommandBusConfig()
	config.CommandStream = "PORT_COMMANDS_" + suffix
	config.StatusStream = "PORT_STATUS_" + suffix
	config.PortTransitionCommandSubjectPrefix = "porttest." + suffix + ".commands"
	config.PortTransitionStatusSubjectPrefix = "porttest." + suffix + ".status"
	config.PortTransitionConsumerPrefix = "port_" + suffix
	config.OperationTimeout = time.Second
	for _, stream := range []*nats.StreamConfig{
		{Name: config.CommandStream, Subjects: []string{config.PortTransitionCommandSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage},
		{Name: config.StatusStream, Subjects: []string{config.PortTransitionStatusSubjectPrefix + ".*"}, Retention: nats.LimitsPolicy, Storage: nats.FileStorage},
	} {
		if _, err := js.AddStream(stream); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := js.DeleteStream(stream.Name); err != nil {
				t.Errorf("delete owned stream: %v", err)
			}
		})
	}
	bus, err := gateway.NewNATSCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS, certificateHash := certificatePair(t)
	peerHashes := make(chan string, 16)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)), grpc.UnaryInterceptor(
		func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			p, ok := peer.FromContext(ctx)
			if !ok {
				t.Error("missing TLS peer")
				return handler(ctx, req)
			}
			info, ok := p.AuthInfo.(credentials.TLSInfo)
			if !ok || len(info.State.PeerCertificates) != 1 {
				t.Error("missing verified client certificate")
				return handler(ctx, req)
			}
			digest := sha256.Sum256(info.State.PeerCertificates[0].Raw)
			peerHashes <- hex.EncodeToString(digest[:])
			return handler(ctx, req)
		}))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(server, healthServer)
	t.Cleanup(server.Stop)
	old := listen(t)
	t.Cleanup(func() { _ = old.Close() })
	go func() { _ = server.Serve(old) }()
	reserved := listen(t)
	newAddress := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	manager := gateway.NewPortTransitionManager(old, old.Addr().String(),
		func(ctx context.Context, address string) (net.Listener, error) {
			listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
			if err == nil {
				t.Cleanup(func() { _ = listener.Close() })
			}
			return listener, err
		}, time.Now)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})
	if err := manager.ConfigureServe(func(listener net.Listener) error {
		go func() { _ = server.Serve(listener) }()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	command := &agentv1.GatewayPortTransitionCommand{
		Event: event(now), Schema: agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1,
		TransitionId: uuid.NewString(), NodeId: uuid.NewString(), Revision: 1, ExpectedNodeRevision: 1,
		OldEndpoint:           &agentv1.GatewayEndpoint{Address: old.Addr().String(), ListenAddress: old.Addr().String(), ServerName: "port.test"},
		NewEndpoint:           &agentv1.GatewayEndpoint{Address: newAddress, ListenAddress: newAddress, ServerName: "port.test"},
		CompatibilityDeadline: timestamppb.New(now.Add(time.Hour)), RollbackDeadline: timestamppb.New(now.Add(2 * time.Hour)),
		CertificateSha256: certificateHash, Action: agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH,
	}
	sub, err := bus.SubscribePortTransitions(t.Context(), command.NodeId)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sub.Close(); err != nil {
			t.Errorf("close subscription: %v", err)
		}
	})
	return &fixture{command: command, manager: manager, bus: bus, js: js, config: config, sub: sub, clientTLS: clientTLS, peerHashes: peerHashes}
}

func (f *fixture) next(t *testing.T) gateway.PortTransitionCommandDelivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	delivery, err := f.sub.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

func (f *fixture) publish(t *testing.T, command *agentv1.GatewayPortTransitionCommand) gateway.PortTransitionCommandDelivery {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.js.Publish(f.config.PortTransitionCommandSubjectPrefix+"."+command.NodeId, payload,
		nats.MsgId(command.Event.EventId), nats.ExpectStream(f.config.CommandStream)); err != nil {
		t.Fatal(err)
	}
	return f.next(t)
}

func (f *fixture) switchPort(t *testing.T) {
	t.Helper()
	f.checkHealth(t, f.command.OldEndpoint.Address)
	delivery := f.publish(t, f.command)
	if _, err := f.manager.Prepare(t.Context(), delivery.Command()); err != nil {
		t.Fatal(err)
	}
	f.checkHealth(t, f.command.OldEndpoint.Address)
	observedHash := f.checkHealth(t, f.command.NewEndpoint.Address)
	if err := f.manager.RecordConnection(f.command.TransitionId, f.command.Revision, f.command.NodeId, observedHash); err != nil {
		t.Fatal(err)
	}
	f.persist(t, f.command, agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED, 1)
	if err := delivery.Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) complete(t *testing.T, action agentv1.GatewayPortTransitionAction) gateway.PortTransitionCommandDelivery {
	t.Helper()
	command := proto.Clone(f.command).(*agentv1.GatewayPortTransitionCommand)
	command.Action, command.Event = action, event(time.Now().UTC())
	delivery := f.publish(t, command)
	if _, err := f.manager.ValidateAction(delivery.Command()); err != nil {
		t.Fatal(err)
	}
	if action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
		f.persist(t, command, agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED, 2)
	} else {
		f.persist(t, command, agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK, 2)
	}
	f.applyTerminal(t, command)
	return delivery
}

func (f *fixture) applyTerminal(t *testing.T, command *agentv1.GatewayPortTransitionCommand) {
	t.Helper()
	var err error
	if command.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
		err = f.manager.Finalize(command.TransitionId, []string{command.NodeId})
	} else {
		err = f.manager.Rollback(command.TransitionId)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) nextTransition(t *testing.T, obsolete *agentv1.GatewayPortTransitionCommand) {
	t.Helper()
	command := proto.Clone(f.command).(*agentv1.GatewayPortTransitionCommand)
	command.TransitionId, command.Event = uuid.NewString(), event(time.Now().UTC())
	command.Revision++
	command.ExpectedNodeRevision++
	if obsolete.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
		command.OldEndpoint = proto.Clone(command.NewEndpoint).(*agentv1.GatewayEndpoint)
	}
	reserved := listen(t)
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	command.NewEndpoint = &agentv1.GatewayEndpoint{Address: address, ListenAddress: address, ServerName: "port.test"}
	f.command = command
	f.switchPort(t)
	terminal := f.complete(t, agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE)
	if err := terminal.Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.ValidateAction(obsolete); err == nil {
		t.Fatal("obsolete terminal command admitted after newer completion")
	}
	if err := f.manager.Finalize(obsolete.TransitionId, []string{obsolete.NodeId}); err == nil {
		t.Fatal("obsolete finalize mutated newer listener")
	}
	if err := f.manager.Rollback(obsolete.TransitionId); err == nil {
		t.Fatal("obsolete rollback mutated newer listener")
	}
	f.checkHealth(t, command.NewEndpoint.Address)
	assertClosed(t, command.OldEndpoint.Address)
}

func (f *fixture) persist(t *testing.T, command *agentv1.GatewayPortTransitionCommand, state agentv1.GatewayPortTransitionState, revision uint64) {
	t.Helper()
	metadata := event(time.Now().UTC())
	metadata.RequestId, metadata.CausationId = command.Event.RequestId, &command.Event.EventId
	endpoint := proto.Clone(command.NewEndpoint).(*agentv1.GatewayEndpoint)
	errorCode := ""
	if state == agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK {
		endpoint = proto.Clone(command.OldEndpoint).(*agentv1.GatewayEndpoint)
		errorCode = "operator_rollback"
	}
	endpoint.ListenAddress = ""
	value := &agentv1.GatewayPortTransitionStatus{Event: metadata, Schema: command.Schema, TransitionId: command.TransitionId,
		NodeId: command.NodeId, Revision: command.Revision, StatusRevision: revision, State: state,
		CertificateSha256: command.CertificateSha256, ActiveEndpoint: endpoint, ErrorCode: errorCode}
	f.lastStatus = value
	first, err := f.bus.PublishPortTransitionStatus(t.Context(), command.NodeId, value)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.bus.PublishPortTransitionStatus(t.Context(), command.NodeId, value)
	if err != nil || !replayed.Replayed || first.Stream != replayed.Stream || first.Sequence != replayed.Sequence {
		t.Fatalf("durable status replay differs: first=%+v replay=%+v err=%v", first, replayed, err)
	}
	conflict := proto.Clone(value).(*agentv1.GatewayPortTransitionStatus)
	conflict.Event.EventId = uuid.NewString()
	if _, err := f.bus.PublishPortTransitionStatus(t.Context(), command.NodeId, conflict); err == nil {
		t.Fatal("different event accepted at the same durable status revision")
	}
}

func (f *fixture) checkHealth(t *testing.T, address string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(credentials.NewTLS(f.clientTLS)), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	result, err := healthv1.NewHealthClient(connection).Check(ctx, &healthv1.HealthCheckRequest{})
	if err != nil || result.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		t.Fatalf("mTLS health: %v %v", result, err)
	}
	select {
	case fingerprint := <-f.peerHashes:
		if fingerprint != f.command.CertificateSha256 {
			t.Fatal("client certificate changed")
		}
		return fingerprint
	case <-ctx.Done():
		t.Fatal("verified client identity was not observed")
	}
	return ""
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func assertClosed(t *testing.T, address string) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatalf("retired listener still accepts TCP: %s", address)
	}
}

func event(now time.Time) *commonv1.EventMetadata {
	return &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), CorrelationId: uuid.NewString(), OccurredTime: timestamppb.New(now)}
}

func certificatePair(t *testing.T) (*tls.Config, *tls.Config, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned port test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"port.test"},
			NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	server := issue(2, x509.ExtKeyUsageServerAuth)
	client := issue(3, x509.ExtKeyUsageClientAuth)
	digest := sha256.Sum256(client.Certificate[0])
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert},
		&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{client}, RootCAs: pool, ServerName: "port.test"}, hex.EncodeToString(digest[:])
}
