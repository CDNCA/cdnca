package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	testArtifactRecipientKeyID = "x25519:82d7e65c0705f0061f99d193e49ba47d0a251b5e95d8f636d32a962858f6d13c"
	frozenAgentConfigMediaType = "application/vnd.cdnca.edge-configuration-bundle+json;version=1"
)

func TestArtifactSizeLimitsAreRequiredAndConsistent(t *testing.T) {
	for _, change := range []func(*Config){
		func(config *Config) { config.MaxArtifactBytes = 0 },
		func(config *Config) { config.MaxArtifactBytes = uint64(config.MaxArtifactChunkBytes - 1) },
	} {
		config := DefaultConfig()
		config.GatewayInstanceID = "gateway-test"
		config.GatewayVersion = "test"
		change(&config)
		if err := config.validate(); err == nil {
			t.Fatal("invalid artifact size limits were accepted")
		}
	}
}

func TestEncryptedArtifactDescriptorContract(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	for _, kind := range []agentv1.ArtifactKind{
		agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE,
	} {
		command := validEncryptedDeploymentCommand(kind)
		if err := gateway.validateDeploymentCommand(command, testArtifactRecipientKeyID); err != nil {
			t.Fatalf("valid encrypted %s command rejected: %v", kind, err)
		}
	}
	if err := gateway.validateDeploymentCommand(validDeploymentCommand(), ""); err != nil {
		t.Fatalf("v1 plaintext configuration rejected without an encryption key: %v", err)
	}

	tests := []struct {
		name      string
		command   func() *agentv1.DeploymentCommand
		sessionID string
	}{
		{name: "wrong recipient", command: func() *agentv1.DeploymentCommand {
			value := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
			wrong := "x25519:" + string(bytes.Repeat([]byte{'0'}, 64))
			value.Artifacts[0].RecipientKeyId = &wrong
			return value
		}, sessionID: testArtifactRecipientKeyID},
		{name: "empty session key", command: func() *agentv1.DeploymentCommand {
			return validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
		}},
		{name: "missing recipient", command: func() *agentv1.DeploymentCommand {
			value := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
			value.Artifacts[0].RecipientKeyId = nil
			return value
		}, sessionID: testArtifactRecipientKeyID},
		{name: "plaintext recipient", command: func() *agentv1.DeploymentCommand {
			value := validDeploymentCommand()
			value.Artifacts[0].RecipientKeyId = proto.String(testArtifactRecipientKeyID)
			return value
		}, sessionID: testArtifactRecipientKeyID},
		{name: "plaintext secret", command: func() *agentv1.DeploymentCommand {
			value := validDeploymentCommand()
			value.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
			return value
		}, sessionID: testArtifactRecipientKeyID},
		{name: "truncated HPKE envelope", command: func() *agentv1.DeploymentCommand {
			value := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
			value.Artifacts[0].SizeBytes = minimumHPKEArtifactBytes - 1
			return value
		}, sessionID: testArtifactRecipientKeyID},
		{name: "artifact exceeds limit", command: func() *agentv1.DeploymentCommand {
			value := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
			value.Artifacts[0].SizeBytes = gateway.config.MaxArtifactBytes + 1
			return value
		}, sessionID: testArtifactRecipientKeyID},
		{name: "unknown kind", command: func() *agentv1.DeploymentCommand {
			value := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
			value.Artifacts[0].Kind = agentv1.ArtifactKind(99)
			return value
		}, sessionID: testArtifactRecipientKeyID},
		{name: "unknown algorithm", command: func() *agentv1.DeploymentCommand {
			value := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
			value.Artifacts[0].EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm(99)
			return value
		}, sessionID: testArtifactRecipientKeyID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := gateway.validateDeploymentCommand(test.command(), test.sessionID); err == nil {
				t.Fatal("invalid encrypted artifact command was accepted")
			}
		})
	}
}

func TestEncryptedConfigurationCommandIsForwardedUnchanged(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
	delivery := &fakeCommandDelivery{command: command}
	bus.subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, testArtifactRecipientKeyID, time.Now().Add(time.Hour), true, false,
		)
	}()
	select {
	case response := <-stream.sent:
		if !proto.Equal(response.GetDeploymentCommand(), command) {
			t.Fatal("Gateway changed the encrypted configuration descriptor")
		}
	case <-time.After(time.Second):
		t.Fatal("encrypted configuration command was not forwarded")
	}
	cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled {
			t.Fatalf("serveSession() code = %v, want Canceled", status.Code(err))
		}
	case <-time.After(time.Second):
		t.Fatal("serveSession() did not stop after cancellation")
	}
	waitForTest(t, time.Second, func() bool { return delivery.naks.Load() == 1 })
	if delivery.acks.Load() != 0 || delivery.naks.Load() != 1 {
		t.Fatalf("unfinished delivery acks=%d naks=%d", delivery.acks.Load(), delivery.naks.Load())
	}
}

func TestEncryptedCommandContextReplayConflictsInFlight(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
	replay := proto.Clone(command).(*agentv1.DeploymentCommand)
	replay.Event.EventId = uuid.NewString()
	first, second := &fakeCommandDelivery{command: command}, &fakeCommandDelivery{command: replay}
	bus.subscription.deliveries <- first
	bus.subscription.deliveries <- second
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	stream := &capturingBidiStream{ctx: context.Background(), sent: make(chan *agentv1.ConnectResponse, 2)}
	err = gateway.serveSession(
		stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
		nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
		&commonv1.ProtocolVersion{Major: 1}, testArtifactRecipientKeyID, time.Now().Add(time.Hour), true, false,
	)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("context replay code = %v, want FailedPrecondition", status.Code(err))
	}
	if first.naks.Load() != 1 || second.naks.Load() != 1 {
		t.Fatalf("replay deliveries naks=%d/%d, want 1/1", first.naks.Load(), second.naks.Load())
	}
}

func TestFetchArtifactForwardsEncryptedWireBytesUnchanged(t *testing.T) {
	wire := bytes.Repeat([]byte{0xa5}, minimumHPKEArtifactBytes+23)
	digest := sha256.Sum256(wire)
	request := validArtifactRequest()
	chunk := &agentv1.ArtifactChunk{
		RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: request.Offset,
		Data: wire, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(wire)), EndOfArtifact: true,
	}
	state := allowedAuthorization(time.Hour)
	state.deploymentsAllowed = true
	control := &scriptedControl{
		fakeControl: defaultFakeControl(), states: []authorizationState{state},
		artifact: func(context.Context) ArtifactStream {
			return &oneArtifactStream{response: &controlv1.FetchArtifactResponse{Chunk: chunk}}
		},
	}
	gateway := newUnitGateway(t, control, nil)
	stream := &capturingArtifactServerStream{ctx: authenticatedTestContext(t)}
	if err := gateway.FetchArtifact(request, stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.sent) != 1 || stream.sent[0].Chunk != chunk || !bytes.Equal(stream.sent[0].Chunk.Data, wire) || !bytes.Equal(stream.sent[0].Chunk.ChunkSha256, digest[:]) {
		t.Fatal("Gateway changed encrypted artifact wire bytes or chunk metadata")
	}
}

func validEncryptedDeploymentCommand(kind agentv1.ArtifactKind) *agentv1.DeploymentCommand {
	command := validDeploymentCommand()
	descriptor := command.Artifacts[0]
	descriptor.Kind = kind
	descriptor.SizeBytes = minimumHPKEArtifactBytes
	if kind == agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION {
		descriptor.MediaType = frozenAgentConfigMediaType
	}
	descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
	descriptor.RecipientKeyId = proto.String(testArtifactRecipientKeyID)
	return command
}

type oneArtifactStream struct {
	response *controlv1.FetchArtifactResponse
}

func (s *oneArtifactStream) Recv() (*controlv1.FetchArtifactResponse, error) {
	if s.response == nil {
		return nil, io.EOF
	}
	response := s.response
	s.response = nil
	return response, nil
}

type capturingArtifactServerStream struct {
	ctx  context.Context
	sent []*agentv1.FetchArtifactResponse
}

func (s *capturingArtifactServerStream) Context() context.Context { return s.ctx }
func (s *capturingArtifactServerStream) Send(response *agentv1.FetchArtifactResponse) error {
	s.sent = append(s.sent, response)
	return nil
}
func (*capturingArtifactServerStream) SetHeader(metadata.MD) error  { return nil }
func (*capturingArtifactServerStream) SendHeader(metadata.MD) error { return nil }
func (*capturingArtifactServerStream) SetTrailer(metadata.MD)       {}
func (*capturingArtifactServerStream) SendMsg(any) error            { return nil }
func (*capturingArtifactServerStream) RecvMsg(any) error            { return io.EOF }
