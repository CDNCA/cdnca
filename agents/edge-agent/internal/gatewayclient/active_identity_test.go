package gatewayclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type rollbackRestoreFailureRuntime struct {
	fail atomic.Bool
}

type applyCrashRuntime struct {
	target string
	point  string
	loaded atomic.Bool
}

type activatingPointerManager struct {
	manager    *deployment.Manager
	command    deployment.Command
	once       sync.Once
	processErr error
}

type lifecycleBlockingDialer struct {
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (d *lifecycleBlockingDialer) Dial(ctx context.Context) (Connection, error) {
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	close(d.canceled)
	<-d.release
	return nil, ctx.Err()
}

func (m *activatingPointerManager) Process(ctx context.Context, command deployment.Command) (deployment.Result, error) {
	return m.manager.Process(ctx, command)
}

func (m *activatingPointerManager) Pointers() (deployment.Pointers, error) {
	pointers, err := m.manager.Pointers()
	if err != nil {
		return deployment.Pointers{}, err
	}
	m.once.Do(func() {
		_, m.processErr = m.manager.Process(context.Background(), m.command)
	})
	if m.processErr != nil {
		return deployment.Pointers{}, m.processErr
	}
	return pointers, nil
}

func (m *activatingPointerManager) Lookup(deploymentID string) (deployment.Result, bool, error) {
	return m.manager.Lookup(deploymentID)
}

func (r *applyCrashRuntime) Reload(_ context.Context, versionID, _ string) error {
	if r.target == "" || versionID != r.target {
		return nil
	}
	if r.point == "after_reload" {
		r.loaded.Store(true)
	}
	panic("deterministic apply crash")
}

func (*applyCrashRuntime) Healthy(context.Context, string) error { return nil }

type retentionGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	active           atomic.Bool
	sessions         atomic.Uint64
	hellos           chan *agentv1.AgentHello
	commands         []*agentv1.DeploymentCommand
	heartbeatOnce    sync.Once
	heartbeatSeen    chan struct{}
	releaseHeartbeat <-chan struct{}
}

type receiptHeartbeatBarrierGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	heartbeats atomic.Int32
	seen       chan struct{}
	once       sync.Once
}

type heartbeatCausationGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	supportReceipt bool
	observed       chan error
}

func (g *heartbeatCausationGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return ErrInvalidMessage
	}
	enabled := []*agentv1.Capability{activeConfigIdentityCapability()}
	if g.supportReceipt {
		for _, capability := range hello.Capabilities.Features {
			if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT && capability.ApiVersion == 1 {
				enabled = append(enabled, deploymentStatusAckReceiptCapability())
				break
			}
		}
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "heartbeat-causation-test",
			SessionId: uuid.NewString(), SessionEpoch: 7, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(5 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled,
		}},
	}); err != nil {
		return err
	}
	responseSequence := uint64(1)
	acknowledged := make(map[string]struct{})
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		heartbeat := request.GetHeartbeat()
		if heartbeat == nil {
			continue
		}
		if causationID := heartbeat.GetEvent().GetCausationId(); causationID != "" {
			_, exact := acknowledged[causationID]
			if !exact {
				g.observed <- fmt.Errorf("heartbeat causation %q does not name an acknowledged heartbeat", causationID)
			} else {
				g.observed <- nil
			}
			return nil
		}
		responseSequence++
		if err := stream.Send(&agentv1.ConnectResponse{
			Stream: responseMetadata(responseSequence),
			Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
				HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 7, ReceivedTime: timestamppb.Now(),
			}},
		}); err != nil {
			return err
		}
		acknowledged[heartbeat.Event.EventId] = struct{}{}
	}
}

func (g *receiptHeartbeatBarrierGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetHello() == nil {
		return ErrInvalidMessage
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "receipt-heartbeat-test",
			SessionId: uuid.NewString(), SessionEpoch: 7, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(5 * time.Millisecond), OfflineAfterDuration: durationpb.New(200 * time.Millisecond),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128,
			EnabledCapabilities: []*agentv1.Capability{activeConfigIdentityCapability(), deploymentStatusAckReceiptCapability()},
		}},
	}); err != nil {
		return err
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if request.GetHeartbeat() != nil {
			g.heartbeats.Add(1)
			g.once.Do(func() { close(g.seen) })
		}
	}
}

type receiptNegotiationGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	supportReceipt  bool
	dropTerminalAck bool
	command         *agentv1.DeploymentCommand
	acknowledged    chan struct{}
	once            sync.Once
	receipts        atomic.Int32
}

type countingDeploymentManager struct {
	manager DeploymentManager
	process atomic.Int32
}

func (m *countingDeploymentManager) Process(ctx context.Context, command deployment.Command) (deployment.Result, error) {
	m.process.Add(1)
	return m.manager.Process(ctx, command)
}

func (m *countingDeploymentManager) Pointers() (deployment.Pointers, error) {
	return m.manager.Pointers()
}

type delayedAuthoritativeCommandGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	supportReceipt             bool
	command                    *agentv1.DeploymentCommand
	sessions                   atomic.Uint64
	terminalBeforeCommand      atomic.Int32
	heartbeatACKsBeforeCommand atomic.Int32
	terminalAfterCommand       atomic.Int32
	terminalAcknowledgements   atomic.Int32
	accepted                   []*agentv1.DeploymentStatus
	terminalAcknowledged       chan struct{}
	terminalOnce               sync.Once
}

type legacyTerminalAckRecoveryGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	supportReceipt  bool
	command         *agentv1.DeploymentCommand
	sessions        atomic.Uint64
	publications    atomic.Int32
	replays         atomic.Int32
	firstAccepted   chan struct{}
	replayAcked     chan struct{}
	causalHeartbeat chan struct{}
	firstOnce       sync.Once
	replayOnce      sync.Once
	heartbeatOnce   sync.Once
	mu              sync.Mutex
	terminal        *agentv1.DeploymentStatus
	ack             *agentv1.DeploymentStatusAck
}

func (g *legacyTerminalAckRecoveryGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return ErrInvalidMessage
	}
	session := g.sessions.Add(1)
	enabled := []*agentv1.Capability{activeConfigIdentityCapability()}
	if g.supportReceipt {
		for _, capability := range hello.Capabilities.Features {
			if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT && capability.ApiVersion == 1 {
				enabled = append(enabled, deploymentStatusAckReceiptCapability())
				break
			}
		}
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "legacy-ack-recovery-test",
			SessionId: uuid.NewString(), SessionEpoch: session, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(10 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled,
		}},
	}); err != nil {
		return err
	}
	responseSequence := uint64(1)
	terminalSeen := 0
	if session == 1 {
		responseSequence++
		if err := stream.Send(&agentv1.ConnectResponse{
			Stream: responseMetadata(responseSequence),
			Payload: &agentv1.ConnectResponse_DeploymentCommand{
				DeploymentCommand: proto.Clone(g.command).(*agentv1.DeploymentCommand),
			},
		}); err != nil {
			return err
		}
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if terminal := request.GetDeploymentStatus(); terminal != nil && terminalDeploymentState(terminal.State) {
			if terminal.DeploymentId != g.command.DeploymentId || terminal.Attempt != g.command.Attempt || terminal.ConfigVersionId != g.command.ConfigVersionId {
				continue
			}
			if session == 1 {
				terminalSeen++
				if terminalSeen == 1 {
					continue
				}
				g.mu.Lock()
				g.terminal = proto.Clone(terminal).(*agentv1.DeploymentStatus)
				g.ack = &agentv1.DeploymentStatusAck{
					StatusEventId: terminal.Event.EventId, DeploymentId: terminal.DeploymentId, Attempt: terminal.Attempt,
					ConfigVersionId: terminal.ConfigVersionId, TransitionSequence: terminal.TransitionSequence,
					PersistedTime: timestamppb.Now(),
				}
				g.mu.Unlock()
				g.publications.Add(1)
				g.firstOnce.Do(func() { close(g.firstAccepted) })
				return grpcstatus.Error(codes.Unavailable, "disconnect before legacy terminal ACK send")
			}
			g.mu.Lock()
			persisted := proto.Clone(g.terminal).(*agentv1.DeploymentStatus)
			ack := proto.Clone(g.ack).(*agentv1.DeploymentStatusAck)
			g.mu.Unlock()
			if !proto.Equal(terminal, persisted) {
				return ErrInvalidMessage
			}
			g.replays.Add(1)
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_DeploymentStatusAck{
					DeploymentStatusAck: ack,
				},
			}); err != nil {
				return err
			}
			g.replayOnce.Do(func() { close(g.replayAcked) })
			continue
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: session, ReceivedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
			if session == 2 {
				g.heartbeatOnce.Do(func() { close(g.causalHeartbeat) })
			}
		}
	}
}

func (g *delayedAuthoritativeCommandGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return ErrInvalidMessage
	}
	session := g.sessions.Add(1)
	enabled := []*agentv1.Capability{activeConfigIdentityCapability()}
	if g.supportReceipt {
		for _, capability := range hello.Capabilities.Features {
			if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT && capability.ApiVersion == 1 {
				enabled = append(enabled, deploymentStatusAckReceiptCapability())
				break
			}
		}
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "delayed-command-test",
			SessionId: uuid.NewString(), SessionEpoch: session, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(10 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled,
		}},
	}); err != nil {
		return err
	}
	responseSequence := uint64(1)
	commandSent := false
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if statusUpdate := request.GetDeploymentStatus(); statusUpdate != nil && terminalDeploymentState(statusUpdate.State) {
			if !commandSent {
				g.terminalBeforeCommand.Add(1)
				if session == 1 {
					continue
				}
				responseSequence++
				if err := stream.Send(&agentv1.ConnectResponse{
					Stream: responseMetadata(responseSequence),
					Payload: &agentv1.ConnectResponse_DeploymentCommand{
						DeploymentCommand: proto.Clone(g.command).(*agentv1.DeploymentCommand),
					},
				}); err != nil {
					return err
				}
				commandSent = true
				continue
			}
			g.terminalAfterCommand.Add(1)
			g.accepted = append(g.accepted, proto.Clone(statusUpdate).(*agentv1.DeploymentStatus))
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_DeploymentStatusAck{DeploymentStatusAck: &agentv1.DeploymentStatusAck{
					StatusEventId: statusUpdate.Event.EventId, DeploymentId: statusUpdate.DeploymentId,
					Attempt: statusUpdate.Attempt, ConfigVersionId: statusUpdate.ConfigVersionId,
					TransitionSequence: statusUpdate.TransitionSequence, PersistedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
			g.terminalAcknowledgements.Add(1)
			g.terminalOnce.Do(func() { close(g.terminalAcknowledged) })
			continue
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: session, ReceivedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
			if !commandSent {
				g.heartbeatACKsBeforeCommand.Add(1)
				return grpcstatus.Error(codes.Unavailable, "deterministic reconnect after unbound terminal")
			}
		}
	}
}

func (g *receiptNegotiationGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return ErrInvalidMessage
	}
	enabled := []*agentv1.Capability{activeConfigIdentityCapability()}
	if g.supportReceipt {
		for _, capability := range hello.Capabilities.Features {
			if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT && capability.ApiVersion == 1 {
				enabled = append(enabled, deploymentStatusAckReceiptCapability())
				break
			}
		}
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "receipt-negotiation-test",
			SessionId: uuid.NewString(), SessionEpoch: 9, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(10 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled,
		}},
	}); err != nil {
		return err
	}
	responseSequence := uint64(1)
	if g.command != nil {
		responseSequence++
		if err := stream.Send(&agentv1.ConnectResponse{
			Stream: responseMetadata(responseSequence),
			Payload: &agentv1.ConnectResponse_DeploymentCommand{
				DeploymentCommand: proto.Clone(g.command).(*agentv1.DeploymentCommand),
			},
		}); err != nil {
			return err
		}
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if status := request.GetDeploymentStatus(); status != nil && terminalDeploymentState(status.State) {
			g.once.Do(func() { close(g.acknowledged) })
			if g.dropTerminalAck {
				continue
			}
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_DeploymentStatusAck{DeploymentStatusAck: &agentv1.DeploymentStatusAck{
					StatusEventId: status.Event.EventId, DeploymentId: status.DeploymentId, Attempt: status.Attempt,
					ConfigVersionId: status.ConfigVersionId, TransitionSequence: status.TransitionSequence,
					PersistedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
			continue
		}
		if request.GetDeploymentStatusAckReceipt() != nil {
			g.receipts.Add(1)
			continue
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 9, ReceivedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
		}
	}
}

func (g *retentionGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return ErrInvalidMessage
	}
	select {
	case g.hellos <- proto.Clone(hello).(*agentv1.AgentHello):
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	epoch := g.sessions.Add(1)
	enabled := []*agentv1.Capability(nil)
	if g.active.Load() {
		enabled = []*agentv1.Capability{activeConfigIdentityCapability()}
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "retention-test",
			SessionId: uuid.NewString(), SessionEpoch: epoch, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(10 * time.Millisecond), OfflineAfterDuration: durationpb.New(5 * time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled,
		}},
	}); err != nil {
		return err
	}
	responseSequence := uint64(1)
	if !g.active.Load() {
		for _, command := range g.commands {
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_DeploymentCommand{
					DeploymentCommand: proto.Clone(command).(*agentv1.DeploymentCommand),
				},
			}); err != nil {
				return err
			}
		}
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			if !g.active.Load() && g.heartbeatSeen != nil {
				g.heartbeatOnce.Do(func() { close(g.heartbeatSeen) })
				select {
				case <-g.releaseHeartbeat:
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
			}
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: epoch, ReceivedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
		}
	}
}

func (r *rollbackRestoreFailureRuntime) Reload(context.Context, string, string) error {
	if r.fail.Load() {
		return errors.New("runtime reload failed")
	}
	return nil
}

func (*rollbackRestoreFailureRuntime) Healthy(context.Context, string) error { return nil }

func TestActiveConfigIdentityRecoversFromVerifiedWireAndPointers(t *testing.T) {
	client, manager, command, wire, root, _ := activeIdentityClient(t)
	record := persistActiveIdentityCommand(t, client, command, wire)

	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.CurrentConfigIdentity != nil || len(hello.ActiveDeployments) != 1 || hello.ActiveDeployments[0].ObservedActiveConfigIdentity != nil {
		t.Fatalf("unfinished APPLY claimed active identity: %+v", hello)
	}
	result, found, err := manager.Lookup(command.DeploymentId)
	if err != nil || !found {
		t.Fatalf("Lookup() = (%+v, %t, %v)", result, found, err)
	}
	if err := client.completeDeploymentRecord(record.RecordKey, statusesForResult(command, result), true); err != nil {
		t.Fatal(err)
	}
	hello, err = client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertIdentityCapability(t, hello.Capabilities.Features)
	assertActiveIdentity(t, hello.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := hex.DecodeString(pointers.CurrentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hello.CurrentConfigIdentity.ArtifactSha256, manifestDigest) {
		t.Fatal("artifact wire digest was confused with the release manifest digest")
	}
	if len(hello.ActiveDeployments) != 0 {
		t.Fatalf("active deployments = %d, want 0", len(hello.ActiveDeployments))
	}

	heartbeat, err := client.heartbeat(7, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCapability(t, heartbeat.ActiveConfigIdentityCapability)
	assertActiveIdentity(t, heartbeat.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)
	assertActiveIdentity(t, heartbeat.Runtime.LoadedConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)
	legacyHeartbeat, err := client.heartbeat(7, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if legacyHeartbeat.ActiveConfigIdentityCapability != nil || legacyHeartbeat.CurrentConfigIdentity != nil || legacyHeartbeat.PreviousConfigIdentity != nil || legacyHeartbeat.Runtime.LoadedConfigIdentity != nil {
		t.Fatal("active identity escaped a session without negotiated capability v1")
	}

	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	final := statuses[len(statuses)-1]
	assertCapability(t, final.ActiveConfigIdentityCapability)
	assertActiveIdentity(t, final.ActiveConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)

	legacyStream := &testConnectStream{ctx: context.Background()}
	if _, err := client.sendRecordStatuses(legacyStream, 1, persisted, map[string]struct{}{}, false, false); err != nil {
		t.Fatal(err)
	}
	legacyFinal := legacyStream.sent[len(legacyStream.sent)-1].GetDeploymentStatus()
	if legacyFinal.ActiveConfigIdentityCapability != nil || legacyFinal.ActiveConfigIdentity != nil {
		t.Fatal("durable active identity was replayed without negotiated capability")
	}
	enabledStream := &testConnectStream{ctx: context.Background()}
	if _, err := client.sendRecordStatuses(enabledStream, 1, persisted, map[string]struct{}{}, false, true); err != nil {
		t.Fatal(err)
	}
	enabledFinal := enabledStream.sent[len(enabledStream.sent)-1].GetDeploymentStatus()
	assertActiveIdentity(t, enabledFinal.ActiveConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)

	restartedManager, err := deployment.NewManager(root, testPrechecker{}, &testRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	closeGatewayClientForRestart(t, client)
	restarted, err := New(client.config, &failingDialer{}, restartedManager, client.trust)
	if err != nil {
		t.Fatal(err)
	}
	restartedHello, err := restarted.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, restartedHello.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)
}

func TestActiveConfigIdentityIgnoresUnfinishedAndFailedSameVersionCandidates(t *testing.T) {
	client, manager, command, wire, _, privateKey := activeIdentityClient(t)
	proof := persistActiveIdentityCommand(t, client, command, wire)
	completeDeploymentWithoutAck(t, client, manager, proof)

	candidate := proto.Clone(command).(*agentv1.DeploymentCommand)
	candidate.DeploymentId = uuid.NewString()
	candidate.RolloutId = uuid.NewString()
	candidate.Event.EventId = uuid.NewString()
	candidate.Event.RequestId = uuid.NewString()
	candidate.Artifacts[0].ArtifactId = uuid.NewString()
	candidateWire := append(append([]byte(nil), wire...), '\n')
	digest := sha256.Sum256(candidateWire)
	candidate.Artifacts[0].SizeBytes = uint64(len(candidateWire))
	candidate.Artifacts[0].Sha256 = digest[:]
	candidate.Artifacts[0].Signature = ed25519.Sign(privateKey, candidateWire)
	candidateRecord := persistActiveIdentityCommand(t, client, candidate, candidateWire)

	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)

	failed := failedStatus(candidate, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "same-version retry failed", false)
	if err := client.store.appendStatuses(candidateRecord.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
		t.Fatal(err)
	}
	hello, err = client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)
}

func TestActiveConfigSnapshotRetriesConcurrentActivation(t *testing.T) {
	client, manager, current, currentWire, _, privateKey := activeIdentityClient(t)
	currentRecord := persistActiveIdentityCommand(t, client, current, currentWire)
	completeDeploymentWithoutAck(t, client, manager, currentRecord)

	next, nextWire := nextActiveIdentityDeployment(t, current, privateKey)
	nextRecord := persistActiveIdentityCommand(t, client, next, nextWire)
	bundle, err := decodeConfigurationBundle(nextWire)
	if err != nil {
		t.Fatal(err)
	}
	tracing := &activatingPointerManager{manager: manager, command: deployment.Command{
		DeploymentID: next.DeploymentId, Attempt: next.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: next.ConfigVersionId, PreviousVersionID: current.ConfigVersionId, Bundle: bundle,
	}}
	client.manager = tracing

	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.CurrentConfigVersionId == nil || hello.GetCurrentConfigVersionId() != next.ConfigVersionId || hello.CurrentConfigIdentity != nil {
		t.Fatalf("concurrent activation produced a mixed snapshot: %+v", hello)
	}
	if persisted, err := client.store.record(nextRecord.RecordKey); err != nil || persisted == nil || persisted.ExecutionDone {
		t.Fatalf("concurrent activation journal = (%+v, %v)", persisted, err)
	}
}

func TestActiveConfigIdentityRequiresCanonicalCommandVersions(t *testing.T) {
	client, _, command, _, _, _ := activeIdentityClient(t)
	invalid := proto.Clone(command).(*agentv1.DeploymentCommand)
	invalid.ConfigVersionId = "cfg-v1"
	if err := validateCommandIdentity(invalid, client.config, true); err == nil {
		t.Fatal("noncanonical command config version was accepted")
	}
	invalid = proto.Clone(command).(*agentv1.DeploymentCommand)
	invalid.PreviousConfigVersionId = proto.String("cfg-v0")
	if err := validateCommand(invalid, client.config, client.now(), true); err == nil {
		t.Fatal("noncanonical previous config version was accepted")
	}
}

func TestActiveConfigIdentityFailsClosedForMissingCorruptAndConflictingCandidates(t *testing.T) {
	client, _, command, wire, _, privateKey := activeIdentityClient(t)
	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.CurrentConfigVersionId == nil || hello.CurrentConfigIdentity != nil {
		t.Fatalf("missing candidate hello = %+v", hello)
	}

	first := persistActiveIdentityCommand(t, client, command, wire)
	corrupt := append([]byte(nil), wire...)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(client.store.artifactPath(first.RecordKey), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	hello, err = client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.CurrentConfigIdentity != nil {
		t.Fatal("corrupt artifact bytes produced an active identity")
	}
	if err := os.WriteFile(client.store.artifactPath(first.RecordKey), wire, 0o600); err != nil {
		t.Fatal(err)
	}

	secondWire := append(append([]byte(nil), wire...), '\n')
	second := proto.Clone(command).(*agentv1.DeploymentCommand)
	second.DeploymentId = uuid.NewString()
	second.Event.EventId = uuid.NewString()
	second.Event.RequestId = uuid.NewString()
	second.Artifacts[0].ArtifactId = uuid.NewString()
	digest := sha256.Sum256(secondWire)
	second.Artifacts[0].SizeBytes = uint64(len(secondWire))
	second.Artifacts[0].Sha256 = digest[:]
	second.Artifacts[0].Signature = ed25519.Sign(privateKey, secondWire)
	persistActiveIdentityCommand(t, client, second, secondWire)
	hello, err = client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.CurrentConfigIdentity != nil {
		t.Fatal("conflicting verified wire digests produced an active identity")
	}
}

func TestActiveConfigIdentityCachesStableVerifiedJournalSnapshot(t *testing.T) {
	client, manager, command, wire, _, _ := activeIdentityClient(t)
	record := persistActiveIdentityCommand(t, client, command, wire)
	completeDeploymentWithoutAck(t, client, manager, record)

	first, err := client.heartbeat(7, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, first.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)

	corrupt := append([]byte(nil), wire...)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(client.store.artifactPath(record.RecordKey), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := client.heartbeat(7, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, second.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)

	client.activeIdentity.mu.Lock()
	client.activeIdentity.initialized = false
	client.activeIdentity.mu.Unlock()
	third, err := client.heartbeat(7, 3, true)
	if err != nil {
		t.Fatal(err)
	}
	if third.CurrentConfigIdentity != nil || third.Runtime.LoadedConfigIdentity != nil || third.Runtime.LoadedConfigVersionId != nil {
		t.Fatalf("changed journal reused stale active identity: %+v", third)
	}
}

func TestRollbackFailedDoesNotClaimLoadedActiveIdentity(t *testing.T) {
	client, _, command, wire, _, _ := activeIdentityClient(t)
	record := persistActiveIdentityCommand(t, client, command, wire)
	rollbackFailed := statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED, client.now(), false, "ROLLBACK_HEALTH_FAILED", "previous release failed health verification", 0)
	if err := client.completeDeploymentRecord(record.RecordKey, []*agentv1.DeploymentStatus{rollbackFailed}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	final := statuses[len(statuses)-1]
	assertCapability(t, final.ActiveConfigIdentityCapability)
	if final.ActiveConfigIdentity != nil {
		t.Fatalf("rollback-failed status claimed active identity: %+v", final.ActiveConfigIdentity)
	}

	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.CurrentConfigIdentity != nil {
		t.Fatalf("rollback-failed hello claimed active identity: %+v", hello.CurrentConfigIdentity)
	}
	heartbeat, err := client.heartbeat(7, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.CurrentConfigIdentity != nil || heartbeat.Runtime.LoadedConfigIdentity != nil || heartbeat.Runtime.LoadedConfigVersionId != nil {
		t.Fatalf("rollback-failed heartbeat claimed loaded identity: %+v", heartbeat)
	}

	replayed := proto.Clone(rollbackFailed).(*agentv1.DeploymentStatus)
	replayed.ActiveConfigIdentityCapability = activeConfigIdentityCapability()
	replayed.ActiveConfigIdentity = testActiveConfigIdentity(command.ConfigVersionId, command.Artifacts[0].Sha256)
	forSession := deploymentStatusForSession(replayed, true)
	if forSession.ActiveConfigIdentity != nil {
		t.Fatalf("non-healthy durable replay retained unbound identity: %+v", forSession.ActiveConfigIdentity)
	}
}

func TestExplicitRollbackRestoreFailureDoesNotClaimBaselineLoadedIdentity(t *testing.T) {
	client, _, baseline, wire, _, _ := activeIdentityClient(t)
	persistActiveIdentityCommand(t, client, baseline, wire)
	rollback := proto.Clone(baseline).(*agentv1.DeploymentCommand)
	rollback.Event.EventId = uuid.NewString()
	rollback.Event.RequestId = uuid.NewString()
	rollback.DeploymentId = uuid.NewString()
	rollback.RolloutId = uuid.NewString()
	rollback.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	rollback.ConfigVersionId = uuid.NewString()
	rollback.PreviousConfigVersionId = proto.String(baseline.ConfigVersionId)
	rollback.Artifacts = nil
	record, _, err := client.store.putCommand(rollback, deliveredStatus(rollback))
	if err != nil {
		t.Fatal(err)
	}
	rollbackFailed := statusFor(rollback, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED, client.now(), false, "ROLLBACK_RESTORE_FAILED", "rollback target failed and the original release could not be confirmed", 0)
	if err := client.completeDeploymentRecord(record.RecordKey, []*agentv1.DeploymentStatus{rollbackFailed}, true); err != nil {
		t.Fatal(err)
	}

	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.GetCurrentConfigVersionId() != baseline.ConfigVersionId || rollback.ConfigVersionId == baseline.ConfigVersionId {
		t.Fatalf("rollback target/baseline fixture is invalid: hello=%+v rollback=%+v", hello, rollback)
	}
	if hello.CurrentConfigIdentity != nil {
		t.Fatalf("explicit rollback restore failure claimed baseline identity: %+v", hello.CurrentConfigIdentity)
	}
	heartbeat, err := client.heartbeat(7, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.CurrentConfigIdentity != nil || heartbeat.Runtime.LoadedConfigIdentity != nil || heartbeat.Runtime.LoadedConfigVersionId != nil {
		t.Fatalf("explicit rollback restore failure claimed loaded baseline: %+v", heartbeat)
	}
}

func TestActiveConfigIdentityCrashWindowUsesManagerTerminalState(t *testing.T) {
	runtime := &rollbackRestoreFailureRuntime{}
	client, manager, first, firstWire, root, privateKey := activeIdentityClientWithRuntime(t, runtime)
	firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
	completeDeploymentWithoutAck(t, client, manager, firstRecord)
	second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
	secondBundle, err := decodeConfigurationBundle(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: secondBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(second) = (%+v, %v)", result, err)
	}
	secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
	completeDeploymentWithoutAck(t, client, manager, secondRecord)

	rollback := proto.Clone(second).(*agentv1.DeploymentCommand)
	rollback.Event.EventId = uuid.NewString()
	rollback.Event.RequestId = uuid.NewString()
	rollback.DeploymentId = uuid.NewString()
	rollback.RolloutId = uuid.NewString()
	rollback.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	rollback.ConfigVersionId = first.ConfigVersionId
	rollback.PreviousConfigVersionId = proto.String(second.ConfigVersionId)
	rollback.Artifacts = nil
	record, _, err := client.store.putCommand(rollback, deliveredStatus(rollback))
	if err != nil {
		t.Fatal(err)
	}
	before, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, before.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)

	runtime.fail.Store(true)
	result, err = manager.Process(context.Background(), deployment.Command{
		DeploymentID: rollback.DeploymentId, Attempt: rollback.Attempt, Action: deployment.ActionRollback,
		ConfigVersionID: rollback.ConfigVersionId, PreviousVersionID: rollback.GetPreviousConfigVersionId(),
	})
	if err != nil || result.State != deployment.StateRollbackFailed || result.ErrorCode != "ROLLBACK_RESTORE_FAILED" || result.RunningConfigUnchanged {
		t.Fatalf("Process(rollback) = (%+v, %v)", result, err)
	}
	assertUnknownLoadedIdentity(t, client)

	restartedManager, err := deployment.NewManager(root, testPrechecker{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	closeGatewayClientForRestart(t, client)
	restarted, err := New(client.config, &failingDialer{}, restartedManager, client.trust)
	if err != nil {
		t.Fatal(err)
	}
	assertUnknownLoadedIdentity(t, restarted)
	if err := restarted.executeRecord(context.Background(), nil, record.RecordKey, restarted.config.MaxArtifactChunkBytes, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := restarted.store.record(record.RecordKey)
	if err != nil || persisted == nil || !persisted.ExecutionDone {
		t.Fatalf("terminal replay record = (%+v, %v)", persisted, err)
	}
	assertUnknownLoadedIdentity(t, restarted)
}

func TestActiveConfigIdentityUnknownAcrossApplyActivationCrashWindows(t *testing.T) {
	for _, test := range []struct {
		name       string
		point      string
		wantLoaded bool
	}{
		{name: "after pointer switch before reload", point: "after_switch"},
		{name: "after reload before pointer persistence", point: "after_reload", wantLoaded: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &applyCrashRuntime{}
			client, _, first, firstWire, root, privateKey := activeIdentityClientWithRuntime(t, runtime)
			persistActiveIdentityCommand(t, client, first, firstWire)
			second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
			record := persistActiveIdentityCommand(t, client, second, secondWire)
			bundle, err := decodeConfigurationBundle(secondWire)
			if err != nil {
				t.Fatal(err)
			}
			runtime.target = second.ConfigVersionId
			runtime.point = test.point
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("activation did not reach the deterministic crash point")
					}
				}()
				_, _ = client.manager.Process(context.Background(), deployment.Command{
					DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
					ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: bundle,
				})
			}()
			if runtime.loaded.Load() != test.wantLoaded {
				t.Fatalf("runtime loaded = %t, want %t", runtime.loaded.Load(), test.wantLoaded)
			}
			persisted, err := client.store.record(record.RecordKey)
			if err != nil || persisted == nil || persisted.ExecutionDone {
				t.Fatalf("unfinished Gateway record = (%+v, %v)", persisted, err)
			}
			restartedManager, err := deployment.NewManager(root, testPrechecker{}, runtime)
			if err != nil {
				t.Fatal(err)
			}
			closeGatewayClientForRestart(t, client)
			restarted, err := New(client.config, &failingDialer{}, restartedManager, client.trust)
			if err != nil {
				t.Fatal(err)
			}
			assertUnknownLoadedIdentity(t, restarted)
		})
	}
}

func TestRuntimeUncertaintyDoesNotUseOccurredTimeAcrossDeployments(t *testing.T) {
	for _, test := range []struct {
		name        string
		failureTime func(time.Time) time.Time
	}{
		{name: "clock rollback", failureTime: func(now time.Time) time.Time { return now.Add(-time.Hour) }},
		{name: "same timestamp", failureTime: func(now time.Time) time.Time { return now }},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _, current, wire, _, _ := activeIdentityClient(t)
			currentRecord := persistActiveIdentityCommand(t, client, current, wire)
			now := client.now().UTC()
			healthy := statusFor(current, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, now, false, "", "", 0)
			healthy.ActiveConfigIdentityCapability = activeConfigIdentityCapability()
			healthy.ActiveConfigIdentity = testActiveConfigIdentity(current.ConfigVersionId, current.Artifacts[0].Sha256)
			if err := client.store.appendStatuses(currentRecord.RecordKey, []*agentv1.DeploymentStatus{healthy}, true); err != nil {
				t.Fatal(err)
			}

			rollback := proto.Clone(current).(*agentv1.DeploymentCommand)
			rollback.Event.EventId = uuid.NewString()
			rollback.Event.RequestId = uuid.NewString()
			rollback.DeploymentId = uuid.NewString()
			rollback.RolloutId = uuid.NewString()
			rollback.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
			rollback.ConfigVersionId = uuid.NewString()
			rollback.PreviousConfigVersionId = proto.String(current.ConfigVersionId)
			rollback.Artifacts = nil
			record, _, err := client.store.putCommand(rollback, deliveredStatus(rollback))
			if err != nil {
				t.Fatal(err)
			}
			failed := statusFor(rollback, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED, test.failureTime(now), false, "ROLLBACK_RESTORE_FAILED", "rollback restore failed", 0)
			failed.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "rollback restore failed"}
			failed.ActiveConfigIdentityCapability = activeConfigIdentityCapability()
			if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
				t.Fatal(err)
			}
			assertUnknownLoadedIdentity(t, client)
		})
	}
}

func TestLegacyGatewayRetentionIsBoundedAndSurvivesCapabilityUpgrade(t *testing.T) {
	client, manager, first, firstWire, _, privateKey := activeIdentityClient(t)
	firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
	completeDeploymentWithoutAck(t, client, manager, firstRecord)
	second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
	secondBundle, err := decodeConfigurationBundle(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: secondBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(second) = (%+v, %v)", result, err)
	}
	secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
	completeDeploymentWithoutAck(t, client, manager, secondRecord)

	client.config.MaxActiveDeployments = 1
	legacyCommands := make([]*agentv1.DeploymentCommand, 0, client.config.MaxActiveDeployments+8)
	for index := 0; index < client.config.MaxActiveDeployments+8; index++ {
		command := proto.Clone(second).(*agentv1.DeploymentCommand)
		command.Event.EventId = uuid.NewString()
		command.Event.RequestId = uuid.NewString()
		command.DeploymentId = uuid.NewString()
		command.RolloutId = uuid.NewString()
		command.ConfigVersionId = uuid.NewString()
		command.Artifacts[0].ArtifactId = uuid.NewString()
		record, _, err := client.store.putCommand(command, deliveredStatus(command))
		if err != nil {
			t.Fatal(err)
		}
		failed := failedStatus(command, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", false)
		if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
			t.Fatal(err)
		}
		legacyCommands = append(legacyCommands, proto.Clone(command).(*agentv1.DeploymentCommand))
	}
	hello, err := client.agentHello()
	if err != nil {
		t.Fatalf("completed legacy history exhausted active deployment capacity: %v", err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
	assertActiveIdentity(t, hello.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)

	heartbeatSeen := make(chan struct{})
	releaseHeartbeat := make(chan struct{})
	gateway := &retentionGateway{
		hellos: make(chan *agentv1.AgentHello, 4), commands: legacyCommands,
		heartbeatSeen: heartbeatSeen, releaseHeartbeat: releaseHeartbeat,
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	connection, err := grpc.NewClient("passthrough:///legacy-retention", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, sessionErr := client.runSession(ctx, agentv1.NewAgentGatewayServiceClient(connection))
		done <- sessionErr
	}()
	select {
	case <-heartbeatSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("legacy session did not reach the causal heartbeat barrier")
	}
	select {
	case legacyHello := <-gateway.hellos:
		assertActiveIdentity(t, legacyHello.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
		assertActiveIdentity(t, legacyHello.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
	case <-time.After(2 * time.Second):
		t.Fatal("legacy session did not send AgentHello")
	}
	pending := proto.Clone(second).(*agentv1.DeploymentCommand)
	pending.Event.EventId = uuid.NewString()
	pending.Event.RequestId = uuid.NewString()
	pending.DeploymentId = uuid.NewString()
	pending.RolloutId = uuid.NewString()
	pending.ConfigVersionId = uuid.NewString()
	pending.Artifacts[0].ArtifactId = uuid.NewString()
	pendingRecord, _, err := client.store.putCommand(pending, deliveredStatus(pending))
	if err != nil {
		t.Fatal(err)
	}
	close(releaseHeartbeat)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		markers, _ := filepath.Glob(filepath.Join(client.store.directory, "*"+deploymentStatusAckSuffix))
		files, _ := filepath.Glob(filepath.Join(client.store.directory, "*.json"))
		if len(files) <= client.config.MaxActiveDeployments+4 {
			break
		}
		select {
		case sessionErr := <-done:
			t.Fatalf("legacy session exited before bounded compaction: %v", sessionErr)
		case <-deadline.C:
			t.Fatalf("legacy bounded compaction timed out with %d ACKs and %d records", len(markers), len(files))
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		t.Fatalf("legacy session error = %v, want canceled session", err)
	}
	if persisted, err := client.store.record(pendingRecord.RecordKey); err != nil || persisted == nil || persisted.ExecutionDone {
		t.Fatalf("pending record was lost during legacy compaction: (%+v, %v)", persisted, err)
	}
	files, err := filepath.Glob(filepath.Join(client.store.directory, "*.json"))
	if err != nil || len(files) > client.config.MaxActiveDeployments+4 {
		t.Fatalf("legacy retained records = %d, err=%v", len(files), err)
	}

	gateway.active.Store(true)
	upgradeCtx, upgradeCancel := context.WithCancel(context.Background())
	upgradeDone := make(chan error, 1)
	go func() {
		_, sessionErr := client.runSession(upgradeCtx, agentv1.NewAgentGatewayServiceClient(connection))
		upgradeDone <- sessionErr
	}()
	var upgradedHello *agentv1.AgentHello
	select {
	case upgradedHello = <-gateway.hellos:
	case <-time.After(2 * time.Second):
		t.Fatal("upgraded session did not send AgentHello")
	}
	assertActiveIdentity(t, upgradedHello.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
	assertActiveIdentity(t, upgradedHello.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
	upgradeCancel()
	if err := <-upgradeDone; !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		t.Fatalf("upgraded session error = %v, want canceled session", err)
	}
}

func TestDeploymentHistoryCompactsAcknowledgedTerminalRecords(t *testing.T) {
	client, manager, first, firstWire, _, privateKey := activeIdentityClient(t)
	firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
	completeAndAcknowledgeDeployment(t, client, manager, firstRecord)

	second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
	secondBundle, err := decodeConfigurationBundle(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: secondBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(second) = (%+v, %v)", result, err)
	}
	secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
	completeAndAcknowledgeDeployment(t, client, manager, secondRecord)

	const historical = 9
	for index := 0; index < historical; index++ {
		command := proto.Clone(second).(*agentv1.DeploymentCommand)
		command.Event.EventId = uuid.NewString()
		command.Event.RequestId = uuid.NewString()
		command.DeploymentId = uuid.NewString()
		command.RolloutId = uuid.NewString()
		command.ConfigVersionId = uuid.NewString()
		command.Artifacts[0].ArtifactId = uuid.NewString()
		record, _, err := client.store.putCommand(command, deliveredStatus(command))
		if err != nil {
			t.Fatal(err)
		}
		failed := failedStatus(command, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "test failure", true)
		if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
			t.Fatal(err)
		}
		persisted, err := client.store.record(record.RecordKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted)); err != nil {
			t.Fatal(err)
		}
	}

	pendingKeys := make([]string, 0, 2)
	for range 2 {
		command := proto.Clone(second).(*agentv1.DeploymentCommand)
		command.Event.EventId = uuid.NewString()
		command.Event.RequestId = uuid.NewString()
		command.DeploymentId = uuid.NewString()
		command.RolloutId = uuid.NewString()
		command.ConfigVersionId = uuid.NewString()
		command.Artifacts[0].ArtifactId = uuid.NewString()
		record, _, err := client.store.putCommand(command, deliveredStatus(command))
		if err != nil {
			t.Fatal(err)
		}
		pendingKeys = append(pendingKeys, record.RecordKey)
	}
	client.config.MaxActiveDeployments = len(pendingKeys)
	before, err := filepath.Glob(filepath.Join(client.store.directory, "*.json"))
	if err != nil || len(before) <= client.config.MaxActiveDeployments {
		t.Fatalf("pre-compaction records = %d, err=%v", len(before), err)
	}

	closeGatewayClientForRestart(t, client)
	restarted, err := New(client.config, &failingDialer{}, manager, client.trust)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := restarted.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
	assertActiveIdentity(t, hello.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
	if len(hello.ActiveDeployments) != len(pendingKeys) {
		t.Fatalf("active deployments = %d, want %d", len(hello.ActiveDeployments), len(pendingKeys))
	}
	for _, key := range pendingKeys {
		record, err := restarted.store.record(key)
		if err != nil || record == nil || record.ExecutionDone {
			t.Fatalf("pending record %s = (%+v, %v)", key, record, err)
		}
	}
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatal(err)
	}
	history, err := restarted.deploymentHistory(pointers)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.replay) != len(pendingKeys) || len(history.records) > len(pendingKeys)+4 {
		t.Fatalf("bounded history = records:%d replay:%d", len(history.records), len(history.replay))
	}
	after, err := filepath.Glob(filepath.Join(restarted.store.directory, "*.json"))
	if err != nil || len(after) > len(pendingKeys)+4 {
		t.Fatalf("post-compaction records = %d, err=%v", len(after), err)
	}
	markers, err := filepath.Glob(filepath.Join(restarted.store.directory, "*"+deploymentStatusAckSuffix))
	if err != nil || len(markers) > 4 {
		t.Fatalf("post-compaction acknowledgement markers = %d, err=%v", len(markers), err)
	}

	closeGatewayClientForRestart(t, restarted)
	secondRestart, err := New(client.config, &failingDialer{}, manager, client.trust)
	if err != nil {
		t.Fatal(err)
	}
	hello, err = secondRestart.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
	assertActiveIdentity(t, hello.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
}

func TestDeploymentRecordSnapshotSkipsEntriesRemovedBeforeLoad(t *testing.T) {
	for _, name := range []string{"deploymentHistory", "receiptDisabling", "terminalReplay", "compaction"} {
		t.Run(name, func(t *testing.T) {
			client, _, command, wire, _, _ := activeIdentityClient(t)
			first := persistActiveIdentityCommand(t, client, command, wire)
			secondCommand := proto.Clone(command).(*agentv1.DeploymentCommand)
			secondCommand.Event.EventId = uuid.NewString()
			secondCommand.Event.RequestId = uuid.NewString()
			secondCommand.DeploymentId = uuid.NewString()
			secondCommand.RolloutId = uuid.NewString()
			secondCommand.ConfigVersionId = uuid.NewString()
			secondCommand.Artifacts[0].ArtifactId = uuid.NewString()
			second := persistActiveIdentityCommand(t, client, secondCommand, wire)

			visited := 0
			client.store.mu.Lock()
			err := client.store.scanDeploymentRecordsLocked(func(record *durableRecord) error {
				if record == nil {
					return errors.New("missing snapshot entry reached a deployment record visitor")
				}
				visited++
				if visited == 1 {
					other := first.RecordKey
					if record.RecordKey == first.RecordKey {
						other = second.RecordKey
					}
					if err := os.Remove(filepath.Join(client.store.directory, other+".json")); err != nil {
						return err
					}
				}
				switch name {
				case "deploymentHistory":
					_ = record.ExecutionDone
				case "receiptDisabling", "terminalReplay", "compaction":
					_, err := client.store.loadDeploymentStatusAckLocked(record.RecordKey)
					return err
				}
				return nil
			})
			client.store.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if visited != 1 {
				t.Fatalf("deployment record visitors = %d, want only the surviving snapshot entry", visited)
			}
		})
	}
	t.Run("presentCorruptRecordFailsClosed", func(t *testing.T) {
		client, _, command, wire, _, _ := activeIdentityClient(t)
		record := persistActiveIdentityCommand(t, client, command, wire)
		if err := os.WriteFile(filepath.Join(client.store.directory, record.RecordKey+".json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		client.store.mu.Lock()
		err := client.store.scanDeploymentRecordsLocked(func(*durableRecord) error { return nil })
		client.store.mu.Unlock()
		if err == nil {
			t.Fatal("present corrupt deployment record was skipped as if it were absent")
		}
	})
}

func TestDeploymentHistoryBoundsSameVersionFailedAndUnverifiableEvidence(t *testing.T) {
	client, manager, command, wire, _, _ := activeIdentityClient(t)
	proof := persistActiveIdentityCommand(t, client, command, wire)
	completeAndAcknowledgeDeployment(t, client, manager, proof)

	for index := 0; index < client.config.MaxActiveDeployments+8; index++ {
		candidate := proto.Clone(command).(*agentv1.DeploymentCommand)
		candidate.DeploymentId = uuid.NewString()
		candidate.RolloutId = uuid.NewString()
		candidate.Event.EventId = uuid.NewString()
		candidate.Event.RequestId = uuid.NewString()
		candidate.Artifacts[0].ArtifactId = uuid.NewString()
		record := persistActiveIdentityCommand(t, client, candidate, wire)
		var final *agentv1.DeploymentStatus
		if index%2 == 0 {
			final = failedStatus(candidate, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "same-version failure", false)
		} else {
			final = statusFor(candidate, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, client.now(), false, "", "", 0)
		}
		if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{final}, true); err != nil {
			t.Fatal(err)
		}
		persisted, err := client.store.record(record.RecordKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted)); err != nil {
			t.Fatal(err)
		}
	}

	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, command.ConfigVersionId, command.Artifacts[0].Sha256)
	records, err := filepath.Glob(filepath.Join(client.store.directory, "*.json"))
	if err != nil || len(records) > 2 {
		t.Fatalf("same-version retained records = %d, err=%v", len(records), err)
	}
	artifacts, err := filepath.Glob(filepath.Join(client.store.artifacts, "*.part"))
	if err != nil || len(artifacts) > 2 {
		t.Fatalf("same-version retained artifacts = %d, err=%v", len(artifacts), err)
	}
}

func TestLegacyCompactionIntentRecoversCrashBetweenRecordAndMarkerDeletion(t *testing.T) {
	client, manager, first, firstWire, _, privateKey := activeIdentityClient(t)
	firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
	completeAndAcknowledgeDeployment(t, client, manager, firstRecord)

	second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
	secondBundle, err := decodeConfigurationBundle(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: secondBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(second) = (%+v, %v)", result, err)
	}
	secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
	completeAndAcknowledgeDeployment(t, client, manager, secondRecord)

	historical := proto.Clone(second).(*agentv1.DeploymentCommand)
	historical.Event.EventId = uuid.NewString()
	historical.Event.RequestId = uuid.NewString()
	historical.DeploymentId = uuid.NewString()
	historical.RolloutId = uuid.NewString()
	historical.ConfigVersionId = uuid.NewString()
	historical.Artifacts[0].ArtifactId = uuid.NewString()
	historicalRecord, _, err := client.store.putCommand(historical, deliveredStatus(historical))
	if err != nil {
		t.Fatal(err)
	}
	failed := failedStatus(historical, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", true)
	if err := client.store.appendStatuses(historicalRecord.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(historicalRecord.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.store.markLegacyDeploymentStatusSent(persisted, 7, 2); err != nil {
		t.Fatal(err)
	}
	ack := deploymentStatusAckForRecord(t, persisted)
	if err := client.store.acknowledgeDeploymentStatus(ack); err != nil {
		t.Fatal(err)
	}

	pending := proto.Clone(second).(*agentv1.DeploymentCommand)
	pending.Event.EventId = uuid.NewString()
	pending.Event.RequestId = uuid.NewString()
	pending.DeploymentId = uuid.NewString()
	pending.RolloutId = uuid.NewString()
	pending.ConfigVersionId = uuid.NewString()
	pending.Artifacts[0].ArtifactId = uuid.NewString()
	pendingRecord, _, err := client.store.putCommand(pending, deliveredStatus(pending))
	if err != nil {
		t.Fatal(err)
	}

	client.store.mu.Lock()
	durableAck, err := client.store.loadDeploymentStatusAckLocked(historicalRecord.RecordKey)
	if err == nil {
		err = client.store.saveDeploymentCompactionIntentLocked(deploymentCompactionIntentForAck(durableAck))
	}
	client.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(client.store.directory, historicalRecord.RecordKey+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(client.store.directory, historicalRecord.RecordKey+legacyDeploymentStatusSentSuffix)); err != nil {
		t.Fatalf("legacy marker did not survive injected crash: %v", err)
	}

	closeGatewayClientForRestart(t, client)
	restarted, err := New(client.config, &failingDialer{}, manager, client.trust)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := restarted.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
	assertActiveIdentity(t, hello.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
	if record, err := restarted.store.record(pendingRecord.RecordKey); err != nil || record == nil || record.ExecutionDone {
		t.Fatalf("pending proof after recovery = (%+v, %v)", record, err)
	}
	for _, suffix := range []string{
		legacyDeploymentStatusSentSuffix, deploymentStatusAckSuffix, deploymentCompactionIntentSuffix,
	} {
		if _, err := os.Stat(filepath.Join(restarted.store.directory, historicalRecord.RecordKey+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered compaction left %s: %v", suffix, err)
		}
	}
}

func TestDeploymentAckCleanupPreservesLiveCompactionIntent(t *testing.T) {
	client, manager, first, firstWire, _, privateKey := activeIdentityClient(t)
	firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
	completeAndAcknowledgeDeployment(t, client, manager, firstRecord)

	second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
	secondBundle, err := decodeConfigurationBundle(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: secondBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(second) = (%+v, %v)", result, err)
	}
	secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
	completeAndAcknowledgeDeployment(t, client, manager, secondRecord)

	historical := proto.Clone(second).(*agentv1.DeploymentCommand)
	historical.Event.EventId = uuid.NewString()
	historical.Event.RequestId = uuid.NewString()
	historical.DeploymentId = uuid.NewString()
	historical.RolloutId = uuid.NewString()
	historical.ConfigVersionId = uuid.NewString()
	historical.Artifacts[0].ArtifactId = uuid.NewString()
	historicalRecord, _, err := client.store.putCommand(historical, deliveredStatus(historical))
	if err != nil {
		t.Fatal(err)
	}
	failed := failedStatus(historical, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", true)
	if err := client.store.appendStatuses(historicalRecord.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(historicalRecord.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted)); err != nil {
		t.Fatal(err)
	}

	var intent *durableDeploymentCompactionIntent
	client.store.mu.Lock()
	ack, err := client.store.loadDeploymentStatusAckLocked(historicalRecord.RecordKey)
	if err == nil {
		intent = deploymentCompactionIntentForAck(ack)
		err = client.store.saveDeploymentCompactionIntentLocked(intent)
	}
	client.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(client.store.directory, historicalRecord.RecordKey+".json")); err != nil {
		t.Fatal(err)
	}
	mismatched := *intent
	mismatched.StatusEventID = uuid.NewString()
	encoded, err := json.Marshal(&mismatched)
	if err != nil {
		t.Fatal(err)
	}
	intentPath := filepath.Join(client.store.directory, historicalRecord.RecordKey+deploymentCompactionIntentSuffix)
	if err := os.WriteFile(intentPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	client.store.mu.Lock()
	err = client.store.cleanupDeploymentAckArtifactsLocked()
	client.store.mu.Unlock()
	if err == nil {
		t.Fatal("cleanup accepted a compaction intent that did not match its durable ACK")
	}
	if err := os.Remove(intentPath); err != nil {
		t.Fatal(err)
	}
	client.store.mu.Lock()
	err = client.store.saveDeploymentCompactionIntentLocked(intent)
	client.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	client.store.mu.Lock()
	err = client.store.cleanupDeploymentAckArtifactsLocked()
	client.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(client.store.directory, historicalRecord.RecordKey+deploymentStatusAckSuffix)); err != nil {
		t.Fatalf("cleanup removed the exact ACK required by a live compaction intent: %v", err)
	}

	closeGatewayClientForRestart(t, client)
	restarted, err := New(client.config, &failingDialer{}, manager, client.trust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.agentHello(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{deploymentStatusAckSuffix, deploymentCompactionIntentSuffix} {
		if _, err := os.Stat(filepath.Join(restarted.store.directory, historicalRecord.RecordKey+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered compaction left %s: %v", suffix, err)
		}
	}
}

func TestDeploymentCompactionRecoveryRequiresExactDurableAck(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, store *durableStore, ack *durableDeploymentStatusAck)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, store *durableStore, ack *durableDeploymentStatusAck) {
				t.Helper()
				if err := os.Remove(filepath.Join(store.directory, ack.RecordKey+deploymentStatusAckSuffix)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "corrupt",
			mutate: func(t *testing.T, store *durableStore, ack *durableDeploymentStatusAck) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(store.directory, ack.RecordKey+deploymentStatusAckSuffix), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "identityMismatch",
			mutate: func(t *testing.T, store *durableStore, ack *durableDeploymentStatusAck) {
				t.Helper()
				mismatched := *ack
				mismatched.StatusEventID = uuid.NewString()
				if err := store.saveDeploymentStatusAckLocked(&mismatched); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, manager, command, _, _, _ := activeIdentityClient(t)
			historical := proto.Clone(command).(*agentv1.DeploymentCommand)
			historical.Event.EventId = uuid.NewString()
			historical.Event.RequestId = uuid.NewString()
			historical.DeploymentId = uuid.NewString()
			historical.RolloutId = uuid.NewString()
			historical.ConfigVersionId = uuid.NewString()
			historical.Artifacts[0].ArtifactId = uuid.NewString()
			record, _, err := client.store.putCommand(historical, deliveredStatus(historical))
			if err != nil {
				t.Fatal(err)
			}
			failed := failedStatus(historical, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", true)
			if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
				t.Fatal(err)
			}
			persisted, err := client.store.record(record.RecordKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted)); err != nil {
				t.Fatal(err)
			}

			client.store.mu.Lock()
			exactAck, err := client.store.loadDeploymentStatusAckLocked(record.RecordKey)
			if err == nil {
				err = client.store.saveDeploymentCompactionIntentLocked(deploymentCompactionIntentForAck(exactAck))
			}
			client.store.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(client.store.directory, record.RecordKey+".json")); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, client.store, exactAck)

			client.store.mu.Lock()
			err = client.store.cleanupDeploymentAckArtifactsLocked()
			client.store.mu.Unlock()
			if err == nil {
				t.Fatalf("cleanup accepted a live compaction intent with %s ACK state", test.name)
			}
			intentPath := filepath.Join(client.store.directory, record.RecordKey+deploymentCompactionIntentSuffix)
			if _, err := os.Stat(intentPath); err != nil {
				t.Fatalf("fail-closed cleanup deleted the live compaction intent: %v", err)
			}

			closeGatewayClientForRestart(t, client)
			failedRestart, err := New(client.config, &failingDialer{}, manager, client.trust)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := failedRestart.agentHello(); err == nil {
				t.Fatalf("restart recovered a live compaction intent with %s ACK state", test.name)
			}
			if _, err := os.Stat(intentPath); err != nil {
				t.Fatalf("failed restart deleted the live compaction intent: %v", err)
			}

			failedRestart.store.mu.Lock()
			err = failedRestart.store.saveDeploymentStatusAckLocked(exactAck)
			failedRestart.store.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			closeGatewayClientForRestart(t, failedRestart)
			recovered, err := New(client.config, &failingDialer{}, manager, client.trust)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := recovered.agentHello(); err != nil {
				t.Fatalf("restart did not recover after restoring the exact ACK: %v", err)
			}
			for _, suffix := range []string{deploymentStatusAckSuffix, deploymentCompactionIntentSuffix} {
				if _, err := os.Stat(filepath.Join(recovered.store.directory, record.RecordKey+suffix)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("final recovery left %s: %v", suffix, err)
				}
			}
		})
	}
}

func TestDeploymentCompactionBatchValidationPrecedesMutation(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(*durableStore) error
	}{
		{
			name: "cleanup",
			run: func(store *durableStore) error {
				store.mu.Lock()
				defer store.mu.Unlock()
				return store.cleanupDeploymentAckArtifactsLocked()
			},
		},
		{
			name: "recovery",
			run: func(store *durableStore) error {
				store.mu.Lock()
				defer store.mu.Unlock()
				return store.recoverDeploymentCompactionsLocked()
			},
		},
	} {
		for _, ackState := range []string{"missing", "corrupt", "identityMismatch"} {
			t.Run(operation.name+"/"+ackState, func(t *testing.T) {
				client, manager, command, _, _, _ := activeIdentityClient(t)
				unrelated := proto.Clone(command).(*agentv1.DeploymentCommand)
				unrelated.Event.EventId = uuid.NewString()
				unrelated.Event.RequestId = uuid.NewString()
				unrelated.DeploymentId = uuid.NewString()
				unrelated.RolloutId = uuid.NewString()
				unrelated.ConfigVersionId = uuid.NewString()
				unrelated.Artifacts[0].ArtifactId = uuid.NewString()
				record, _, err := client.store.putCommand(unrelated, deliveredStatus(unrelated))
				if err != nil {
					t.Fatal(err)
				}
				failed := failedStatus(unrelated, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", true)
				if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
					t.Fatal(err)
				}
				persisted, err := client.store.record(record.RecordKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted)); err != nil {
					t.Fatal(err)
				}
				client.store.mu.Lock()
				unrelatedAck, err := client.store.loadDeploymentStatusAckLocked(record.RecordKey)
				if err == nil {
					err = client.store.saveDeploymentCompactionIntentLocked(deploymentCompactionIntentForAck(unrelatedAck))
				}
				if err == nil {
					err = client.store.saveLegacyDeploymentStatusSentLocked(&durableLegacyDeploymentStatusSent{
						Version: legacyDeploymentStatusSentVersion, RecordKey: unrelatedAck.RecordKey,
						SessionEpoch: 1, StreamSequence: 1, StatusEventID: unrelatedAck.StatusEventID,
						DeploymentID: unrelatedAck.DeploymentID, Attempt: unrelatedAck.Attempt,
						ConfigVersionID: unrelatedAck.ConfigVersionID, TransitionSequence: unrelatedAck.TransitionSequence,
					})
				}
				client.store.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(client.store.artifactPath(record.RecordKey), []byte("unrelated artifact proof"), 0o600); err != nil {
					t.Fatal(err)
				}

				exactAcks := map[string]*durableDeploymentStatusAck{unrelatedAck.RecordKey: unrelatedAck}
				selectable := make(map[string]struct{})
				mutableBeforeValidation := make(map[string]struct{})
				invalidKey := ""
				for round := 0; round < 8 && invalidKey == ""; round++ {
					for index := 0; index < 8; index++ {
						key := fmt.Sprintf("%032x%032x", round+1, index+1)
						ack := &durableDeploymentStatusAck{
							Version: deploymentStatusAckVersion, RecordKey: key,
							StatusEventID: uuid.NewString(), DeploymentID: uuid.NewString(), Attempt: 1,
							ConfigVersionID: uuid.NewString(), TransitionSequence: 1,
						}
						client.store.mu.Lock()
						err = client.store.saveDeploymentStatusAckLocked(ack)
						if err == nil {
							err = client.store.saveDeploymentCompactionIntentLocked(deploymentCompactionIntentForAck(ack))
						}
						client.store.mu.Unlock()
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(client.store.artifactPath(key), []byte("ordered artifact proof"), 0o600); err != nil {
							t.Fatal(err)
						}
						exactAcks[key] = ack
						selectable[key] = struct{}{}

						orphanKey := fmt.Sprintf("%032x%031xq", round+1, index+1)
						orphanName := orphanKey + deploymentStatusAckSuffix
						if err := os.WriteFile(filepath.Join(client.store.directory, orphanName), []byte("orphan acknowledgement"), 0o600); err != nil {
							t.Fatal(err)
						}
						mutableBeforeValidation[orphanName] = struct{}{}
						temporaryName := fmt.Sprintf(".deployment-ack-order-%02d-%02d", round, index)
						if err := os.WriteFile(filepath.Join(client.store.directory, temporaryName), []byte("temporary acknowledgement"), 0o600); err != nil {
							t.Fatal(err)
						}
						mutableBeforeValidation[temporaryName] = struct{}{}
					}
					invalidKey = deploymentCompactionKeyAfterEarlierEntry(
						t, client.store.directory, operation.name, selectable, mutableBeforeValidation,
					)
				}
				if invalidKey == "" {
					t.Fatal("could not construct deterministic directory order for the mutation-before-validation proof")
				}
				invalidAck := exactAcks[invalidKey]
				switch ackState {
				case "missing":
					if err := os.Remove(filepath.Join(client.store.directory, invalidAck.RecordKey+deploymentStatusAckSuffix)); err != nil {
						t.Fatal(err)
					}
				case "corrupt":
					if err := os.WriteFile(filepath.Join(client.store.directory, invalidAck.RecordKey+deploymentStatusAckSuffix), []byte("{"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "identityMismatch":
					mismatched := *invalidAck
					mismatched.StatusEventID = uuid.NewString()
					client.store.mu.Lock()
					err = client.store.saveDeploymentStatusAckLocked(&mismatched)
					client.store.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}

				before := deploymentCompactionProofSnapshot(t, client.store)
				if err := operation.run(client.store); err == nil {
					t.Fatalf("%s accepted %s exact ACK state", operation.name, ackState)
				}
				after := deploymentCompactionProofSnapshot(t, client.store)
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("%s mutated durable proof before validating every intent\nbefore: %#v\nafter:  %#v", operation.name, before, after)
				}

				client.store.mu.Lock()
				err = client.store.saveDeploymentStatusAckLocked(invalidAck)
				client.store.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				closeGatewayClientForRestart(t, client)
				restarted, err := New(client.config, &failingDialer{}, manager, client.trust)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := restarted.agentHello(); err != nil {
					t.Fatalf("restart did not recover after restoring exact ACK: %v", err)
				}
				paths := make([]string, 0, 3*len(exactAcks)+len(mutableBeforeValidation)+1)
				for key := range exactAcks {
					paths = append(paths,
						filepath.Join(restarted.store.directory, key+deploymentStatusAckSuffix),
						filepath.Join(restarted.store.directory, key+deploymentCompactionIntentSuffix),
						restarted.store.artifactPath(key),
					)
				}
				for name := range mutableBeforeValidation {
					paths = append(paths, filepath.Join(restarted.store.directory, name))
				}
				paths = append(paths, filepath.Join(restarted.store.directory, unrelatedAck.RecordKey+".json"))
				for _, path := range paths {
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("final cleanup left %s: %v", path, err)
					}
				}
			})
		}
	}
}

func TestClientJournalLeaseSerializesCompactionMutation(t *testing.T) {
	client, manager, _, _, _, _ := activeIdentityClient(t)
	orphanPath := filepath.Join(client.store.directory, strings.Repeat("a", sha256.Size*2)+deploymentStatusAckSuffix)
	if err := os.WriteFile(orphanPath, []byte("orphan acknowledgement"), 0o600); err != nil {
		t.Fatal(err)
	}
	client.store.mu.Lock()
	validated, err := client.store.snapshotDeploymentCompactionsLocked()
	client.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	foundOrphan := false
	for _, cleanup := range validated.cleanup {
		foundOrphan = foundOrphan || cleanup.path.name == filepath.Base(orphanPath)
	}
	validated.close()
	if !foundOrphan {
		t.Fatal("orphan acknowledgement was not selected for cleanup")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		client.store.mu.Lock()
		defer client.store.mu.Unlock()
		done <- client.store.cleanupDeploymentAckArtifactsWithHookLocked(func() {
			close(entered)
			<-release
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not reach its descriptor-anchored mutation boundary")
	}
	before := deploymentCompactionProofSnapshot(t, client.store)
	second, err := New(client.config, &failingDialer{}, manager, client.trust)
	if err == nil {
		_ = second.Close()
		t.Fatal("second client acquired an already-owned journal")
	}
	after := deploymentCompactionProofSnapshot(t, client.store)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("failed journal opener mutated durable state\nbefore: %#v\nafter:  %#v", before, after)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned cleanup did not remove its validated orphan: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(client.config, &failingDialer{}, manager, client.trust)
	if err != nil {
		t.Fatalf("journal lease was not released by Close: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentCompactionReceiptInventoryIsBoundToCleanup(t *testing.T) {
	for _, mutation := range []string{"add receipt", "add temporary proof", "delete receipt", "replace receipt", "delete cleanup target", "replace cleanup target"} {
		t.Run(mutation, func(t *testing.T) {
			client, _, _, _, _, _ := activeIdentityClient(t)
			orphanPaths := []string{
				filepath.Join(client.store.directory, strings.Repeat("a", sha256.Size*2)+deploymentStatusAckSuffix),
				filepath.Join(client.store.directory, strings.Repeat("c", sha256.Size*2)+deploymentStatusAckSuffix),
			}
			for _, path := range orphanPaths {
				if err := os.WriteFile(path, []byte("orphan acknowledgement"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			receiptPath := filepath.Join(client.store.directory, strings.Repeat("b", sha256.Size*2)+deploymentStatusAckReceiptSuffix)
			if mutation != "add receipt" {
				if err := os.WriteFile(receiptPath, []byte("receipt proof"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var afterInterleaving map[string]journalTreeEntry
			client.store.mu.Lock()
			err := client.store.cleanupDeploymentAckArtifactsWithHookLocked(func() {
				switch mutation {
				case "add receipt":
					if err := os.WriteFile(receiptPath, []byte("receipt proof"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "add temporary proof":
					if err := os.WriteFile(filepath.Join(client.store.directory, ".deployment-ack-post-validation"), []byte("temporary proof"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "delete receipt":
					if err := os.Remove(receiptPath); err != nil {
						t.Fatal(err)
					}
				case "replace receipt":
					content, err := os.ReadFile(receiptPath)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(receiptPath); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(receiptPath, content, 0o600); err != nil {
						t.Fatal(err)
					}
				case "delete cleanup target":
					if err := os.Remove(orphanPaths[1]); err != nil {
						t.Fatal(err)
					}
				case "replace cleanup target":
					content, err := os.ReadFile(orphanPaths[1])
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(orphanPaths[1]); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(orphanPaths[1], content, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				afterInterleaving = journalTreeSnapshot(t, client.store.directory)
			})
			client.store.mu.Unlock()
			if err == nil {
				t.Fatal("compaction cleanup accepted post-validation receipt inventory drift")
			}
			if after := journalTreeSnapshot(t, client.store.directory); !reflect.DeepEqual(after, afterInterleaving) {
				t.Fatalf("failed compaction cleanup mutated journal after receipt drift\ninterleaved: %#v\nafter: %#v", afterInterleaving, after)
			}
		})
	}
}

func TestClientCloseWaitsForActiveRunBeforeReleasingJournalLease(t *testing.T) {
	client, manager, _, _, _, _ := activeIdentityClient(t)
	dialer := &lifecycleBlockingDialer{
		entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}),
	}
	client.dialer = dialer
	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(context.Background()) }()
	select {
	case <-dialer.entered:
	case <-time.After(time.Second):
		t.Fatal("Run did not enter the blocking dialer")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case <-dialer.canceled:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the active Run")
	}
	if second, err := New(client.config, &failingDialer{}, manager, client.trust); err == nil {
		_ = second.Close()
		t.Fatal("Close released the journal lease before the active Run stopped")
	}
	close(dialer.release)
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := client.Run(context.Background()); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("post-Close Run() error = %v, want invalid configuration", err)
	}
	reopened, err := New(client.config, &failingDialer{}, manager, client.trust)
	if err != nil {
		t.Fatalf("journal lease was not released after Run stopped: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientJournalLeaseRejectsNamespaceReplacement(t *testing.T) {
	t.Run("hardlinked lock", func(t *testing.T) {
		client, manager, _, _, _, _ := activeIdentityClient(t)
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(client.config.JournalDir, gatewayJournalLockName)
		if err := os.Link(lockPath, lockPath+".hardlink"); err != nil {
			t.Fatal(err)
		}
		before := journalTreeSnapshot(t, client.config.JournalDir)
		candidate, err := New(client.config, &failingDialer{}, manager, client.trust)
		if err == nil {
			_ = candidate.Close()
			t.Fatal("journal lease accepted a hardlinked lock inode")
		}
		if after := journalTreeSnapshot(t, client.config.JournalDir); !reflect.DeepEqual(after, before) {
			t.Fatalf("failed hardlink lease acquisition mutated journal\nbefore: %#v\nafter: %#v", before, after)
		}
	})

	t.Run("unlinked and replaced lock", func(t *testing.T) {
		client, manager, _, _, _, _ := activeIdentityClient(t)
		lockPath := filepath.Join(client.config.JournalDir, gatewayJournalLockName)
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(lockPath, []byte("same-owner replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := journalTreeSnapshot(t, client.config.JournalDir)
		candidate, err := New(client.config, &failingDialer{}, manager, client.trust)
		if err == nil {
			_ = candidate.Close()
			t.Fatal("second client acquired a replacement lock inode")
		}
		if after := journalTreeSnapshot(t, client.config.JournalDir); !reflect.DeepEqual(after, before) {
			t.Fatalf("replacement lock acquisition mutated journal\nbefore: %#v\nafter: %#v", before, after)
		}
	})

	t.Run("renamed and replaced journal", func(t *testing.T) {
		client, manager, _, _, _, _ := activeIdentityClient(t)
		original := client.config.JournalDir
		moved := original + ".moved"
		if err := os.Rename(original, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(original, 0o700); err != nil {
			t.Fatal(err)
		}
		before := journalTreeSnapshot(t, original)
		candidate, err := New(client.config, &failingDialer{}, manager, client.trust)
		if err == nil {
			_ = candidate.Close()
			t.Fatal("second client acquired a same-owner replacement journal")
		}
		if after := journalTreeSnapshot(t, original); !reflect.DeepEqual(after, before) {
			t.Fatalf("replacement journal acquisition mutated replacement path\nbefore: %#v\nafter: %#v", before, after)
		}
	})

	t.Run("renamed and replaced parent", func(t *testing.T) {
		baseClient, manager, _, _, _, _ := activeIdentityClient(t)
		root := secureTempDir(t)
		parent := filepath.Join(root, "parent")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		config := testClientConfig(filepath.Join(parent, "journal"))
		client, err := New(config, &failingDialer{}, manager, baseClient.trust)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })

		moved := filepath.Join(root, "moved-parent")
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		replacementBefore := journalTreeSnapshot(t, parent)
		movedBefore := journalTreeSnapshot(t, moved)
		beforeFDs := testOpenFileDescriptorCount(t)

		candidate, err := New(config, &failingDialer{}, manager, client.trust)
		if err == nil {
			_ = candidate.Close()
			t.Fatal("second client acquired a lease through a replacement parent")
		}
		if afterFDs := testOpenFileDescriptorCount(t); afterFDs != beforeFDs {
			t.Fatalf("failed parent replacement acquisition leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		if err := client.Run(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatalf("Run after parent replacement = %v, want journal parent identity failure", err)
		}
		if afterFDs := testOpenFileDescriptorCount(t); afterFDs > beforeFDs {
			t.Fatalf("parent replacement failure leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
		}
		if after := journalTreeSnapshot(t, parent); !reflect.DeepEqual(after, replacementBefore) {
			t.Fatalf("replacement parent changed\nbefore: %#v\nafter: %#v", replacementBefore, after)
		}
		if after := journalTreeSnapshot(t, moved); !reflect.DeepEqual(after, movedBefore) {
			t.Fatalf("anchored journal changed after namespace replacement\nbefore: %#v\nafter: %#v", movedBefore, after)
		}

		siblingConfig := testClientConfig(filepath.Join(moved, "sibling-journal"))
		sibling, err := New(siblingConfig, &failingDialer{}, manager, client.trust)
		if err != nil {
			t.Fatalf("independent sibling journal lease failed: %v", err)
		}
		if err := sibling.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("renamed and replaced grandparent", func(t *testing.T) {
		baseClient, manager, _, _, _, _ := activeIdentityClient(t)
		root := secureTempDir(t)
		grandparent := filepath.Join(root, "grandparent")
		parent := filepath.Join(grandparent, "parent")
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		config := testClientConfig(filepath.Join(parent, "journal"))
		client, err := New(config, &failingDialer{}, manager, baseClient.trust)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })

		moved := filepath.Join(root, "moved-grandparent")
		if err := os.Rename(grandparent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		replacementBefore := journalTreeSnapshot(t, grandparent)
		movedBefore := journalTreeSnapshot(t, moved)
		beforeFDs := testOpenFileDescriptorCount(t)

		candidate, err := New(config, &failingDialer{}, manager, client.trust)
		if err == nil {
			_ = candidate.Close()
			t.Fatal("second client acquired a split lease through a replacement grandparent")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		if err := client.Run(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatalf("Run after grandparent replacement = %v, want namespace identity failure", err)
		}
		if afterFDs := testOpenFileDescriptorCount(t); afterFDs > beforeFDs {
			t.Fatalf("grandparent replacement failure leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
		}
		if after := journalTreeSnapshot(t, grandparent); !reflect.DeepEqual(after, replacementBefore) {
			t.Fatalf("replacement grandparent changed\nbefore: %#v\nafter: %#v", replacementBefore, after)
		}
		if after := journalTreeSnapshot(t, moved); !reflect.DeepEqual(after, movedBefore) {
			t.Fatalf("anchored journal changed after grandparent replacement\nbefore: %#v\nafter: %#v", movedBefore, after)
		}
	})
}

func TestDisableDeploymentStatusAckReceiptsValidatesWholeBoundedSet(t *testing.T) {
	t.Run("later corrupt receipt cannot partially downgrade", func(t *testing.T) {
		client, _, command, _, _, _ := activeIdentityClient(t)
		commands := []*agentv1.DeploymentCommand{proto.Clone(command).(*agentv1.DeploymentCommand), proto.Clone(command).(*agentv1.DeploymentCommand)}
		commands[1].Event.EventId = uuid.NewString()
		commands[1].Event.RequestId = uuid.NewString()
		commands[1].DeploymentId = uuid.NewString()
		commands[1].ConfigVersionId = uuid.NewString()
		keys := make([]string, 0, len(commands))
		for _, candidate := range commands {
			record, _, err := client.store.putCommand(candidate, deliveredStatus(candidate))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{
				failedStatus(candidate, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "test failure", false),
			}, true); err != nil {
				t.Fatal(err)
			}
			persisted, err := client.store.record(record.RecordKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted), true); err != nil {
				t.Fatal(err)
			}
			client.store.mu.Lock()
			ack, err := client.store.loadDeploymentStatusAckLocked(record.RecordKey)
			if err == nil {
				err = client.store.saveDeploymentStatusAckReceiptLocked(deploymentStatusAckReceiptForAck(ack))
			}
			client.store.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, record.RecordKey)
		}
		directory, err := os.Open(client.store.directory)
		if err != nil {
			t.Fatal(err)
		}
		entries, readErr := directory.Readdir(-1)
		closeErr := directory.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		keys = keys[:0]
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				keys = append(keys, strings.TrimSuffix(entry.Name(), ".json"))
			}
		}
		if len(keys) != 2 {
			t.Fatalf("deployment record scan fixture has %d records, want 2", len(keys))
		}
		firstAckPath := filepath.Join(client.store.directory, keys[0]+deploymentStatusAckSuffix)
		firstReceiptPath := filepath.Join(client.store.directory, keys[0]+deploymentStatusAckReceiptSuffix)
		firstAckBefore, err := os.ReadFile(firstAckPath)
		if err != nil {
			t.Fatal(err)
		}
		firstReceiptBefore, err := os.ReadFile(firstReceiptPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(client.store.directory, keys[1]+deploymentStatusAckReceiptSuffix), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := client.store.disableDeploymentStatusAckReceipts(); err == nil {
			t.Fatal("downgrade accepted a later corrupt durable receipt")
		}
		firstAckAfter, ackErr := os.ReadFile(firstAckPath)
		firstReceiptAfter, receiptErr := os.ReadFile(firstReceiptPath)
		if ackErr != nil || receiptErr != nil || !bytes.Equal(firstAckAfter, firstAckBefore) || !bytes.Equal(firstReceiptAfter, firstReceiptBefore) {
			t.Fatalf("downgrade mutated an earlier valid receipt before validating the full set: ack_err=%v receipt_err=%v", ackErr, receiptErr)
		}
	})

	t.Run("entry budget", func(t *testing.T) {
		client, _, _, _, _, _ := activeIdentityClient(t)
		entries, err := os.ReadDir(client.store.directory)
		if err != nil {
			t.Fatal(err)
		}
		for index := len(entries); index < deploymentJournalEntryLimit; index++ {
			if err := os.WriteFile(filepath.Join(client.store.directory, fmt.Sprintf("downgrade-budget-%04d", index)), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := client.store.disableDeploymentStatusAckReceipts(); err != nil {
			t.Fatalf("exact downgrade entry budget failed: %v", err)
		}
		overflow := filepath.Join(client.store.directory, "downgrade-budget-overflow")
		if err := os.WriteFile(overflow, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := journalTreeSnapshot(t, client.store.directory)
		beforeFDs := testOpenFileDescriptorCount(t)
		if err := client.store.disableDeploymentStatusAckReceipts(); err == nil {
			t.Fatal("downgrade entry budget+1 was accepted")
		}
		if afterFDs := testOpenFileDescriptorCount(t); afterFDs != beforeFDs {
			t.Fatalf("downgrade entry budget failure leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
		}
		if after := journalTreeSnapshot(t, client.store.directory); !reflect.DeepEqual(after, before) {
			t.Fatal("downgrade entry budget failure mutated journal")
		}
	})

	for _, test := range []struct {
		name  string
		setup func(*testing.T, *Client, *agentv1.DeploymentCommand, *durableDeploymentStatusAckReceipt)
	}{
		{
			name: "orphan receipt",
			setup: func(t *testing.T, client *Client, _ *agentv1.DeploymentCommand, receipt *durableDeploymentStatusAckReceipt) {
				orphan := *receipt
				orphan.RecordKey = strings.Repeat("f", sha256.Size*2)
				client.store.mu.Lock()
				err := client.store.saveDeploymentStatusAckReceiptLocked(&orphan)
				client.store.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "receipt without acknowledgement",
			setup: func(t *testing.T, client *Client, command *agentv1.DeploymentCommand, _ *durableDeploymentStatusAckReceipt) {
				_, ack, receipt := persistTerminalAckReceipt(t, client, command, true)
				if err := os.Remove(filepath.Join(client.store.directory, ack.RecordKey+deploymentStatusAckSuffix)); err != nil {
					t.Fatal(err)
				}
				if receipt == nil {
					t.Fatal("receipt fixture is missing")
				}
			},
		},
		{
			name: "non-required corrupt receipt",
			setup: func(t *testing.T, client *Client, command *agentv1.DeploymentCommand, _ *durableDeploymentStatusAckReceipt) {
				_, ack, _ := persistTerminalAckReceipt(t, client, command, false)
				if err := os.WriteFile(filepath.Join(client.store.directory, ack.RecordKey+deploymentStatusAckReceiptSuffix), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized receipt",
			setup: func(t *testing.T, client *Client, _ *agentv1.DeploymentCommand, _ *durableDeploymentStatusAckReceipt) {
				path := filepath.Join(client.store.directory, strings.Repeat("e", sha256.Size*2)+deploymentStatusAckReceiptSuffix)
				if err := os.WriteFile(path, make([]byte, 4097), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _, command, _, _, _ := activeIdentityClient(t)
			_, _, validReceipt := persistTerminalAckReceipt(t, client, command, true)
			test.setup(t, client, command, validReceipt)
			before := journalTreeSnapshot(t, client.store.directory)
			beforeFDs := testOpenFileDescriptorCount(t)
			if err := client.store.disableDeploymentStatusAckReceipts(); err == nil {
				t.Fatal("downgrade accepted an invalid unreferenced receipt")
			}
			if afterFDs := testOpenFileDescriptorCount(t); afterFDs != beforeFDs {
				t.Fatalf("receipt preflight leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
			}
			if after := journalTreeSnapshot(t, client.store.directory); !reflect.DeepEqual(after, before) {
				t.Fatalf("receipt preflight failure mutated journal\nbefore: %#v\nafter: %#v", before, after)
			}
		})
	}
}

func TestDisableDeploymentStatusAckReceiptsBindsValidatedInventoryToMutation(t *testing.T) {
	for _, kind := range []string{"receipt", "acknowledgement", "record"} {
		for _, mutation := range []string{"add", "delete", "replace"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				client, _, command, _, _, _ := activeIdentityClient(t)
				_, ack, _ := persistTerminalAckReceipt(t, client, command, true)
				targetPath := filepath.Join(client.store.directory, ack.RecordKey+deploymentStatusAckReceiptSuffix)
				addedPath := filepath.Join(client.store.directory, strings.Repeat("f", sha256.Size*2)+deploymentStatusAckReceiptSuffix)
				switch kind {
				case "acknowledgement":
					targetPath = filepath.Join(client.store.directory, ack.RecordKey+deploymentStatusAckSuffix)
					addedPath = filepath.Join(client.store.directory, strings.Repeat("e", sha256.Size*2)+deploymentStatusAckSuffix)
				case "record":
					targetPath = filepath.Join(client.store.directory, ack.RecordKey+".json")
					addedPath = filepath.Join(client.store.directory, strings.Repeat("d", sha256.Size*2)+".json")
				}
				var afterInterleaving map[string]journalTreeEntry
				err := client.store.disableDeploymentStatusAckReceiptsWithHook(func() {
					switch mutation {
					case "add":
						if err := os.WriteFile(addedPath, []byte("post-validation proof"), 0o600); err != nil {
							t.Fatal(err)
						}
					case "delete":
						if err := os.Remove(targetPath); err != nil {
							t.Fatal(err)
						}
					case "replace":
						content, err := os.ReadFile(targetPath)
						if err != nil {
							t.Fatal(err)
						}
						before, err := os.Stat(targetPath)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(targetPath); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(targetPath, content, 0o600); err != nil {
							t.Fatal(err)
						}
						after, err := os.Stat(targetPath)
						if err != nil || os.SameFile(before, after) {
							t.Fatalf("replacement did not change inode: before=%+v after=%+v err=%v", before, after, err)
						}
					}
					afterInterleaving = journalTreeSnapshot(t, client.store.directory)
				})
				if err == nil {
					t.Fatal("capability-18 downgrade accepted post-validation inventory drift")
				}
				if after := journalTreeSnapshot(t, client.store.directory); !reflect.DeepEqual(after, afterInterleaving) {
					t.Fatalf("failed downgrade mutated journal after detecting inventory drift\ninterleaved: %#v\nafter: %#v", afterInterleaving, after)
				}
			})
		}
	}
}

func TestDeploymentAckBatchesValidateAllItemsBeforeMutation(t *testing.T) {
	t.Run("receipt confirmation", func(t *testing.T) {
		client, _, command, _, _, _ := activeIdentityClient(t)
		candidates := make(map[string]struct{}, 2)
		for range 2 {
			record := persistFailedTerminalRecord(t, client, command)
			ack := deploymentStatusAckForRecord(t, record)
			if err := client.store.acknowledgeDeploymentStatus(ack, true); err != nil {
				t.Fatal(err)
			}
			client.store.mu.Lock()
			persisted, err := client.store.loadDeploymentStatusAckLocked(record.RecordKey)
			receipt := deploymentStatusAckReceiptForAck(persisted)
			receipt.SessionEpoch = 7
			receipt.StreamSequence = 1
			if err == nil {
				err = client.store.saveDeploymentStatusAckReceiptLocked(receipt)
			}
			client.store.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			candidates[record.RecordKey] = struct{}{}
		}
		ordered := journalKeysInReadOrder(t, client.store.directory, deploymentStatusAckReceiptSuffix, candidates)
		if err := os.WriteFile(filepath.Join(client.store.directory, ordered[1]+".json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := journalTreeSnapshot(t, client.store.directory)
		if err := client.confirmDeploymentStatusAckReceipts(7, 2); err == nil {
			t.Fatal("receipt confirmation accepted a corrupt later record")
		}
		if after := journalTreeSnapshot(t, client.store.directory); !reflect.DeepEqual(after, before) {
			t.Fatalf("receipt confirmation mutated an earlier item before full validation\nbefore: %#v\nafter: %#v", before, after)
		}
	})

	t.Run("legacy promotion", func(t *testing.T) {
		client, _, command, _, _, _ := activeIdentityClient(t)
		candidates := make(map[string]struct{}, 2)
		for range 2 {
			record := persistFailedTerminalRecord(t, client, command)
			if err := client.store.markLegacyDeploymentStatusSent(record, 7, 1); err != nil {
				t.Fatal(err)
			}
			candidates[record.RecordKey] = struct{}{}
		}
		ordered := journalKeysInReadOrder(t, client.store.directory, legacyDeploymentStatusSentSuffix, candidates)
		if err := os.WriteFile(filepath.Join(client.store.directory, ordered[1]+".json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := journalTreeSnapshot(t, client.store.directory)
		if err := client.store.promoteLegacyDeploymentStatuses(7, 2); err == nil {
			t.Fatal("legacy promotion accepted a corrupt later record")
		}
		if after := journalTreeSnapshot(t, client.store.directory); !reflect.DeepEqual(after, before) {
			t.Fatalf("legacy promotion mutated an earlier item before full validation\nbefore: %#v\nafter: %#v", before, after)
		}
	})

	t.Run("deployment history", func(t *testing.T) {
		client, _, command, _, _, _ := activeIdentityClient(t)
		candidates := make(map[string]struct{}, 2)
		for range 2 {
			record := persistFailedTerminalRecord(t, client, command)
			if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, record), true); err != nil {
				t.Fatal(err)
			}
			candidates[record.RecordKey] = struct{}{}
		}
		ordered := journalKeysInReadOrder(t, client.store.directory, ".json", candidates)
		if err := os.WriteFile(filepath.Join(client.store.directory, ordered[1]+".json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := journalTreeSnapshot(t, client.store.directory)
		if _, err := client.deploymentHistory(deployment.Pointers{}); err == nil {
			t.Fatal("deployment history accepted a corrupt later record")
		}
		if after := journalTreeSnapshot(t, client.store.directory); !reflect.DeepEqual(after, before) {
			t.Fatalf("deployment history mutated an earlier item before full validation\nbefore: %#v\nafter: %#v", before, after)
		}
	})
}

func persistFailedTerminalRecord(t *testing.T, client *Client, template *agentv1.DeploymentCommand) *durableRecord {
	t.Helper()
	command := proto.Clone(template).(*agentv1.DeploymentCommand)
	command.Event.EventId = uuid.NewString()
	command.Event.RequestId = uuid.NewString()
	command.DeploymentId = uuid.NewString()
	command.RolloutId = uuid.NewString()
	command.ConfigVersionId = uuid.NewString()
	command.Artifacts[0].ArtifactId = uuid.NewString()
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{
		failedStatus(command, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "test failure", false),
	}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	return persisted
}

func journalKeysInReadOrder(t *testing.T, directory, suffix string, candidates map[string]struct{}) []string {
	t.Helper()
	opened, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	names, err := opened.Readdirnames(-1)
	if closeErr := opened.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	ordered := make([]string, 0, len(candidates))
	for _, name := range names {
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		key := strings.TrimSuffix(name, suffix)
		if _, ok := candidates[key]; ok {
			ordered = append(ordered, key)
		}
	}
	if len(ordered) != len(candidates) {
		t.Fatalf("journal scan found %d candidate %s files, want %d", len(ordered), suffix, len(candidates))
	}
	return ordered
}

func persistTerminalAckReceipt(t *testing.T, client *Client, template *agentv1.DeploymentCommand, receiptRequired bool) (*durableRecord, *durableDeploymentStatusAck, *durableDeploymentStatusAckReceipt) {
	t.Helper()
	command := proto.Clone(template).(*agentv1.DeploymentCommand)
	command.Event.EventId = uuid.NewString()
	command.Event.RequestId = uuid.NewString()
	command.DeploymentId = uuid.NewString()
	command.RolloutId = uuid.NewString()
	command.ConfigVersionId = uuid.NewString()
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{
		failedStatus(command, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "test failure", false),
	}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.store.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted), receiptRequired); err != nil {
		t.Fatal(err)
	}
	client.store.mu.Lock()
	ack, err := client.store.loadDeploymentStatusAckLocked(record.RecordKey)
	receipt := deploymentStatusAckReceiptForAck(ack)
	if err == nil {
		err = client.store.saveDeploymentStatusAckReceiptLocked(receipt)
	}
	client.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return persisted, ack, receipt
}

func TestDeploymentJournalAggregateExactBoundary(t *testing.T) {
	client, _, _, _, _, _ := activeIdentityClient(t)
	entries, err := os.ReadDir(client.store.directory)
	if err != nil {
		t.Fatal(err)
	}
	var aggregate int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			aggregate += info.Size()
		}
	}
	remaining := deploymentJournalAggregateByteLimit - aggregate
	if remaining <= 0 {
		t.Fatalf("journal fixture already exceeds aggregate boundary: %d", aggregate)
	}
	boundaryPath := filepath.Join(client.store.directory, "aggregate-exact-boundary")
	file, err := os.OpenFile(boundaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(remaining); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.store.snapshotDeploymentCompactionsLocked()
	if err != nil {
		t.Fatalf("exact 256 MiB aggregate boundary failed: %v", err)
	}
	snapshot.close()
	if err := client.store.disableDeploymentStatusAckReceipts(); err != nil {
		t.Fatalf("exact 256 MiB downgrade boundary failed: %v", err)
	}
	if err := os.Truncate(boundaryPath, remaining+1); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(boundaryPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeFDs := testOpenFileDescriptorCount(t)
	if err := client.store.disableDeploymentStatusAckReceipts(); err == nil {
		t.Fatal("downgrade accepted aggregate boundary+1")
	}
	if afterFDs := testOpenFileDescriptorCount(t); afterFDs != beforeFDs {
		t.Fatalf("aggregate boundary failure leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
	}
	after, err := os.Stat(boundaryPath)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("aggregate boundary failure mutated sparse fixture: before=%+v after=%+v err=%v", before, after, err)
	}
}

type journalTreeEntry struct {
	Mode   os.FileMode
	Size   int64
	Inode  uint64
	Digest [sha256.Size]byte
}

func journalTreeSnapshot(t *testing.T, root string) map[string]journalTreeEntry {
	t.Helper()
	snapshot := make(map[string]journalTreeEntry)
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := journalTreeEntry{Mode: info.Mode(), Size: info.Size()}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			entry.Inode = stat.Ino
		}
		if info.Mode().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry.Digest = sha256.Sum256(content)
		}
		snapshot[relative] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestClientJournalLeaseFailureIsMutationAndFDNeutral(t *testing.T) {
	client, manager, _, _, _, _ := activeIdentityClient(t)
	invalidPath := filepath.Join(client.store.directory, strings.Repeat("f", sha256.Size*2)+deploymentCompactionIntentSuffix)
	if err := os.WriteFile(invalidPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := deploymentCompactionProofSnapshot(t, client.store)
	beforeFDs := testOpenFileDescriptorCount(t)
	for range 32 {
		candidate, err := New(client.config, &failingDialer{}, manager, client.trust)
		if err == nil {
			_ = candidate.Close()
			t.Fatal("concurrent journal owner was accepted")
		}
	}
	afterFDs := testOpenFileDescriptorCount(t)
	after := deploymentCompactionProofSnapshot(t, client.store)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("failed pre-lease validation mutated journal\nbefore: %#v\nafter:  %#v", before, after)
	}
	if afterFDs != beforeFDs {
		t.Fatalf("failed journal opens leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
	}
}

func TestDeploymentCompactionSnapshotBudgets(t *testing.T) {
	client, _, _, _, _, _ := activeIdentityClient(t)
	entries, err := os.ReadDir(client.store.directory)
	if err != nil {
		t.Fatal(err)
	}
	for index := len(entries); index < deploymentJournalEntryLimit; index++ {
		path := filepath.Join(client.store.directory, fmt.Sprintf("budget-%04d", index))
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := client.store.snapshotDeploymentCompactionsLocked()
	if err != nil {
		t.Fatalf("exact journal entry budget failed: %v", err)
	}
	snapshot.close()
	overflowPath := filepath.Join(client.store.directory, "budget-overflow")
	if err := os.WriteFile(overflowPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(client.store.directory); err != nil || len(entries) != deploymentJournalEntryLimit+1 {
		t.Fatalf("journal boundary fixture has %d entries, want %d: %v", len(entries), deploymentJournalEntryLimit+1, err)
	}
	before := deploymentCompactionProofSnapshot(t, client.store)
	beforeFDs := testOpenFileDescriptorCount(t)
	for range 16 {
		if snapshot, err := client.store.snapshotDeploymentCompactionsLocked(); err == nil {
			snapshot.close()
			t.Fatal("journal entry budget+1 was accepted")
		}
	}
	if afterFDs := testOpenFileDescriptorCount(t); afterFDs != beforeFDs {
		t.Fatalf("entry budget failures leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
	}
	after := deploymentCompactionProofSnapshot(t, client.store)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("entry budget failure mutated journal")
	}
	for index := len(entries); index < deploymentJournalEntryLimit; index++ {
		if err := os.Remove(filepath.Join(client.store.directory, fmt.Sprintf("budget-%04d", index))); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(overflowPath); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(client.store.directory, "aggregate-overflow")
	file, err := os.OpenFile(oversizedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(deploymentJournalAggregateByteLimit + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Stat(oversizedPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeFDs = testOpenFileDescriptorCount(t)
	for range 16 {
		if snapshot, err := client.store.snapshotDeploymentCompactionsLocked(); err == nil {
			snapshot.close()
			t.Fatal("journal aggregate byte budget+1 was accepted")
		}
	}
	if afterFDs := testOpenFileDescriptorCount(t); afterFDs != beforeFDs {
		t.Fatalf("aggregate budget failures leaked file descriptors: before=%d after=%d", beforeFDs, afterFDs)
	}
	infoAfter, err := os.Stat(oversizedPath)
	if err != nil || !os.SameFile(infoBefore, infoAfter) || infoBefore.Size() != infoAfter.Size() || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatalf("aggregate budget failure changed oversized proof: before=%+v after=%+v err=%v", infoBefore, infoAfter, err)
	}
}

func testOpenFileDescriptorCount(t *testing.T) int {
	t.Helper()
	directory, err := os.Open("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	entries, readErr := directory.Readdirnames(-1)
	if closeErr := directory.Close(); readErr == nil {
		readErr = closeErr
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return len(entries)
}

func deploymentCompactionKeyAfterEarlierEntry(
	t *testing.T,
	directory string,
	operation string,
	selectable map[string]struct{},
	mutable map[string]struct{},
) string {
	t.Helper()
	opened, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	names, err := opened.Readdirnames(-1)
	if closeErr := opened.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	seenIntent := false
	seenMutable := false
	for _, name := range names {
		if _, exists := mutable[name]; exists {
			seenMutable = true
		}
		if !strings.HasSuffix(name, deploymentCompactionIntentSuffix) {
			continue
		}
		key := strings.TrimSuffix(name, deploymentCompactionIntentSuffix)
		if _, exists := selectable[key]; !exists {
			continue
		}
		if operation == "cleanup" && seenMutable || operation == "recovery" && seenIntent {
			return key
		}
		seenIntent = true
	}
	return ""
}

func deploymentCompactionProofSnapshot(t *testing.T, store *durableStore) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	for label, directory := range map[string]string{"store": store.directory, "artifacts": store.artifacts} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			snapshot[label+"/"+entry.Name()] = fmt.Sprintf("%#o:%x", info.Mode(), content)
		}
	}
	return snapshot
}

func TestDeploymentStatusAckReceiptIsDurableUntilCausalHeartbeat(t *testing.T) {
	client, _, command, _, _, _ := activeIdentityClient(t)
	historical := proto.Clone(command).(*agentv1.DeploymentCommand)
	historical.Event.EventId = uuid.NewString()
	historical.Event.RequestId = uuid.NewString()
	historical.DeploymentId = uuid.NewString()
	historical.RolloutId = uuid.NewString()
	historical.ConfigVersionId = uuid.NewString()
	historical.Artifacts[0].ArtifactId = uuid.NewString()
	record, _, err := client.store.putCommand(historical, deliveredStatus(historical))
	if err != nil {
		t.Fatal(err)
	}
	failed := failedStatus(historical, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", true)
	if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.persistDeploymentStatusAckReceipt(deploymentStatusAckForRecord(t, persisted))
	if err != nil {
		t.Fatal(err)
	}
	if receipt == nil || receipt.StatusEventId != failed.Event.EventId || receipt.PersistedTime == nil {
		t.Fatalf("durable ACK receipt = %+v", receipt)
	}
	if err := client.store.markDeploymentStatusAckReceiptSent(record.RecordKey, 7, 2); err != nil {
		t.Fatal(err)
	}

	closeGatewayClientForRestart(t, client)
	restarted, err := New(client.config, &failingDialer{}, client.manager, client.trust)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.pendingDeploymentStatusAckReceipts()
	if err != nil || len(pending) != 1 || !proto.Equal(pending[0].receipt, receipt) {
		t.Fatalf("restarted ACK receipts = (%+v, %v)", pending, err)
	}
	if err := restarted.confirmDeploymentStatusAckReceipts(7, 2); err != nil {
		t.Fatal(err)
	}
	if proof, err := restarted.store.record(record.RecordKey); err != nil || proof == nil {
		t.Fatalf("same-sequence heartbeat compacted proof: (%+v, %v)", proof, err)
	}
	if err := restarted.confirmDeploymentStatusAckReceipts(7, 3); err != nil {
		t.Fatal(err)
	}
	if proof, err := restarted.store.record(record.RecordKey); err != nil || proof != nil {
		t.Fatalf("causally confirmed proof was not compacted: (%+v, %v)", proof, err)
	}
}

func TestDeploymentStatusAckPublicationIdentityIsDurableAndBoundToReceipt(t *testing.T) {
	client, _, command, _, _, _ := activeIdentityClient(t)
	record := persistFailedTerminalRecord(t, client, command)
	ack := deploymentStatusAckForRecord(t, record)
	ack.PublishedStream = "AGENT_DEPLOYMENT_STATUS"
	ack.PublishedSequence = 73
	receipt, err := client.persistDeploymentStatusAckReceipt(ack)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.GetPublishedStream() != ack.PublishedStream || receipt.GetPublishedSequence() != ack.PublishedSequence {
		t.Fatalf("ACK receipt publication = (%q, %d), want (%q, %d)",
			receipt.GetPublishedStream(), receipt.GetPublishedSequence(), ack.PublishedStream, ack.PublishedSequence)
	}
	persisted, err := client.store.loadDeploymentStatusAckLocked(record.RecordKey)
	if err != nil || persisted == nil || persisted.PublishedStream != ack.PublishedStream || persisted.PublishedSequence != ack.PublishedSequence {
		t.Fatalf("durable ACK publication = (%+v, %v)", persisted, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*agentv1.DeploymentStatusAck)
	}{
		{name: "missing stream", mutate: func(value *agentv1.DeploymentStatusAck) { value.PublishedStream = "" }},
		{name: "zero sequence", mutate: func(value *agentv1.DeploymentStatusAck) { value.PublishedSequence = 0 }},
		{name: "wrong stream", mutate: func(value *agentv1.DeploymentStatusAck) { value.PublishedStream = "OTHER" }},
		{name: "sequence conflict", mutate: func(value *agentv1.DeploymentStatusAck) { value.PublishedSequence++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			conflict := proto.Clone(ack).(*agentv1.DeploymentStatusAck)
			test.mutate(conflict)
			if _, err := client.persistDeploymentStatusAckReceipt(conflict); err == nil {
				t.Fatal("invalid publication identity was accepted")
			}
		})
	}
}

func TestDeploymentStatusAckReceiptHeartbeatBarrierHasOneOutstandingHeartbeat(t *testing.T) {
	client, _, _, _, _, _ := activeIdentityClient(t)
	gateway := &receiptHeartbeatBarrierGateway{seen: make(chan struct{})}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	connection, err := grpc.NewClient("passthrough:///receipt-heartbeat", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, runErr := client.runSession(ctx, agentv1.NewAgentGatewayServiceClient(connection))
		done <- runErr
	}()
	select {
	case <-gateway.seen:
	case <-time.After(time.Second):
		t.Fatal("receipt session did not send its first heartbeat")
	}
	time.Sleep(40 * time.Millisecond)
	if got := gateway.heartbeats.Load(); got != 1 {
		t.Fatalf("heartbeats outstanding before an ACK = %d, want 1", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		t.Fatalf("receipt heartbeat session error = %v", err)
	}
}

func TestHeartbeatCausationProvesPriorAckForCapability18Sessions(t *testing.T) {
	for _, test := range []struct {
		name                   string
		agentOffersReceipt     bool
		gatewaySupportsReceipt bool
	}{
		{name: "Agent19Gateway18", agentOffersReceipt: true, gatewaySupportsReceipt: false},
		{name: "Gateway19Agent18", agentOffersReceipt: false, gatewaySupportsReceipt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _, _, _, _, _ := activeIdentityClient(t)
			if !test.agentOffersReceipt {
				client.config.Capabilities.Features = removeCapability(
					client.config.Capabilities.Features,
					agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT,
				)
			}
			gateway := &heartbeatCausationGateway{
				supportReceipt: test.gatewaySupportsReceipt,
				observed:       make(chan error, 1),
			}
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer()
			agentv1.RegisterAgentGatewayServiceServer(server, gateway)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() {
				server.Stop()
				_ = listener.Close()
			})
			connection, err := grpc.NewClient("passthrough:///heartbeat-causation", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, runErr := client.runSession(ctx, agentv1.NewAgentGatewayServiceClient(connection))
				done <- runErr
			}()
			select {
			case err := <-gateway.observed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Agent did not causally bind a heartbeat to a processed HeartbeatAck")
			}
			cancel()
			// The cancel can land while a gRPC Send/Recv is in flight, which
			// reports status Canceled instead of context.Canceled (as in the
			// sibling receipt-lifecycle tests).
			if err := <-done; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) &&
				grpcstatus.Code(err) != codes.Canceled {
				t.Fatalf("heartbeat causation session error = %v", err)
			}
		})
	}
}

func TestDeploymentStatusAckReceiptLifecycleRequiresNegotiatedCapability19(t *testing.T) {
	for _, test := range []struct {
		name                   string
		agentOffersReceipt     bool
		gatewaySupportsReceipt bool
	}{
		{name: "Agent19Gateway18", agentOffersReceipt: true, gatewaySupportsReceipt: false},
		{name: "Gateway19Agent18", agentOffersReceipt: false, gatewaySupportsReceipt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _, command, _, _, _ := activeIdentityClient(t)
			if !test.agentOffersReceipt {
				client.config.Capabilities.Features = removeCapability(
					client.config.Capabilities.Features,
					agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT,
				)
			}
			historical := proto.Clone(command).(*agentv1.DeploymentCommand)
			historical.Event.EventId = uuid.NewString()
			historical.Event.RequestId = uuid.NewString()
			historical.DeploymentId = uuid.NewString()
			historical.RolloutId = uuid.NewString()
			historical.ConfigVersionId = uuid.NewString()
			historical.Artifacts[0].ArtifactId = uuid.NewString()
			record, _, err := client.store.putCommand(historical, deliveredStatus(historical))
			if err != nil {
				t.Fatal(err)
			}
			failed := failedStatus(historical, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", true)
			if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
				t.Fatal(err)
			}

			gateway := &receiptNegotiationGateway{
				supportReceipt:  test.gatewaySupportsReceipt,
				dropTerminalAck: true,
				command:         historical,
				acknowledged:    make(chan struct{}),
			}
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer()
			agentv1.RegisterAgentGatewayServiceServer(server, gateway)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() {
				server.Stop()
				_ = listener.Close()
			})
			connection, err := grpc.NewClient("passthrough:///receipt-negotiation", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, runErr := client.runSession(ctx, agentv1.NewAgentGatewayServiceClient(connection))
				done <- runErr
			}()
			select {
			case <-gateway.acknowledged:
			case <-time.After(time.Second):
				t.Fatal("legacy-compatible terminal status was not observed")
			}
			waitForActiveIdentityTest(t, time.Second, func() bool {
				persisted, loadErr := client.store.record(record.RecordKey)
				return loadErr == nil && persisted == nil
			})
			if gateway.receipts.Load() != 0 {
				t.Fatalf("non-negotiated session sent %d receipt messages", gateway.receipts.Load())
			}
			if _, err := os.Stat(filepath.Join(client.store.directory, record.RecordKey+deploymentStatusAckReceiptSuffix)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("non-negotiated session retained receipt state: %v", err)
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && grpcstatus.Code(err) != codes.Canceled {
				t.Fatalf("receipt negotiation session error = %v", err)
			}
		})
	}
}

func TestLegacyHeartbeatPromotionWaitsForAuthoritativeCommand(t *testing.T) {
	for _, test := range []struct {
		name                   string
		agentOffersReceipt     bool
		gatewaySupportsReceipt bool
	}{
		{name: "Agent19Gateway18", agentOffersReceipt: true, gatewaySupportsReceipt: false},
		{name: "Gateway19Agent18", agentOffersReceipt: false, gatewaySupportsReceipt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _, command, _, _, _ := activeIdentityClient(t)
			if !test.agentOffersReceipt {
				client.config.Capabilities.Features = removeCapability(
					client.config.Capabilities.Features,
					agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT,
				)
			}
			historical := proto.Clone(command).(*agentv1.DeploymentCommand)
			historical.Event.EventId = uuid.NewString()
			historical.Event.RequestId = uuid.NewString()
			historical.DeploymentId = uuid.NewString()
			historical.RolloutId = uuid.NewString()
			historical.ConfigVersionId = uuid.NewString()
			historical.Artifacts[0].ArtifactId = uuid.NewString()
			record, _, err := client.store.putCommand(historical, deliveredStatus(historical))
			if err != nil {
				t.Fatal(err)
			}
			failed := failedStatus(historical, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", false)
			if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
				t.Fatal(err)
			}
			counter := &countingDeploymentManager{manager: client.manager}
			client.manager = counter
			gateway := &delayedAuthoritativeCommandGateway{
				supportReceipt:       test.gatewaySupportsReceipt,
				command:              proto.Clone(historical).(*agentv1.DeploymentCommand),
				terminalAcknowledged: make(chan struct{}),
			}
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer()
			agentv1.RegisterAgentGatewayServiceServer(server, gateway)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() {
				server.Stop()
				_ = listener.Close()
			})
			connection, err := grpc.NewClient("passthrough:///delayed-authoritative-command", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close() })

			_, runErr := client.runSession(context.Background(), agentv1.NewAgentGatewayServiceClient(connection))
			if !errors.Is(runErr, io.EOF) && grpcstatus.Code(runErr) != codes.Unavailable {
				t.Fatalf("session 1 error = %v, want EOF or Unavailable", runErr)
			}
			persisted, loadErr := client.store.record(record.RecordKey)
			if loadErr != nil || persisted == nil || !persisted.ExecutionDone {
				t.Fatalf("unbound terminal proof after heartbeat ACK = (%+v, %v)", persisted, loadErr)
			}
			if _, statErr := os.Stat(filepath.Join(client.store.directory, record.RecordKey+deploymentStatusAckSuffix)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unbound terminal gained a durable ACK: %v", statErr)
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, sessionErr := client.runSession(ctx, agentv1.NewAgentGatewayServiceClient(connection))
				done <- sessionErr
			}()
			select {
			case <-gateway.terminalAcknowledged:
			case <-time.After(time.Second):
				t.Fatal("delayed authoritative terminal was not acknowledged")
			}
			waitForActiveIdentityTest(t, time.Second, func() bool {
				persisted, err := client.store.record(record.RecordKey)
				return err == nil && persisted == nil
			})
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && grpcstatus.Code(err) != codes.Canceled {
				t.Fatalf("session 2 error = %v, want canceled session", err)
			}

			if gateway.sessions.Load() != 2 || gateway.heartbeatACKsBeforeCommand.Load() != 1 ||
				gateway.terminalBeforeCommand.Load() != 2 || gateway.terminalAfterCommand.Load() != 1 ||
				gateway.terminalAcknowledgements.Load() != 1 {
				t.Fatalf("mixed-version replay = sessions:%d heartbeat-before-command:%d terminal-before:%d terminal-after:%d ACKs:%d",
					gateway.sessions.Load(), gateway.heartbeatACKsBeforeCommand.Load(), gateway.terminalBeforeCommand.Load(),
					gateway.terminalAfterCommand.Load(), gateway.terminalAcknowledgements.Load())
			}
			if len(gateway.accepted) != 1 || !proto.Equal(gateway.accepted[0], failed) {
				t.Fatalf("accepted terminal replay = %+v, want %+v", gateway.accepted, failed)
			}
			if counter.process.Load() != 0 {
				t.Fatalf("completed deployment executed again %d times", counter.process.Load())
			}
		})
	}
}

func TestLegacyTerminalAckOutboxRecoveryPreservesActiveProof(t *testing.T) {
	for _, test := range []struct {
		name                   string
		agentOffersReceipt     bool
		gatewaySupportsReceipt bool
	}{
		{name: "Agent19Gateway18", agentOffersReceipt: true, gatewaySupportsReceipt: false},
		{name: "Gateway19Agent18", agentOffersReceipt: false, gatewaySupportsReceipt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, manager, current, wire, _, privateKey := activeIdentityClient(t)
			if !test.agentOffersReceipt {
				client.config.Capabilities.Features = removeCapability(
					client.config.Capabilities.Features,
					agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT,
				)
			}
			historical, historicalWire := nextActiveIdentityDeployment(t, current, privateKey)
			historicalRecord := persistActiveIdentityCommand(t, client, historical, historicalWire)
			failed := failedStatus(historical, 2, client.now(), commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "historical failure", false)
			if err := client.store.appendStatuses(historicalRecord.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
				t.Fatal(err)
			}
			currentRecord := persistActiveIdentityCommand(t, client, current, wire)
			completeDeploymentWithoutAck(t, client, manager, currentRecord)
			hello, err := client.agentHello()
			if err != nil {
				t.Fatal(err)
			}
			assertActiveIdentity(t, hello.CurrentConfigIdentity, current.ConfigVersionId, current.Artifacts[0].Sha256)
			counter := &countingDeploymentManager{manager: client.manager}
			client.manager = counter
			gateway := &legacyTerminalAckRecoveryGateway{
				supportReceipt: test.gatewaySupportsReceipt,
				command:        proto.Clone(historical).(*agentv1.DeploymentCommand),
				firstAccepted:  make(chan struct{}), replayAcked: make(chan struct{}), causalHeartbeat: make(chan struct{}),
			}
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer()
			agentv1.RegisterAgentGatewayServiceServer(server, gateway)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() {
				server.Stop()
				_ = listener.Close()
			})
			connection, err := grpc.NewClient("passthrough:///legacy-terminal-ack-recovery", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close() })

			_, runErr := client.runSession(context.Background(), agentv1.NewAgentGatewayServiceClient(connection))
			if !errors.Is(runErr, io.EOF) && grpcstatus.Code(runErr) != codes.Unavailable {
				t.Fatalf("session A error = %v, want EOF or Unavailable", runErr)
			}
			select {
			case <-gateway.firstAccepted:
			default:
				t.Fatal("session A did not persist the command-bound terminal")
			}
			if persisted, err := client.store.record(historicalRecord.RecordKey); err != nil || persisted == nil || !persisted.ExecutionDone {
				t.Fatalf("lost terminal ACK discarded replay proof: (%+v, %v)", persisted, err)
			}
			if _, err := os.Stat(client.store.artifactPath(historicalRecord.RecordKey)); err != nil {
				t.Fatalf("lost terminal ACK discarded artifact proof: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, sessionErr := client.runSession(ctx, agentv1.NewAgentGatewayServiceClient(connection))
				done <- sessionErr
			}()
			select {
			case <-gateway.replayAcked:
			case <-time.After(time.Second):
				t.Fatal("session B did not replay the durable terminal ACK")
			}
			select {
			case <-gateway.causalHeartbeat:
			case <-time.After(time.Second):
				t.Fatal("session B did not reach the causal heartbeat")
			}
			waitForActiveIdentityTest(t, time.Second, func() bool {
				persisted, loadErr := client.store.record(historicalRecord.RecordKey)
				return loadErr == nil && persisted == nil
			})
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && grpcstatus.Code(err) != codes.Canceled {
				t.Fatalf("session B error = %v, want canceled session", err)
			}
			if gateway.sessions.Load() != 2 || gateway.publications.Load() != 1 || gateway.replays.Load() != 1 || counter.process.Load() != 0 {
				t.Fatalf("legacy ACK recovery = sessions:%d publications:%d replays:%d executions:%d",
					gateway.sessions.Load(), gateway.publications.Load(), gateway.replays.Load(), counter.process.Load())
			}
			if currentProof, err := client.store.record(currentRecord.RecordKey); err != nil || currentProof == nil {
				t.Fatalf("current HEALTHY proof was compacted: (%+v, %v)", currentProof, err)
			}
			if _, err := os.Stat(client.store.artifactPath(currentRecord.RecordKey)); err != nil {
				t.Fatalf("current HEALTHY artifact proof was compacted: %v", err)
			}
		})
	}
}

func TestCurrentAndPreviousProofSurvivesArtifactReadFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		target string
		mutate func(string) error
	}{
		{name: "missing current", target: "current", mutate: os.Remove},
		{name: "unreadable previous", target: "previous", mutate: func(path string) error { return os.Chmod(path, 0) }},
		{name: "corrupt current", target: "current", mutate: func(path string) error {
			return os.WriteFile(path, []byte("corrupt signed artifact"), 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, manager, first, firstWire, _, privateKey := activeIdentityClient(t)
			firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
			completeAndAcknowledgeDeployment(t, client, manager, firstRecord)

			second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
			bundle, err := decodeConfigurationBundle(secondWire)
			if err != nil {
				t.Fatal(err)
			}
			result, err := manager.Process(context.Background(), deployment.Command{
				DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
				ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: bundle,
			})
			if err != nil || result.State != deployment.StateHealthy {
				t.Fatalf("Process(second) = (%+v, %v)", result, err)
			}
			secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
			completeAndAcknowledgeDeployment(t, client, manager, secondRecord)

			pendingCommand := proto.Clone(second).(*agentv1.DeploymentCommand)
			pendingCommand.Event.EventId = uuid.NewString()
			pendingCommand.Event.RequestId = uuid.NewString()
			pendingCommand.DeploymentId = uuid.NewString()
			pendingCommand.RolloutId = uuid.NewString()
			pendingCommand.ConfigVersionId = uuid.NewString()
			pendingCommand.Artifacts[0].ArtifactId = uuid.NewString()
			pendingRecord, _, err := client.store.putCommand(pendingCommand, deliveredStatus(pendingCommand))
			if err != nil {
				t.Fatal(err)
			}

			target := secondRecord
			if test.target == "previous" {
				target = firstRecord
			}
			if err := test.mutate(client.store.artifactPath(target.RecordKey)); err != nil {
				t.Fatal(err)
			}
			closeGatewayClientForRestart(t, client)
			restarted, err := New(client.config, &failingDialer{}, manager, client.trust)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.agentHello(); err != nil {
				t.Fatal(err)
			}
			for _, proof := range []*durableRecord{firstRecord, secondRecord} {
				if _, err := os.Stat(filepath.Join(restarted.store.directory, proof.RecordKey+".json")); err != nil {
					t.Fatalf("active identity proof %s was deleted: %v", proof.RecordKey, err)
				}
			}
			if pending, err := restarted.store.record(pendingRecord.RecordKey); err != nil || pending == nil || pending.ExecutionDone {
				t.Fatalf("pending proof = (%+v, %v)", pending, err)
			}
			closeGatewayClientForRestart(t, restarted)
			secondRestart, err := New(client.config, &failingDialer{}, manager, client.trust)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := secondRestart.agentHello(); err != nil {
				t.Fatal(err)
			}
			for _, proof := range []*durableRecord{firstRecord, secondRecord} {
				if _, err := os.Stat(filepath.Join(secondRestart.store.directory, proof.RecordKey+".json")); err != nil {
					t.Fatalf("second restart deleted proof %s: %v", proof.RecordKey, err)
				}
			}
		})
	}
}

func TestActiveConfigIdentityTracksCurrentPreviousAndExplicitRollback(t *testing.T) {
	client, manager, first, firstWire, _, privateKey := activeIdentityClient(t)
	firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
	completeDeploymentWithoutAck(t, client, manager, firstRecord)

	second := proto.Clone(first).(*agentv1.DeploymentCommand)
	second.Event.EventId = uuid.NewString()
	second.Event.RequestId = uuid.NewString()
	second.DeploymentId = uuid.NewString()
	second.RolloutId = uuid.NewString()
	second.ConfigVersionId = uuid.NewString()
	second.PreviousConfigVersionId = proto.String(first.ConfigVersionId)
	second.Artifacts[0].ArtifactId = uuid.NewString()
	content := []byte("server { listen 8443; }")
	contentDigest := sha256.Sum256(content)
	manifest := deployment.Manifest{Files: []deployment.FileManifest{{
		Path: "nginx/site.conf", Size: int64(len(content)), SHA256: hex.EncodeToString(contentDigest[:]),
	}}}
	manifestDigest, err := deployment.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	secondWire, err := json.Marshal(configurationBundleDocument{
		Version: 1, Manifest: manifest, ManifestSHA256: manifestDigest,
		Files: map[string][]byte{"nginx/site.conf": content},
	})
	if err != nil {
		t.Fatal(err)
	}
	wireDigest := sha256.Sum256(secondWire)
	second.Artifacts[0].SizeBytes = uint64(len(secondWire))
	second.Artifacts[0].Sha256 = wireDigest[:]
	second.Artifacts[0].Signature = ed25519.Sign(privateKey, secondWire)
	secondBundle, err := decodeConfigurationBundle(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: secondBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(second) = (%+v, %v)", result, err)
	}
	secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
	completeDeploymentWithoutAck(t, client, manager, secondRecord)

	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
	assertActiveIdentity(t, hello.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
	heartbeat, err := client.heartbeat(9, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, heartbeat.CurrentConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
	assertActiveIdentity(t, heartbeat.PreviousConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)

	rollback, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: uuid.NewString(), Attempt: 1, Action: deployment.ActionRollback,
		ConfigVersionID: first.ConfigVersionId, PreviousVersionID: second.ConfigVersionId,
	})
	if err != nil || rollback.State != deployment.StateReverted {
		t.Fatalf("Process(rollback) = (%+v, %v)", rollback, err)
	}
	hello, err = client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	assertActiveIdentity(t, hello.CurrentConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
	assertActiveIdentity(t, hello.PreviousConfigIdentity, second.ConfigVersionId, second.Artifacts[0].Sha256)
}

func closeGatewayClientForRestart(t *testing.T, client *Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func activeIdentityClient(t *testing.T) (*Client, *deployment.Manager, *agentv1.DeploymentCommand, []byte, string, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, wire := signedBundleTestCommand(t, privateKey)
	command.ConfigVersionId = uuid.NewString()
	bundle, err := decodeConfigurationBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(secureTempDir(t), "deployment")
	manager, err := deployment.NewManager(root, testPrechecker{}, &testRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeTestTreeWritable(root) })
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: command.DeploymentId, Attempt: command.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: command.ConfigVersionId, Bundle: bundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	client, err := New(config, &failingDialer{}, manager, trust)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, manager, command, wire, root, privateKey
}

func activeIdentityClientWithRuntime(t *testing.T, runtime deployment.Runtime) (*Client, *deployment.Manager, *agentv1.DeploymentCommand, []byte, string, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, wire := signedBundleTestCommand(t, privateKey)
	command.ConfigVersionId = uuid.NewString()
	bundle, err := decodeConfigurationBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(secureTempDir(t), "deployment")
	manager, err := deployment.NewManager(root, testPrechecker{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeTestTreeWritable(root) })
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: command.DeploymentId, Attempt: command.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: command.ConfigVersionId, Bundle: bundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	client, err := New(config, &failingDialer{}, manager, trust)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, manager, command, wire, root, privateKey
}

func nextActiveIdentityDeployment(t *testing.T, previous *agentv1.DeploymentCommand, privateKey ed25519.PrivateKey) (*agentv1.DeploymentCommand, []byte) {
	t.Helper()
	command := proto.Clone(previous).(*agentv1.DeploymentCommand)
	command.Event.EventId = uuid.NewString()
	command.Event.RequestId = uuid.NewString()
	command.DeploymentId = uuid.NewString()
	command.RolloutId = uuid.NewString()
	command.ConfigVersionId = uuid.NewString()
	command.PreviousConfigVersionId = proto.String(previous.ConfigVersionId)
	command.Artifacts[0].ArtifactId = uuid.NewString()
	content := []byte("server { listen 9443; }")
	contentDigest := sha256.Sum256(content)
	manifest := deployment.Manifest{Files: []deployment.FileManifest{{
		Path: "nginx/next.conf", Size: int64(len(content)), SHA256: hex.EncodeToString(contentDigest[:]),
	}}}
	manifestDigest, err := deployment.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(configurationBundleDocument{
		Version: 1, Manifest: manifest, ManifestSHA256: manifestDigest,
		Files: map[string][]byte{"nginx/next.conf": content},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	command.Artifacts[0].SizeBytes = uint64(len(wire))
	command.Artifacts[0].Sha256 = digest[:]
	command.Artifacts[0].Signature = ed25519.Sign(privateKey, wire)
	return command, wire
}

func completeAndAcknowledgeDeployment(t *testing.T, client *Client, manager *deployment.Manager, record *durableRecord) {
	t.Helper()
	result, found, err := manager.Lookup(record.DeploymentID)
	if err != nil || !found {
		t.Fatalf("Lookup() = (%+v, %t, %v)", result, found, err)
	}
	command := commandFromBytes(record.Command)
	if command == nil {
		t.Fatal("durable command is corrupt")
	}
	if err := client.completeDeploymentRecord(record.RecordKey, statusesForResult(command, result), true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.acknowledgeDeploymentStatus(deploymentStatusAckForRecord(t, persisted)); err != nil {
		t.Fatal(err)
	}
}

func completeDeploymentWithoutAck(t *testing.T, client *Client, manager *deployment.Manager, record *durableRecord) {
	t.Helper()
	result, found, err := manager.Lookup(record.DeploymentID)
	if err != nil || !found {
		t.Fatalf("Lookup() = (%+v, %t, %v)", result, found, err)
	}
	command := commandFromBytes(record.Command)
	if command == nil {
		t.Fatal("durable command is corrupt")
	}
	if err := client.completeDeploymentRecord(record.RecordKey, statusesForResult(command, result), true); err != nil {
		t.Fatal(err)
	}
}

func waitForActiveIdentityTest(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func deploymentStatusAckForRecord(t *testing.T, record *durableRecord) *agentv1.DeploymentStatusAck {
	t.Helper()
	statuses, err := statusesFromRecord(record)
	if err != nil || len(statuses) == 0 {
		t.Fatalf("statusesFromRecord() = (%d, %v)", len(statuses), err)
	}
	final := statuses[len(statuses)-1]
	return &agentv1.DeploymentStatusAck{
		StatusEventId: final.Event.EventId, DeploymentId: final.DeploymentId, Attempt: final.Attempt,
		ConfigVersionId: final.ConfigVersionId, TransitionSequence: final.TransitionSequence,
		PersistedTime: timestamppb.Now(), PublishedStream: deploymentStatusStream, PublishedSequence: 41,
	}
}

func assertUnknownLoadedIdentity(t *testing.T, client *Client) {
	t.Helper()
	hello, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.CurrentConfigIdentity != nil {
		t.Fatalf("hello claimed uncertain identity: %+v", hello.CurrentConfigIdentity)
	}
	heartbeat, err := client.heartbeat(7, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.CurrentConfigIdentity != nil || heartbeat.Runtime.LoadedConfigIdentity != nil || heartbeat.Runtime.LoadedConfigVersionId != nil {
		t.Fatalf("heartbeat claimed uncertain loaded identity: %+v", heartbeat)
	}
}

func persistActiveIdentityCommand(t *testing.T, client *Client, command *agentv1.DeploymentCommand, wire []byte) *durableRecord {
	t.Helper()
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	file, err := client.store.openArtifact(record.RecordKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(wire); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.store.setArtifactOffset(record.RecordKey, uint64(len(wire))); err != nil {
		t.Fatal(err)
	}
	return record
}

func assertIdentityCapability(t *testing.T, capabilities []*agentv1.Capability) {
	t.Helper()
	for _, capability := range capabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY {
			assertCapability(t, capability)
			return
		}
	}
	t.Fatal("active config identity capability was not advertised")
}

func assertCapability(t *testing.T, capability *agentv1.Capability) {
	t.Helper()
	if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY || capability.ApiVersion != 1 {
		t.Fatalf("capability = %+v, want active config identity v1", capability)
	}
}

func assertActiveIdentity(t *testing.T, identity *agentv1.ActiveConfigIdentity, configVersionID string, digest []byte) {
	t.Helper()
	if identity == nil || identity.ConfigVersionId != configVersionID || identity.Schema != agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1 || !bytes.Equal(identity.ArtifactSha256, digest) || len(identity.ArtifactSha256) != sha256.Size {
		t.Fatalf("identity = %+v, want config=%s digest=%x", identity, configVersionID, digest)
	}
}

func testActiveConfigIdentity(configVersionID string, digest []byte) *agentv1.ActiveConfigIdentity {
	return &agentv1.ActiveConfigIdentity{
		ConfigVersionId: configVersionID,
		ArtifactSha256:  append([]byte(nil), digest...),
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
	}
}
