package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	mtScopeA = "11111111-1111-4111-8111-111111111111"
	mtScopeB = "22222222-2222-4222-8222-222222222222"
)

// scopedSignedRelease is a signed site object release for scopeID.
func scopedSignedRelease(t *testing.T, privateKey ed25519.PrivateKey, scopeID string) *siteObjectTestRelease {
	t.Helper()
	contentKey := make([]byte, siteobject.ContentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	return newSiteObjectRelease(t, privateKey, testRecipientKey, testRecipientID, contentKey, scopeID, 1, []byte(`{"cc":1}`))
}

type multiTenantGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	commands   []*agentv1.DeploymentCommand
	artifacts  map[string][]byte
	holdFirst  chan struct{} // closed once the last command is queued on the node
	holdOnce   sync.Once
	firstID    string
	mu         sync.Mutex
	hello      *agentv1.AgentHello
	statuses   []*agentv1.DeploymentStatus
	heartbeats []*agentv1.Heartbeat
	events     chan struct{}
}

func (g *multiTenantGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil || first.GetHello() == nil {
		return status.Error(codes.InvalidArgument, "invalid hello")
	}
	g.mu.Lock()
	g.hello = first.GetHello()
	g.mu.Unlock()
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
		SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test", SessionId: uuid.NewString(),
		SessionEpoch: 1, ServerTime: timestamppb.Now(), HeartbeatIntervalDuration: durationpb.New(20 * time.Millisecond),
		OfflineAfterDuration: durationpb.New(2 * time.Second), MaximumArtifactChunkBytes: 1 << 16, MessageIdReplayWindow: 128,
		EnabledCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME, ApiVersion: 1},
		},
	}}}); err != nil {
		return err
	}
	sequence := uint64(1)
	for _, command := range g.commands {
		sequence++
		if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(sequence), Payload: &agentv1.ConnectResponse_DeploymentCommand{DeploymentCommand: command}}); err != nil {
			return err
		}
	}
	lastID := g.commands[len(g.commands)-1].DeploymentId
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		g.mu.Lock()
		if value := request.GetDeploymentStatus(); value != nil {
			g.statuses = append(g.statuses, value)
			// Release the first deployment only after the node has queued the
			// last command, so the supersede decision is deterministic.
			if value.DeploymentId == lastID && value.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED {
				g.holdOnce.Do(func() { close(g.holdFirst) })
			}
		}
		heartbeat := request.GetHeartbeat()
		if heartbeat != nil {
			g.heartbeats = append(g.heartbeats, heartbeat)
		}
		g.mu.Unlock()
		select {
		case g.events <- struct{}{}:
		default:
		}
		if heartbeat != nil {
			sequence++
			if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(sequence), Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
				HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 1, ReceivedTime: timestamppb.Now(),
			}}}); err != nil {
				return err
			}
		}
	}
}

func (g *multiTenantGateway) FetchArtifact(request *agentv1.FetchArtifactRequest, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error {
	if request.DeploymentId == g.firstID {
		<-g.holdFirst // keep the node busy until every command has been queued
	}
	artifact := g.artifacts[request.ArtifactId]
	remaining := artifact[request.Offset:]
	digest := sha256.Sum256(remaining)
	return stream.Send(&agentv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: request.Offset,
		Data: remaining, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(artifact)), EndOfArtifact: true,
	}})
}

func (g *multiTenantGateway) statusesFor(deploymentID string) []*agentv1.DeploymentStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	var result []*agentv1.DeploymentStatus
	seen := map[string]bool{}
	for _, value := range g.statuses {
		if value.DeploymentId == deploymentID && !seen[value.Event.EventId] {
			seen[value.Event.EventId] = true
			result = append(result, value)
		}
	}
	return result
}

func TestMultiTenantSessionQueuesSupersedesAndReportsScopes(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r1, r2, r3 := scopedSignedRelease(t, privateKey, mtScopeA), scopedSignedRelease(t, privateKey, mtScopeB), scopedSignedRelease(t, privateKey, mtScopeB)
	a1, b1, b2 := r1.command, r2.command, r3.command
	gateway := &dynamicMultiGateway{
		multiTenantGateway: &multiTenantGateway{
			commands: []*agentv1.DeploymentCommand{a1, b1, b2}, holdFirst: make(chan struct{}), firstID: a1.DeploymentId,
			events: make(chan struct{}, 1),
		},
		releases: map[string]*siteObjectTestRelease{a1.DeploymentId: r1, b1.DeploymentId: r2, b2.DeploymentId: r3},
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	applier := &scopedDynamicRouting{current: map[string]deployment.Pointers{}, results: map[string]deployment.Result{}}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := testClientConfig(filepath.Join(root, "gateway-journal"))
	clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features,
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY, ApiVersion: 1})
	client, err := New(clientConfig, &bufDialer{listener: listener}, applier, trust, dynamicTestOptions(t, root, applier)...)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	final := func(deploymentID string) *agentv1.DeploymentStatus {
		statuses := gateway.statusesFor(deploymentID)
		if len(statuses) == 0 {
			return nil
		}
		return statuses[len(statuses)-1]
	}
	deadline := time.After(10 * time.Second)
	for {
		a, b := final(a1.DeploymentId), final(b2.DeploymentId)
		superseded := final(b1.DeploymentId)
		if a != nil && b != nil && superseded != nil && a.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
			b.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
			superseded.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED {
			break
		}
		select {
		case <-gateway.events:
		case <-deadline:
			t.Fatalf("deployments did not settle: a1=%v b1=%v b2=%v", a, superseded, b)
		}
	}

	gateway.mu.Lock()
	hello := gateway.hello
	gateway.mu.Unlock()
	if !hasCapability(hello.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME) {
		t.Fatalf("hello did not declare capability 33: %+v", hello.Capabilities)
	}
	wantStates := map[string][]agentv1.NodeDeploymentState{
		a1.DeploymentId: {agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED},
		b1.DeploymentId: {agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED},
	}
	for _, command := range []*agentv1.DeploymentCommand{a1, b1, b2} {
		statuses := gateway.statusesFor(command.DeploymentId)
		for index, value := range statuses {
			if value.GetConfigurationScopeId() != command.GetConfigurationScopeId() {
				t.Fatalf("%s status %s has scope %q, want %q", command.DeploymentId, value.State, value.GetConfigurationScopeId(), command.GetConfigurationScopeId())
			}
			if value.TransitionSequence != uint64(index+1) {
				t.Fatalf("%s status %s sequence %d, want %d (all: %v)", command.DeploymentId, value.State, value.TransitionSequence, index+1, statuses)
			}
		}
		for index, want := range wantStates[command.DeploymentId] {
			if index >= len(statuses) || statuses[index].State != want {
				t.Fatalf("%s states = %v, want prefix %v", command.DeploymentId, statuses, wantStates[command.DeploymentId])
			}
		}
	}

	// Heartbeats converge on each scope's current release and last result.
	settled := func(entries []*agentv1.ScopedConfigIdentity) bool {
		return len(entries) == 2 &&
			entries[0].GetCurrentConfigVersionId() == a1.ConfigVersionId && entries[0].GetLastApplyResult().GetDeploymentId() == a1.DeploymentId &&
			entries[1].GetCurrentConfigVersionId() == b2.ConfigVersionId && entries[1].GetLastApplyResult().GetDeploymentId() == b2.DeploymentId
	}
	var scoped []*agentv1.ScopedConfigIdentity
	heartbeatDeadline := time.After(10 * time.Second)
	for scoped == nil {
		gateway.mu.Lock()
		for _, heartbeat := range gateway.heartbeats {
			if len(heartbeat.ScopedConfigIdentities) > 1 && (heartbeat.CurrentConfigVersionId != nil || heartbeat.CurrentConfigIdentity != nil) {
				gateway.mu.Unlock()
				t.Fatalf("multi-scope heartbeat carried a node-wide identity: %+v", heartbeat)
			}
			for _, entry := range heartbeat.ScopedConfigIdentities {
				if entry.LastApplyResult != nil && entry.GetLastApplyResult().GetState() == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
					entry.GetCurrentConfigVersionId() != entry.GetLastApplyResult().GetConfigVersionId() {
					gateway.mu.Unlock()
					t.Fatalf("heartbeat reported a healthy result newer than the scope's current release: %+v", entry)
				}
			}
			if settled(heartbeat.ScopedConfigIdentities) {
				scoped = heartbeat.ScopedConfigIdentities
			}
		}
		gateway.mu.Unlock()
		if scoped != nil {
			break
		}
		select {
		case <-gateway.events:
		case <-heartbeatDeadline:
			t.Fatal("heartbeats never reported both scopes' settled state")
		}
	}
	if len(scoped) != 2 || scoped[0].ConfigurationScopeId != mtScopeA || scoped[1].ConfigurationScopeId != mtScopeB {
		t.Fatalf("scoped identities = %+v", scoped)
	}
	for _, check := range []struct {
		entry   *agentv1.ScopedConfigIdentity
		command *agentv1.DeploymentCommand
	}{{scoped[0], a1}, {scoped[1], b2}} {
		if check.entry.GetCurrentConfigVersionId() != check.command.ConfigVersionId || check.entry.CurrentConfigIdentity == nil ||
			check.entry.LastApplyResult.GetDeploymentId() != check.command.DeploymentId ||
			check.entry.LastApplyResult.GetState() != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
			t.Fatalf("scope %s entry = %+v, want current %s and healthy result for %s",
				check.entry.ConfigurationScopeId, check.entry, check.command.ConfigVersionId, check.command.DeploymentId)
		}
	}
}
