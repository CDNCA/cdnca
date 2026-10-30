package gatewayclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// scopedDynamicRouting stands in for the daemon's dynamic routing manager:
// per-scope pointers and every apply merging all scopes' current releases.
type scopedDynamicRouting struct {
	mu      sync.Mutex
	current map[string]deployment.Pointers
	results map[string]deployment.Result
	// merged is the scope -> config version set of each apply.
	merged []map[string]string
}

func (f *scopedDynamicRouting) ApplyDynamicRouting(_ context.Context, deploymentID string, attempt uint32,
	release DynamicRoutingRelease) (deployment.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.current[release.ConfigurationScopeID] = deployment.Pointers{Current: release.ConfigVersionID, CurrentDigest: release.RootSHA256}
	view := map[string]string{}
	for scopeID, pointers := range f.current {
		view[scopeID] = pointers.Current
	}
	f.merged = append(f.merged, view)
	result := DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, release.ConfigVersionID, time.Now(), time.Now(), nil)
	f.results[deploymentID] = result
	return result, nil
}

func (f *scopedDynamicRouting) Process(context.Context, deployment.Command) (deployment.Result, error) {
	return deployment.Result{}, errors.New("not used")
}

func (f *scopedDynamicRouting) Pointers() (deployment.Pointers, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.current) != 1 {
		return deployment.Pointers{}, nil
	}
	for _, pointers := range f.current {
		return pointers, nil
	}
	return deployment.Pointers{}, nil
}

func (f *scopedDynamicRouting) ScopePointers(scopeID string) (deployment.Pointers, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current[scopeID], nil
}

func (f *scopedDynamicRouting) Scopes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	scopes := make([]string, 0, len(f.current))
	for scopeID := range f.current {
		scopes = append(scopes, scopeID)
	}
	sort.Strings(scopes)
	return scopes
}

func (f *scopedDynamicRouting) Lookup(deploymentID string) (deployment.Result, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result, ok := f.results[deploymentID]
	return result, ok, nil
}

// dynamicMultiGateway is the multi-tenant gateway serving v2 root releases.
type dynamicMultiGateway struct {
	*multiTenantGateway
	releases map[string]*siteObjectTestRelease // by deployment ID
}

func (g *dynamicMultiGateway) FetchArtifact(request *agentv1.FetchArtifactRequest, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error {
	if g.firstID != "" && request.DeploymentId == g.firstID {
		<-g.holdFirst // keep the node busy until every command has been queued
	}
	release := g.releases[request.DeploymentId]
	if release == nil {
		return status.Error(codes.NotFound, "deployment")
	}
	artifact, present := release.artifacts[request.ArtifactId]
	if !present {
		return status.Error(codes.NotFound, "artifact")
	}
	remaining := artifact[request.Offset:]
	digest := sha256.Sum256(remaining)
	return stream.Send(&agentv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: request.Offset,
		Data: remaining, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(artifact)), EndOfArtifact: true,
	}})
}

func (g *dynamicMultiGateway) FetchSiteObjects(request *agentv1.FetchSiteObjectsRequest, stream grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse]) error {
	release := g.releases[request.DeploymentId]
	if release == nil {
		return status.Error(codes.NotFound, "deployment")
	}
	for _, digest := range request.Sha256 {
		wire, present := release.objects[digest]
		if !present {
			return status.Error(codes.NotFound, "site object")
		}
		if err := stream.Send(&agentv1.FetchSiteObjectsResponse{Chunk: &agentv1.SiteObjectChunk{
			RequestId: request.Request.RequestId, Sha256: digest, Data: wire,
			TotalSizeBytes: uint64(len(wire)), EndOfObject: true,
		}}); err != nil {
			return err
		}
	}
	return nil
}

// A dynamic routing node whose manager keeps per-scope state declares
// MULTI_TENANT_RUNTIME; with the gateway enabling it, releases of two scopes
// are queued per scope, both applied (the second apply merges both scopes),
// and heartbeats report each scope's current v2 root.
func TestDynamicRoutingMultiTenantSessionAppliesSeveralScopes(t *testing.T) {
	h := newSiteObjectHarness(t)
	scopeA, scopeB := mtScopeA, mtScopeB
	releaseA := h.dynamicRoutingReleaseFor(t, scopeA, 2, []byte(`{"cc":"a"}`))
	releaseB := h.dynamicRoutingReleaseFor(t, scopeB, 1, []byte(`{"cc":"b"}`))
	closeGatewayClientForRestart(t, h.client)

	gateway := &dynamicMultiGateway{
		multiTenantGateway: &multiTenantGateway{
			commands: []*agentv1.DeploymentCommand{releaseA.command, releaseB.command}, holdFirst: make(chan struct{}),
			events: make(chan struct{}, 1),
		},
		releases: map[string]*siteObjectTestRelease{
			releaseA.command.DeploymentId: releaseA, releaseB.command.DeploymentId: releaseB,
		},
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	config := h.client.config
	config.Capabilities = proto.Clone(config.Capabilities).(*agentv1.AgentCapabilities)
	for _, capability := range config.Capabilities.Features {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			capability.ApiVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion
		}
	}
	store, err := objectstore.Open(filepath.Join(h.root, "dynamic-multi-objects"))
	if err != nil {
		t.Fatal(err)
	}
	applier := &scopedDynamicRouting{current: map[string]deployment.Pointers{}, results: map[string]deployment.Result{}}
	client, err := New(config, &bufDialer{listener: listener}, applier, h.client.trust,
		WithSiteObjectStore(store), WithDynamicRouting(applier))
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; _ = client.Close() })

	final := func(deploymentID string) *agentv1.DeploymentStatus {
		statuses := gateway.statusesFor(deploymentID)
		if len(statuses) == 0 {
			return nil
		}
		return statuses[len(statuses)-1]
	}
	var scoped []*agentv1.ScopedConfigIdentity
	deadline := time.After(15 * time.Second)
	for scoped == nil {
		a, b := final(releaseA.command.DeploymentId), final(releaseB.command.DeploymentId)
		if a != nil && b != nil && a.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
			b.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
			gateway.mu.Lock()
			for _, heartbeat := range gateway.heartbeats {
				if len(heartbeat.ScopedConfigIdentities) == 2 && heartbeat.ScopedConfigIdentities[0].CurrentConfigIdentity != nil &&
					heartbeat.ScopedConfigIdentities[1].CurrentConfigIdentity != nil {
					scoped = heartbeat.ScopedConfigIdentities
				}
			}
			gateway.mu.Unlock()
		}
		if scoped != nil {
			break
		}
		select {
		case <-gateway.events:
		case <-deadline:
			t.Fatalf("scopes did not settle: a=%v b=%v", a, b)
		}
	}

	gateway.mu.Lock()
	hello := gateway.hello
	gateway.mu.Unlock()
	if !hasCapability(hello.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME) {
		t.Fatalf("dynamic routing hello did not declare MULTI_TENANT_RUNTIME: %+v", hello.Capabilities)
	}
	for _, release := range []*siteObjectTestRelease{releaseA, releaseB} {
		statuses := gateway.statusesFor(release.command.DeploymentId)
		if len(statuses) < 2 || statuses[1].State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED {
			t.Fatalf("%s was not queued per scope: %v", release.command.DeploymentId, statuses)
		}
		for _, value := range statuses {
			if value.GetConfigurationScopeId() != release.command.GetConfigurationScopeId() {
				t.Fatalf("%s status %s has scope %q", release.command.DeploymentId, value.State, value.GetConfigurationScopeId())
			}
		}
	}
	applier.mu.Lock()
	last := maps.Clone(applier.merged[len(applier.merged)-1])
	applier.mu.Unlock()
	want := map[string]string{scopeA: releaseA.command.ConfigVersionId, scopeB: releaseB.command.ConfigVersionId}
	if !maps.Equal(last, want) {
		t.Fatalf("last apply merged %v, want both scopes %v", last, want)
	}
	for index, release := range []*siteObjectTestRelease{releaseA, releaseB} {
		entry := scoped[index]
		rootDigest := sha256.Sum256(release.artifacts[release.command.Artifacts[0].ArtifactId])
		if entry.ConfigurationScopeId != release.command.GetConfigurationScopeId() ||
			entry.GetCurrentConfigVersionId() != release.command.ConfigVersionId ||
			fmt.Sprintf("%x", entry.CurrentConfigIdentity.ArtifactSha256) != fmt.Sprintf("%x", rootDigest) {
			t.Fatalf("scope entry %+v, want %s current %s root %x", entry, release.command.GetConfigurationScopeId(),
				release.command.ConfigVersionId, rootDigest)
		}
	}
}
