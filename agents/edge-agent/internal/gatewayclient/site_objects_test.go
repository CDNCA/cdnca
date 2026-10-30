package gatewayclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func siteObjectAgentFeatures() []*agentv1.Capability {
	return []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.MaxSiteRuntimeVersion},
	}
}

// siteObjectRelease is what control publishes for one deployment to one node.
type siteObjectTestRelease struct {
	command *agentv1.DeploymentCommand
	// artifacts by artifact ID; objects (wire) by plaintext digest.
	artifacts map[string][]byte
	objects   map[string][]byte
	kinds     map[string]siteobject.ObjectKind
}

type siteObjectHarness struct {
	*siteRuntimeRouteHarness
	store      *objectstore.Store
	contentKey []byte
}

func newSiteObjectHarness(t *testing.T) *siteObjectHarness {
	t.Helper()
	base := newSiteRuntimeRouteHarnessWithCapabilities(t, siteObjectAgentFeatures())
	store, err := objectstore.Open(filepath.Join(base.root, "deployment-objects"))
	if err != nil {
		t.Fatal(err)
	}
	closeGatewayClientForRestart(t, base.client)
	client, err := New(base.client.config, &failingDialer{}, base.manager, base.client.trust, WithSiteObjectStore(store))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	base.client = client
	contentKey := make([]byte, siteobject.ContentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	return &siteObjectHarness{siteRuntimeRouteHarness: base, store: store, contentKey: contentKey}
}

func agentCapabilityName(t testing.TB, name string) agentv1.CapabilityName {
	t.Helper()
	for _, candidate := range []agentv1.CapabilityName{
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, agentv1.CapabilityName_CAPABILITY_NAME_IPV4,
		agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME,
	} {
		if mapped, _ := siteRuntimeCapabilityName(candidate); string(mapped) == name {
			return candidate
		}
	}
	t.Fatalf("no agent capability for %s", name)
	return 0
}

// siteObjectGateway serves one release's artifacts and objects and records
// which objects were requested.
type siteObjectGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	mu        sync.Mutex
	release   *siteObjectTestRelease
	requested []string
	requests  int
	// tamper replaces an object's wire; dropAfter ends a stream early after
	// that many objects (once).
	tamper    map[string][]byte
	dropAfter int
	chunk     int
}

func (gateway *siteObjectGateway) FetchArtifact(request *agentv1.FetchArtifactRequest, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error {
	gateway.mu.Lock()
	release := gateway.release
	gateway.mu.Unlock()
	wire, present := release.artifacts[request.ArtifactId]
	if !present || request.DeploymentId != release.command.DeploymentId {
		return status.Error(codes.NotFound, "artifact")
	}
	step := uint64(512)
	if gateway.chunk > 0 {
		step = uint64(gateway.chunk)
	}
	for offset := request.Offset; offset < uint64(len(wire)); {
		end := min(offset+step, uint64(len(wire)))
		digest := sha256.Sum256(wire[offset:end])
		if err := stream.Send(&agentv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
			RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: offset, Data: wire[offset:end],
			ChunkSha256: digest[:], TotalSizeBytes: uint64(len(wire)), EndOfArtifact: end == uint64(len(wire)),
		}}); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (gateway *siteObjectGateway) FetchSiteObjects(request *agentv1.FetchSiteObjectsRequest, stream grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse]) error {
	gateway.mu.Lock()
	release := gateway.release
	gateway.requests++
	gateway.requested = append(gateway.requested, request.Sha256...)
	dropAfter := gateway.dropAfter
	gateway.dropAfter = 0
	chunkSize := gateway.chunk
	gateway.mu.Unlock()
	if chunkSize == 0 {
		chunkSize = 700
	}
	rootDigest := sha256.Sum256(release.artifacts[release.command.Artifacts[0].ArtifactId])
	if request.DeploymentId != release.command.DeploymentId || request.RootSha256 != fmt.Sprintf("%x", rootDigest) ||
		len(request.Sha256) == 0 || len(request.Sha256) > maxSiteObjectsPerRequest {
		return status.Error(codes.PermissionDenied, "site objects")
	}
	for index, digest := range request.Sha256 {
		if dropAfter > 0 && index == dropAfter {
			return status.Error(codes.Unavailable, "injected site object stream interruption")
		}
		wire, present := release.objects[digest]
		if replacement, tampered := gateway.tamper[digest]; tampered {
			wire = replacement
		}
		if !present {
			return status.Error(codes.NotFound, "site object")
		}
		for offset := 0; offset < len(wire); {
			end := min(offset+chunkSize, len(wire))
			if err := stream.Send(&agentv1.FetchSiteObjectsResponse{Chunk: &agentv1.SiteObjectChunk{
				RequestId: request.Request.RequestId, Sha256: digest, Offset: uint64(offset), Data: wire[offset:end],
				TotalSizeBytes: uint64(len(wire)), EndOfObject: end == len(wire),
			}}); err != nil {
				return err
			}
			offset = end
		}
	}
	return nil
}

func (gateway *siteObjectGateway) take() []string {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	requested := gateway.requested
	gateway.requested = nil
	return requested
}

func newSiteObjectGatewayClient(t *testing.T, gateway *siteObjectGateway) agentv1.AgentGatewayServiceClient {
	t.Helper()
	listener := bufconnListen(t)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection.Client()
}

func executeSiteObjectRelease(t *testing.T, client *Client, gateway agentv1.AgentGatewayServiceClient, command *agentv1.DeploymentCommand) *agentv1.DeploymentStatus {
	t.Helper()
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; ; attempt++ {
		err := client.executeRecord(t.Context(), gateway, record.RecordKey, 1<<20)
		if err == nil {
			break
		}
		if attempt == 3 {
			t.Fatalf("executeRecord: %v", err)
		}
	}
	record, err = client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(record)
	if err != nil || !record.ExecutionDone || len(statuses) == 0 {
		t.Fatalf("incomplete execution: %+v %v", record, err)
	}
	return statuses[len(statuses)-1]
}
