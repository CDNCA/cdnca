package controlinternal

import (
	"context"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeSiteObjectStore struct {
	last   *controlv1.FetchSiteObjectsRequest
	chunks []*agentv1.SiteObjectChunk
	err    error
}

func (f *fakeSiteObjectStore) FetchSiteObjects(_ context.Context, request *controlv1.FetchSiteObjectsRequest,
	send edgeartifact.SiteObjectChunkSink) error {
	f.last = request
	for _, chunk := range f.chunks {
		if err := send(&controlv1.FetchSiteObjectsResponse{Chunk: chunk}); err != nil {
			return err
		}
	}
	return f.err
}

type fakeSiteObjectStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*controlv1.FetchSiteObjectsResponse
}

func (f *fakeSiteObjectStream) Context() context.Context { return f.ctx }
func (f *fakeSiteObjectStream) Send(response *controlv1.FetchSiteObjectsResponse) error {
	f.sent = append(f.sent, response)
	return nil
}

func siteObjectsRequestForTest() *controlv1.FetchSiteObjectsRequest {
	return &controlv1.FetchSiteObjectsRequest{
		Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		EventId: uuid.NewString(), NodeId: uuid.NewString(), DeploymentId: uuid.NewString(), Attempt: 1,
		RootSha256: strings.Repeat("1", 64), Sha256: []string{strings.Repeat("a", 64)}, GatewayInstanceId: uuid.NewString(),
	}
}

// Production wraps the artifact store (ACME overlay composite), so the site
// object store is configured explicitly and still serves; without one the
// RPC is unimplemented.
func TestFetchSiteObjectsUsesConfiguredStoreAndChecksChunks(t *testing.T) {
	request := siteObjectsRequestForTest()
	objects := &fakeSiteObjectStore{chunks: []*agentv1.SiteObjectChunk{{RequestId: request.Request.RequestId,
		Sha256: request.Sha256[0], Data: []byte("wire"), TotalSizeBytes: 4, EndOfObject: true}}}
	service, err := NewService(&fakeIdentityService{}, &fakeArtifactStore{}, Config{SiteObjects: objects})
	if err != nil {
		t.Fatal(err)
	}
	stream := &fakeSiteObjectStream{ctx: gatewayContext(t)}
	if err := service.FetchSiteObjects(request, stream); err != nil || len(stream.sent) != 1 || objects.last == nil {
		t.Fatalf("serve = %v, sent %d", err, len(stream.sent))
	}

	objects.chunks[0].Sha256 = strings.Repeat("b", 64)
	if err := service.FetchSiteObjects(siteObjectsRequestForTest(), &fakeSiteObjectStream{ctx: gatewayContext(t)}); status.Code(err) != codes.Internal {
		t.Fatalf("unrequested object chunk: %v", err)
	}
	objects.chunks, objects.err = nil, edgeartifact.ErrSiteObjectNotMember
	if err := service.FetchSiteObjects(siteObjectsRequestForTest(), &fakeSiteObjectStream{ctx: gatewayContext(t)}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-member: %v", err)
	}
	unconfigured, err := NewService(&fakeIdentityService{}, &fakeArtifactStore{}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unconfigured.FetchSiteObjects(siteObjectsRequestForTest(), &fakeSiteObjectStream{ctx: gatewayContext(t)}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("unconfigured: %v", err)
	}
}
