package gateway

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// validSiteObjectCommand is what Control sends a node for a dynamic routing
// release (ADR 0009 §8.3): [shared signed plaintext v2 root, the node's HPKE
// key envelope], requiring site_runtime 9.
func validSiteObjectCommand(t *testing.T) *agentv1.DeploymentCommand {
	t.Helper()
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	envelope := command.Artifacts[0]
	envelope.MediaType = siteobject.KeyMediaType
	envelope.SizeBytes = minimumHPKEArtifactBytes
	envelope.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
	envelope.RecipientKeyId = proto.String(testArtifactRecipientKeyID)
	root := &agentv1.ArtifactDescriptor{
		ArtifactId: uuid.NewString(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		SizeBytes: 512, Sha256: append(make([]byte, 31), 1), Signature: make([]byte, 64), SigningKeyId: "signing-key",
		SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		MediaType:           siteobject.RootMediaTypeV2,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}
	command.Artifacts = []*agentv1.ArtifactDescriptor{root, envelope}
	command.RequiredCapabilities = []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion},
	}
	setDeploymentConfigurationScope(t, command, uuid.NewString())
	return command
}

func TestSiteObjectDeploymentCommandContract(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	if err := gateway.validateDeploymentCommand(validSiteObjectCommand(t), testArtifactRecipientKeyID); err != nil {
		t.Fatalf("Control-shaped site object command rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*agentv1.DeploymentCommand)
	}{
		{"envelope before root", func(command *agentv1.DeploymentCommand) {
			command.Artifacts[0], command.Artifacts[1] = command.Artifacts[1], command.Artifacts[0]
		}},
		{"encrypted root", func(command *agentv1.DeploymentCommand) {
			command.Artifacts[0].EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
			command.Artifacts[0].RecipientKeyId = proto.String(testArtifactRecipientKeyID)
			command.Artifacts[0].SizeBytes = minimumHPKEArtifactBytes
		}},
		{"plaintext envelope", func(command *agentv1.DeploymentCommand) {
			command.Artifacts[1].EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
			command.Artifacts[1].RecipientKeyId = nil
		}},
		{"envelope for another node", func(command *agentv1.DeploymentCommand) {
			command.Artifacts[1].RecipientKeyId = proto.String("other-key")
		}},
		{"root alone", func(command *agentv1.DeploymentCommand) { command.Artifacts = command.Artifacts[:1] }},
		{"a third artifact", func(command *agentv1.DeploymentCommand) {
			extra := proto.Clone(command.Artifacts[1]).(*agentv1.ArtifactDescriptor)
			extra.ArtifactId = uuid.NewString()
			command.Artifacts = append(command.Artifacts, extra)
		}},
		{"site runtime 7", func(command *agentv1.DeploymentCommand) {
			command.RequiredCapabilities[len(command.RequiredCapabilities)-1].ApiVersion = 7
		}},
		{"site runtime 8", func(command *agentv1.DeploymentCommand) {
			command.RequiredCapabilities[len(command.RequiredCapabilities)-1].ApiVersion = 8
		}},
		{"v1 root", func(command *agentv1.DeploymentCommand) {
			command.Artifacts[0].MediaType = "application/vnd.cdnca.edge-site-root+json;version=1"
		}},
		{"v2 bundle with site runtime 9", func(command *agentv1.DeploymentCommand) {
			command.Artifacts = command.Artifacts[1:]
			command.Artifacts[0].MediaType = "application/vnd.cdnca.edge-site-runtime-bundle+json;version=2"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := validSiteObjectCommand(t)
			test.change(command)
			if err := gateway.validateDeploymentCommand(command, testArtifactRecipientKeyID); err == nil {
				t.Fatal("invalid site object command accepted")
			}
		})
	}
}

// A node running a site object release reports the shared root's digest as
// its active identity; its envelope's digest is not a running configuration.
func TestSiteObjectActiveIdentityNamesTheRoot(t *testing.T) {
	command := validSiteObjectCommand(t)
	command.Artifacts[1].Sha256 = append(make([]byte, 31), 2)
	for _, test := range []struct {
		digest []byte
		ok     bool
	}{{command.Artifacts[0].Sha256, true}, {command.Artifacts[1].Sha256, false}} {
		status := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
		status.ActiveConfigIdentityCapability = testActiveIdentityCapability()
		status.ActiveConfigIdentity = testActiveIdentity(command.ConfigVersionId, test.digest)
		if err := validateDeploymentStatusActiveIdentityCommandBinding(status, command); (err == nil) != test.ok {
			t.Fatalf("identity %x: %v, want accepted=%v", test.digest, err, test.ok)
		}
	}
}

// siteObjectControl serves FetchSiteObjects from a fixed chunk script and
// records what the Gateway forwarded.
type siteObjectControl struct {
	*scriptedControl
	chunks   []*agentv1.SiteObjectChunk
	received *controlv1.FetchSiteObjectsRequest
}

func (c *siteObjectControl) FetchSiteObjects(_ context.Context, request *controlv1.FetchSiteObjectsRequest) (SiteObjectStream, error) {
	c.received = proto.Clone(request).(*controlv1.FetchSiteObjectsRequest)
	return &scriptedSiteObjectStream{chunks: c.chunks}, nil
}

type scriptedSiteObjectStream struct{ chunks []*agentv1.SiteObjectChunk }

func (s *scriptedSiteObjectStream) Recv() (*controlv1.FetchSiteObjectsResponse, error) {
	if len(s.chunks) == 0 {
		return nil, io.EOF
	}
	chunk := s.chunks[0]
	s.chunks = s.chunks[1:]
	return &controlv1.FetchSiteObjectsResponse{Chunk: chunk}, nil
}

type capturingSiteObjectServerStream struct {
	ctx  context.Context
	sent []*agentv1.FetchSiteObjectsResponse
}

func (s *capturingSiteObjectServerStream) Context() context.Context { return s.ctx }
func (s *capturingSiteObjectServerStream) Send(response *agentv1.FetchSiteObjectsResponse) error {
	s.sent = append(s.sent, response)
	return nil
}
func (*capturingSiteObjectServerStream) SetHeader(metadata.MD) error  { return nil }
func (*capturingSiteObjectServerStream) SendHeader(metadata.MD) error { return nil }
func (*capturingSiteObjectServerStream) SetTrailer(metadata.MD)       {}
func (*capturingSiteObjectServerStream) SendMsg(any) error            { return nil }
func (*capturingSiteObjectServerStream) RecvMsg(any) error            { return io.EOF }

func siteObjectRequestForTest() *agentv1.FetchSiteObjectsRequest {
	return &agentv1.FetchSiteObjectsRequest{
		Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		EventId: uuid.NewString(), DeploymentId: uuid.NewString(), Attempt: 1,
		RootSha256: strings.Repeat("0", 63) + "1",
		Sha256:     []string{strings.Repeat("a", 64), strings.Repeat("b", 64)},
	}
}

func siteObjectChunks(request *agentv1.FetchSiteObjectsRequest) []*agentv1.SiteObjectChunk {
	return []*agentv1.SiteObjectChunk{
		{RequestId: request.Request.RequestId, Sha256: request.Sha256[0], Offset: 0, Data: []byte("first-"), TotalSizeBytes: 11},
		{RequestId: request.Request.RequestId, Sha256: request.Sha256[0], Offset: 6, Data: []byte("half"), TotalSizeBytes: 11},
		{RequestId: request.Request.RequestId, Sha256: request.Sha256[0], Offset: 10, Data: []byte("!"), TotalSizeBytes: 11, EndOfObject: true},
		{RequestId: request.Request.RequestId, Sha256: request.Sha256[1], Offset: 0, Data: []byte("second"), TotalSizeBytes: 6, EndOfObject: true},
	}
}

func siteObjectGatewayForTest(t *testing.T, chunks func(*agentv1.FetchSiteObjectsRequest) []*agentv1.SiteObjectChunk,
	request *agentv1.FetchSiteObjectsRequest) (*Gateway, *siteObjectControl) {
	t.Helper()
	state := allowedAuthorization(time.Hour)
	state.deploymentsAllowed = true
	control := &siteObjectControl{scriptedControl: &scriptedControl{fakeControl: defaultFakeControl(),
		states: []authorizationState{state}}, chunks: chunks(request)}
	return newUnitGateway(t, control, nil), control
}

// The Gateway forwards the node's request with its authenticated node ID
// and streams the objects back unchanged.
func TestFetchSiteObjectsForwardsAuthenticatedRequestAndChunks(t *testing.T) {
	request := siteObjectRequestForTest()
	gateway, control := siteObjectGatewayForTest(t, siteObjectChunks, request)
	stream := &capturingSiteObjectServerStream{ctx: authenticatedTestContext(t)}
	if err := gateway.FetchSiteObjects(request, stream); err != nil {
		t.Fatal(err)
	}
	if control.received == nil || control.received.NodeId != testNodeID || control.received.RootSha256 != request.RootSha256 ||
		!slices.Equal(control.received.Sha256, request.Sha256) || control.received.DeploymentId != request.DeploymentId ||
		control.received.GatewayInstanceId == "" {
		t.Fatalf("forwarded request = %+v", control.received)
	}
	if len(stream.sent) != 4 || string(stream.sent[3].Chunk.Data) != "second" {
		t.Fatalf("forwarded %d chunks", len(stream.sent))
	}
}

func TestFetchSiteObjectsRejectsInvalidRequestsAndChunks(t *testing.T) {
	for name, change := range map[string]func(*agentv1.FetchSiteObjectsRequest){
		"uppercase digest": func(request *agentv1.FetchSiteObjectsRequest) { request.Sha256[0] = strings.Repeat("A", 64) },
		"duplicate digest": func(request *agentv1.FetchSiteObjectsRequest) { request.Sha256[1] = request.Sha256[0] },
		"no digests":       func(request *agentv1.FetchSiteObjectsRequest) { request.Sha256 = nil },
		"bad root":         func(request *agentv1.FetchSiteObjectsRequest) { request.RootSha256 = "00" },
		"too many": func(request *agentv1.FetchSiteObjectsRequest) {
			request.Sha256 = nil
			for index := 0; index <= maxSiteObjectsPerRequest; index++ {
				request.Sha256 = append(request.Sha256, fmt.Sprintf("%064x", index))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := siteObjectRequestForTest()
			change(request)
			gateway, control := siteObjectGatewayForTest(t, siteObjectChunks, siteObjectRequestForTest())
			err := gateway.FetchSiteObjects(request, &capturingSiteObjectServerStream{ctx: authenticatedTestContext(t)})
			if status.Code(err) != codes.InvalidArgument || control.received != nil {
				t.Fatalf("code %v, forwarded %v", status.Code(err), control.received != nil)
			}
		})
	}
	for name, chunks := range map[string]func(*agentv1.FetchSiteObjectsRequest) []*agentv1.SiteObjectChunk{
		"objects out of order": func(request *agentv1.FetchSiteObjectsRequest) []*agentv1.SiteObjectChunk {
			all := siteObjectChunks(request)
			return []*agentv1.SiteObjectChunk{all[3], all[0], all[1], all[2]}
		},
		"stream ends early": func(request *agentv1.FetchSiteObjectsRequest) []*agentv1.SiteObjectChunk {
			return siteObjectChunks(request)[:3]
		},
		"offset gap": func(request *agentv1.FetchSiteObjectsRequest) []*agentv1.SiteObjectChunk {
			all := siteObjectChunks(request)
			return append([]*agentv1.SiteObjectChunk{all[0]}, all[2:]...)
		},
		"unrequested object": func(request *agentv1.FetchSiteObjectsRequest) []*agentv1.SiteObjectChunk {
			all := siteObjectChunks(request)
			all[3].Sha256 = strings.Repeat("c", 64)
			return all
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := siteObjectRequestForTest()
			gateway, _ := siteObjectGatewayForTest(t, chunks, request)
			if err := gateway.FetchSiteObjects(request, &capturingSiteObjectServerStream{ctx: authenticatedTestContext(t)}); status.Code(err) != codes.Internal {
				t.Fatalf("code %v, want Internal", status.Code(err))
			}
		})
	}
}
