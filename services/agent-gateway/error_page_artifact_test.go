package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/protobuf/proto"
)

func TestSITE13GatewayValidatesErrorPageArtifactContract(t *testing.T) {
	descriptor := site13GatewayDescriptor()
	if err := ValidateErrorPageArtifactDescriptor(descriptor, 1<<20); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentv1.ArtifactDescriptor){
		"kind": func(value *agentv1.ArtifactDescriptor) {
			value.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
		},
		"media": func(value *agentv1.ArtifactDescriptor) { value.MediaType = "application/json" },
		"compression": func(value *agentv1.ArtifactDescriptor) {
			value.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD
		},
		"encryption": func(value *agentv1.ArtifactDescriptor) {
			value.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
		},
		"recipient": func(value *agentv1.ArtifactDescriptor) { value.RecipientKeyId = proto.String("forbidden") },
		"signature": func(value *agentv1.ArtifactDescriptor) { value.Signature = nil },
		"algorithm": func(value *agentv1.ArtifactDescriptor) {
			value.SignatureAlgorithm = agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256
		},
		"oversize": func(value *agentv1.ArtifactDescriptor) { value.SizeBytes = 1<<20 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			value := proto.Clone(descriptor).(*agentv1.ArtifactDescriptor)
			mutate(value)
			if err := ValidateErrorPageArtifactDescriptor(value, 1<<20); err == nil {
				t.Fatal("invalid error-page artifact descriptor was accepted")
			}
		})
	}
}

func TestSITE13GatewayFetchCarriesErrorPageBytesUnchanged(t *testing.T) {
	wire := []byte(`{"schema":"cdnca.edge.error-page-snapshot/v1"}`)
	digest := sha256.Sum256(wire)
	request := validArtifactRequest()
	chunk := &agentv1.ArtifactChunk{RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: 0,
		Data: wire, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(wire)), EndOfArtifact: true}
	state := allowedAuthorization(time.Hour)
	state.deploymentsAllowed = true
	control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{state}, artifact: func(context.Context) ArtifactStream {
		return &site13ArtifactStream{response: &controlv1.FetchArtifactResponse{Chunk: chunk}}
	}}
	gateway := newUnitGateway(t, control, nil)
	stream := &capturingArtifactServerStream{ctx: authenticatedTestContext(t)}
	if err := gateway.FetchArtifact(request, stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.sent) != 1 || stream.sent[0].Chunk != chunk || !bytes.Equal(stream.sent[0].Chunk.Data, wire) || !bytes.Equal(stream.sent[0].Chunk.ChunkSha256, digest[:]) {
		t.Fatal("Gateway changed error-page artifact bytes or metadata")
	}
}

func site13GatewayDescriptor() *agentv1.ArtifactDescriptor {
	wire := []byte("signed error page bundle")
	digest := sha256.Sum256(wire)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	return &agentv1.ArtifactDescriptor{
		ArtifactId: "01990000-0000-7000-8000-000000000001", Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		SizeBytes: uint64(len(wire)), Sha256: digest[:], Signature: ed25519.Sign(private, wire), SigningKeyId: "error-page-signing-v1",
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: ErrorPageArtifactMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}
}

type site13ArtifactStream struct {
	response *controlv1.FetchArtifactResponse
}

func (stream *site13ArtifactStream) Recv() (*controlv1.FetchArtifactResponse, error) {
	if stream.response == nil {
		return nil, io.EOF
	}
	response := stream.response
	stream.response = nil
	return response, nil
}
