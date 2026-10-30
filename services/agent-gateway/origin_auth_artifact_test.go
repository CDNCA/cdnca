package gateway

import (
	"crypto/sha256"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestSITE09GatewayValidatesOriginAuthSecretArtifactContract(t *testing.T) {
	recipient := "x25519:" + strings.Repeat("0", 64)
	descriptor := &agentv1.ArtifactDescriptor{
		ArtifactId: "01990000-0000-7000-8000-000000000001", Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE,
		SizeBytes: 512, Sha256: make([]byte, sha256.Size), Signature: make([]byte, 64), SigningKeyId: "origin-auth-signing-v1",
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: OriginAuthArtifactMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM,
		RecipientKeyId:      &recipient,
	}
	if err := ValidateOriginAuthArtifactDescriptor(descriptor, 1<<20); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.ArtifactDescriptor){
		"kind":  func(value *agentv1.ArtifactDescriptor) { value.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION },
		"media": func(value *agentv1.ArtifactDescriptor) { value.MediaType = "application/json" },
		"compression": func(value *agentv1.ArtifactDescriptor) {
			value.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD
		},
		"encryption": func(value *agentv1.ArtifactDescriptor) {
			value.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
		},
		"recipient": func(value *agentv1.ArtifactDescriptor) { value.RecipientKeyId = nil },
		"signature": func(value *agentv1.ArtifactDescriptor) { value.Signature = value.Signature[:63] },
		"oversize":  func(value *agentv1.ArtifactDescriptor) { value.SizeBytes = 1<<20 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proto.Clone(descriptor).(*agentv1.ArtifactDescriptor)
			mutate(candidate)
			if err := ValidateOriginAuthArtifactDescriptor(candidate, 1<<20); err == nil {
				t.Fatal("invalid origin-auth descriptor was accepted")
			}
		})
	}
}
