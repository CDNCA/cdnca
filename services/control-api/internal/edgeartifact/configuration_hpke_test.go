package edgeartifact

import (
	"bytes"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestDescriptorFromStorageAcceptsHPKEConfigurationRecipient(t *testing.T) {
	recipient := "x25519:" + string(bytes.Repeat([]byte{'a'}, 64))
	descriptor, err := descriptorFromStorage(storedDescriptor{
		id: uuid.New(), ordinal: 1, configOrdinal: 1, kind: "configuration", sizeBytes: 80,
		sha256: make([]byte, 32), signature: make([]byte, 64), signingKeyID: "configuration-key",
		signingKeyAlgorithm: "ed25519", signatureAlgorithm: "ed25519", compression: "none",
		mediaType:  "application/vnd.cdnca.edge-site-runtime-bundle+json;version=2",
		encryption: "hpke_x25519_hkdf_sha256_aes_256_gcm", recipientKeyID: &recipient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		descriptor.GetRecipientKeyId() != recipient {
		t.Fatalf("descriptor = %+v", descriptor)
	}
}
