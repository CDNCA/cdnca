package gateway

import (
	"encoding/hex"
	"errors"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

const OriginAuthArtifactMediaType = "application/vnd.cdnca.edge-origin-auth-snapshot+hpke;version=1"

var ErrInvalidOriginAuthArtifact = errors.New("invalid origin authentication artifact descriptor")

func ValidateOriginAuthArtifactDescriptor(descriptor *agentv1.ArtifactDescriptor, maximumBytes uint64) error {
	if descriptor == nil || maximumBytes == 0 || descriptor.SizeBytes < minimumHPKEArtifactBytes || descriptor.SizeBytes > maximumBytes ||
		descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE || descriptor.MediaType != OriginAuthArtifactMediaType ||
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		len(descriptor.Sha256) != 32 || len(descriptor.Signature) != 64 || !originAuthUUID(descriptor.ArtifactId) ||
		!originAuthIdentifier(descriptor.SigningKeyId) || descriptor.RecipientKeyId == nil || !originAuthRecipientID(descriptor.GetRecipientKeyId()) {
		return ErrInvalidOriginAuthArtifact
	}
	return nil
}

func originAuthUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func originAuthRecipientID(value string) bool {
	if !strings.HasPrefix(value, "x25519:") || len(value) != len("x25519:")+64 {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "x25519:"))
	return err == nil && len(raw) == 32
}

func originAuthIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			index > 0 && strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}
