package gateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"regexp"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

const ErrorPageArtifactMediaType = "application/vnd.cdnca.edge-error-page-snapshot+json;version=1"

var errorPageArtifactIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func ValidateErrorPageArtifactDescriptor(descriptor *agentv1.ArtifactDescriptor, maximumBytes uint64) error {
	if descriptor == nil || maximumBytes == 0 {
		return fmt.Errorf("error page artifact descriptor is required")
	}
	artifactID, err := uuid.Parse(descriptor.ArtifactId)
	if err != nil || artifactID == uuid.Nil || artifactID.String() != descriptor.ArtifactId ||
		descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || descriptor.MediaType != ErrorPageArtifactMediaType ||
		descriptor.SizeBytes == 0 || descriptor.SizeBytes > maximumBytes || len(descriptor.Sha256) != sha256.Size ||
		len(descriptor.Signature) != ed25519.SignatureSize || !errorPageArtifactIdentifier.MatchString(descriptor.SigningKeyId) ||
		descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
		descriptor.RecipientKeyId != nil {
		return fmt.Errorf("error page artifact descriptor contract is invalid")
	}
	return nil
}
