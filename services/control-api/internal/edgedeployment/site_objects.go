package edgedeployment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"github.com/google/uuid"
)

// A site runtime v8 release (ADR 0009 §8.3) is one signed plaintext root,
// shared by every target node, plus one HPKE key envelope per node. Its
// canonical snapshot is still the whole v2 document; the root and every
// rollout of the release require the document's capabilities with
// site_runtime raised to v8.
const (
	siteObjectKeyMediaType = siteobject.KeyMediaType
	// siteObjectRootMediaTypeV2 is the dynamic routing (site_runtime 9) root:
	// same envelopes, site objects activated without a bundle.
	siteObjectRootMediaTypeV2 = siteobject.RootMediaTypeV2
)

func isSiteObjectRootMediaType(mediaType string) bool {
	return mediaType == siteObjectRootMediaTypeV2
}

// DynamicRoutingDeliveryCapabilities is what a dynamic routing (v2 root)
// release of a v2 document requiring document requires: document with
// site_runtime raised to 9, in name order.
func DynamicRoutingDeliveryCapabilities(document []*agentv1.Capability) ([]*agentv1.Capability, error) {
	return siteObjectDeliveryCapabilitiesAt(document, edgeconfig.DynamicRoutingSiteRuntimeVersion)
}

func siteObjectDeliveryCapabilitiesAt(document []*agentv1.Capability, version uint32) ([]*agentv1.Capability, error) {
	result := cloneCapabilities(document)
	found := false
	for _, capability := range result {
		if capability == nil {
			return nil, ErrInvalidInput
		}
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			if capability.ApiVersion < 2 || capability.ApiVersion > edgeconfig.MaxDocumentSiteRuntimeVersion {
				return nil, ErrInvalidInput
			}
			capability.ApiVersion, found = version, true
		}
	}
	if !found {
		return nil, ErrInvalidInput
	}
	return result, nil
}

func isSiteObjectArtifact(artifact ArtifactInput) bool {
	return isSiteObjectRootMediaType(artifact.MediaType) || artifact.MediaType == siteObjectKeyMediaType
}

// validateSiteObjectConfigBinding checks a dynamic routing artifact set: one
// signed plaintext root naming the canonical v2 document, and one HPKE key
// envelope per recipient. It reports false when artifacts is not such a set.
func validateSiteObjectConfigBinding(
	expectedScopeID, expectedConfigID uuid.UUID,
	expectedCanonical []byte,
	artifacts []ArtifactInput,
	requiredCapabilities []*agentv1.Capability,
	requireCapabilities bool,
) (bool, error) {
	var root *ArtifactInput
	recipients := map[string]struct{}{}
	siteObjects := 0
	for index := range artifacts {
		artifact := artifacts[index]
		if !isSiteObjectArtifact(artifact) {
			continue
		}
		siteObjects++
		if artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION ||
			artifact.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE {
			return true, fmt.Errorf("%w: site object artifact set is invalid", ErrInvalidInput)
		}
		switch artifact.MediaType {
		case siteObjectRootMediaTypeV2:
			if root != nil || artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
				artifact.RecipientKeyID != nil {
				return true, fmt.Errorf("%w: site object root artifact is invalid", ErrInvalidInput)
			}
			root = &artifacts[index]
		case siteObjectKeyMediaType:
			if artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
				artifact.RecipientKeyID == nil || !recipientKeyPattern.MatchString(*artifact.RecipientKeyID) {
				return true, fmt.Errorf("%w: site object key artifact is invalid", ErrInvalidInput)
			}
			if _, duplicate := recipients[*artifact.RecipientKeyID]; duplicate {
				return true, fmt.Errorf("%w: site object key recipient is duplicated", ErrInvalidInput)
			}
			recipients[*artifact.RecipientKeyID] = struct{}{}
		}
	}
	if siteObjects == 0 {
		return false, nil
	}
	if root == nil || len(recipients) == 0 || siteObjects != len(artifacts) {
		return true, fmt.Errorf("%w: site object artifact set is incomplete", ErrInvalidInput)
	}
	var scopeID, configID, documentSHA256 string
	var required []siteobject.Capability
	deliver := DynamicRoutingDeliveryCapabilities
	parsed, err := siteobject.ParseRootV2(root.WireBytes)
	if err != nil {
		return true, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	scopeID, configID, documentSHA256, required = parsed.ConfigurationScopeID, parsed.ConfigVersionID, parsed.DocumentSHA256, parsed.RequiredCapabilities
	documentCapabilities, err := siteRuntimeV2DocumentCapabilities(expectedCanonical)
	if err != nil {
		return true, err
	}
	digest := sha256.Sum256(expectedCanonical)
	if scopeID != expectedScopeID.String() || configID != expectedConfigID.String() ||
		documentSHA256 != hex.EncodeToString(digest[:]) {
		return true, fmt.Errorf("%w: site object root does not match its configuration", ErrInvalidInput)
	}
	delivery, err := deliver(documentCapabilities)
	if err != nil {
		return true, err
	}
	rootCapabilities := make([]*agentv1.Capability, len(required))
	for index, capability := range required {
		name, known := siteruntimecap.Name(capability.Name)
		if !known {
			return true, fmt.Errorf("%w: site object root capability is unknown", ErrInvalidInput)
		}
		rootCapabilities[index] = &agentv1.Capability{Name: name, ApiVersion: capability.APIVersion}
	}
	if !equalSiteRuntimeV2Capabilities(rootCapabilities, delivery) {
		return true, fmt.Errorf("%w: site object root capabilities do not match the document", ErrInvalidInput)
	}
	if requireCapabilities && !equalSiteRuntimeV2Capabilities(delivery, requiredCapabilities) {
		return true, fmt.Errorf("%w: site object capabilities do not match the rollout", ErrInvalidInput)
	}
	return true, nil
}

// siteRuntimeV2DocumentCapabilities decodes the canonical v2 document's
// required capabilities.
func siteRuntimeV2DocumentCapabilities(canonical []byte) ([]*agentv1.Capability, error) {
	if len(canonical) == 0 || edgeconfig.RejectDuplicateJSONKeys(canonical) != nil {
		return nil, fmt.Errorf("%w: site runtime v2 canonical document is invalid", ErrInvalidInput)
	}
	var document siteRuntimeV2BundleDocument
	if err := json.Unmarshal(canonical, &document); err != nil || document.Schema != "cdnca.edge.site-runtime/v2" {
		return nil, fmt.Errorf("%w: site runtime v2 canonical document is invalid", ErrInvalidInput)
	}
	capabilities, err := decodeSiteRuntimeV2Capabilities(document.RequiredCapabilities)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return capabilities, nil
}
