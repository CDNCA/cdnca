package edgedeployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var (
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	recipientKeyPattern = regexp.MustCompile(`^x25519:[0-9a-f]{64}$`)
)

const (
	// maxConfigSnapshotBytes is the canonical document bound nodes accept;
	// a v8 release never sends it whole.
	maxConfigSnapshotBytes    = edgeconfig.MaxSiteRuntimeDocumentBytes
	maxArtifactWireBytes      = 4 << 20
	maxConfigArtifactBytes    = 16 << 20
	maxConfigArtifacts        = 128
	maxRequiredCapabilities   = 64
	maxDeploymentCommandBytes = 1 << 20
	// siteRuntimeV2MediaType is the retired whole site runtime bundle; such
	// artifacts are refused (site objects only).
	siteRuntimeV2MediaType = "application/vnd.cdnca.edge-site-runtime-bundle+json;version=2"
)

type siteRuntimeV2BundleDocument struct {
	Schema               string `json:"schema"`
	ConfigurationScopeID string `json:"configuration_scope_id"`
	SourceRevision       uint64 `json:"source_revision"`
	ConfigVersionID      string `json:"config_version_id"`
	RequiredCapabilities []struct {
		Name       string `json:"name"`
		APIVersion uint32 `json:"api_version"`
	} `json:"required_capabilities"`
}

type normalizedConfigRequest struct {
	ConfigurationScopeID uuid.UUID
	CanonicalSnapshot    []byte
	GeneratorName        string
	GeneratorVersion     string
	Artifacts            []ArtifactInput
	IdempotencyKey       string
	Digest               [32]byte
}

type configDigestArtifact struct {
	ID                  string  `json:"id"`
	Kind                int32   `json:"kind"`
	WireBytes           []byte  `json:"wire_bytes"`
	SizeBytes           uint64  `json:"size_bytes"`
	SHA256              []byte  `json:"sha256"`
	Signature           []byte  `json:"signature"`
	SigningKeyID        string  `json:"signing_key_id"`
	SigningPublicKey    []byte  `json:"signing_public_key"`
	SignatureAlgorithm  int32   `json:"signature_algorithm"`
	Compression         int32   `json:"compression"`
	MediaType           string  `json:"media_type"`
	EncryptionAlgorithm int32   `json:"encryption_algorithm"`
	RecipientKeyID      *string `json:"recipient_key_id,omitempty"`
}

func normalizeConfigRequest(request PersistConfigRequest) (normalizedConfigRequest, error) {
	if request.ConfigurationScopeID == uuid.Nil || len(request.CanonicalSnapshot) == 0 ||
		len(request.CanonicalSnapshot) > maxConfigSnapshotBytes ||
		!validLabel(request.GeneratorName) || !validLabel(request.GeneratorVersion) ||
		!validIdempotencyKey(request.IdempotencyKey) || len(request.Artifacts) == 0 || len(request.Artifacts) > maxConfigArtifacts {
		return normalizedConfigRequest{}, ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(request.Artifacts))
	digestArtifacts := make([]configDigestArtifact, 0, len(request.Artifacts))
	artifacts := make([]ArtifactInput, len(request.Artifacts))
	totalArtifactBytes := 0
	for index, input := range request.Artifacts {
		artifact, err := validateArtifact(input)
		if err != nil {
			return normalizedConfigRequest{}, fmt.Errorf("%w: artifact %d: %v", ErrInvalidInput, index, err)
		}
		if _, exists := seen[artifact.ID]; exists {
			return normalizedConfigRequest{}, fmt.Errorf("%w: duplicate artifact ID", ErrInvalidInput)
		}
		seen[artifact.ID] = struct{}{}
		totalArtifactBytes += len(artifact.WireBytes)
		if totalArtifactBytes > maxConfigArtifactBytes {
			return normalizedConfigRequest{}, fmt.Errorf("%w: artifact bytes exceed limit", ErrInvalidInput)
		}
		artifacts[index] = artifact
		digestArtifacts = append(digestArtifacts, configDigestArtifact{
			ID: artifact.ID.String(), Kind: int32(artifact.Kind), WireBytes: artifact.WireBytes,
			SizeBytes: artifact.SizeBytes, SHA256: artifact.SHA256, Signature: artifact.Signature,
			SigningKeyID: artifact.SigningKeyID, SigningPublicKey: artifact.SigningPublicKey,
			SignatureAlgorithm: int32(artifact.SignatureAlgorithm), Compression: int32(artifact.Compression),
			MediaType: artifact.MediaType, EncryptionAlgorithm: int32(artifact.EncryptionAlgorithm),
			RecipientKeyID: artifact.RecipientKeyID,
		})
	}
	encoded, err := json.Marshal(struct {
		ScopeID          string                 `json:"scope_id"`
		Snapshot         []byte                 `json:"snapshot"`
		GeneratorName    string                 `json:"generator_name"`
		GeneratorVersion string                 `json:"generator_version"`
		Artifacts        []configDigestArtifact `json:"artifacts"`
	}{request.ConfigurationScopeID.String(), request.CanonicalSnapshot, request.GeneratorName, request.GeneratorVersion, digestArtifacts})
	if err != nil {
		return normalizedConfigRequest{}, fmt.Errorf("encode config request digest: %w", err)
	}
	return normalizedConfigRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		CanonicalSnapshot:    bytes.Clone(request.CanonicalSnapshot),
		GeneratorName:        request.GeneratorName,
		GeneratorVersion:     request.GeneratorVersion,
		Artifacts:            artifacts,
		IdempotencyKey:       request.IdempotencyKey,
		Digest:               sha256.Sum256(encoded),
	}, nil
}

func validateArtifact(input ArtifactInput) (ArtifactInput, error) {
	if input.ID == uuid.Nil || len(input.WireBytes) == 0 || len(input.WireBytes) > maxArtifactWireBytes ||
		input.SizeBytes != uint64(len(input.WireBytes)) ||
		len(input.SHA256) != sha256.Size || len(input.Signature) != ed25519.SignatureSize ||
		!identifierPattern.MatchString(input.SigningKeyID) || len(input.SigningPublicKey) != ed25519.PublicKeySize ||
		input.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		!validLabel(input.MediaType) {
		return ArtifactInput{}, fmt.Errorf("integrity metadata is invalid")
	}
	digest := sha256.Sum256(input.WireBytes)
	if !bytes.Equal(digest[:], input.SHA256) {
		return ArtifactInput{}, fmt.Errorf("SHA256 does not match wire bytes")
	}
	if !ed25519.Verify(input.SigningPublicKey, input.WireBytes, input.Signature) {
		return ArtifactInput{}, fmt.Errorf("Ed25519 signature does not match wire bytes")
	}
	if input.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE &&
		input.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD {
		return ArtifactInput{}, fmt.Errorf("compression is invalid")
	}
	switch input.Kind {
	case agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION:
		if input.MediaType == siteRuntimeV2MediaType || input.MediaType == siteObjectKeyMediaType {
			if input.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
				input.RecipientKeyID == nil || !recipientKeyPattern.MatchString(*input.RecipientKeyID) ||
				input.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE || len(input.WireBytes) < 48 {
				return ArtifactInput{}, fmt.Errorf("site runtime v2 bundle compression is invalid")
			}
		} else if input.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE || input.RecipientKeyID != nil {
			return ArtifactInput{}, fmt.Errorf("configuration artifact encryption is invalid")
		}
	case agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE:
		if input.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
			input.RecipientKeyID == nil || !identifierPattern.MatchString(*input.RecipientKeyID) {
			return ArtifactInput{}, fmt.Errorf("secret artifact recipient binding is invalid")
		}
	default:
		return ArtifactInput{}, fmt.Errorf("kind is invalid")
	}
	input.WireBytes = bytes.Clone(input.WireBytes)
	input.SHA256 = bytes.Clone(input.SHA256)
	input.Signature = bytes.Clone(input.Signature)
	input.SigningPublicKey = bytes.Clone(input.SigningPublicKey)
	if input.RecipientKeyID != nil {
		value := *input.RecipientKeyID
		input.RecipientKeyID = &value
	}
	return input, nil
}

func validateSiteRuntimeV2ConfigBinding(
	expectedScopeID, expectedConfigID uuid.UUID,
	expectedCanonical []byte,
	artifacts []ArtifactInput,
	requiredCapabilities []*agentv1.Capability,
	requireCapabilities bool,
) error {
	if siteObjects, err := validateSiteObjectConfigBinding(
		expectedScopeID, expectedConfigID, expectedCanonical, artifacts, requiredCapabilities, requireCapabilities,
	); siteObjects || err != nil {
		return err
	}
	// Site runtime releases are site objects only; the whole site runtime
	// bundle is no longer produced or released.
	for _, artifact := range artifacts {
		if artifact.MediaType == siteRuntimeV2MediaType {
			return fmt.Errorf("%w: site runtime bundle artifacts are not supported (site objects only)", ErrInvalidInput)
		}
	}
	if requireCapabilities && requiresSiteRuntimeV2(requiredCapabilities) {
		return fmt.Errorf("%w: site runtime release requires site objects", ErrInvalidInput)
	}
	return nil
}

func requiresSiteRuntimeV2(capabilities []*agentv1.Capability) bool {
	for _, capability := range capabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			return true
		}
	}
	return false
}

func canonicalSiteRuntimeV2UUID(value string) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(value)
	return parsed, err == nil && parsed != uuid.Nil && parsed.String() == value
}

func decodeSiteRuntimeV2Capabilities(values []struct {
	Name       string `json:"name"`
	APIVersion uint32 `json:"api_version"`
}) ([]*agentv1.Capability, error) {
	if len(values) == 0 || len(values) > maxRequiredCapabilities {
		return nil, fmt.Errorf("site runtime v2 capabilities are invalid")
	}
	result := make([]*agentv1.Capability, len(values))
	for index, value := range values {
		name, ok := siteruntimecap.Name(value.Name)
		if !ok || value.APIVersion == 0 || (name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME &&
			(value.APIVersion < edgeconfig.MinSiteRuntimeVersion || value.APIVersion > edgeconfig.MaxDocumentSiteRuntimeVersion)) ||
			(index > 0 && values[index-1].Name >= value.Name) {
			return nil, fmt.Errorf("site runtime v2 capabilities are invalid")
		}
		result[index] = &agentv1.Capability{Name: name, ApiVersion: value.APIVersion}
	}
	if !requiresSiteRuntimeV2(result) {
		return nil, fmt.Errorf("site runtime v2 capabilities are invalid")
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result, nil
}

func equalSiteRuntimeV2Capabilities(left, right []*agentv1.Capability) bool {
	canonicalize := func(values []*agentv1.Capability) ([]*agentv1.Capability, bool) {
		result := make([]*agentv1.Capability, len(values))
		for index, value := range values {
			if value == nil || value.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || value.ApiVersion == 0 {
				return nil, false
			}
			result[index] = proto.Clone(value).(*agentv1.Capability)
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
		for index := 1; index < len(result); index++ {
			if result[index-1].Name == result[index].Name {
				return nil, false
			}
		}
		return result, true
	}
	left, leftOK := canonicalize(left)
	right, rightOK := canonicalize(right)
	if !leftOK || !rightOK || len(left) != len(right) {
		return false
	}
	for index := range left {
		if !proto.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

type normalizedRolloutRequest struct {
	CreateRolloutRequest
	NodeIDs              []uuid.UUID
	RequiredCapabilities []*agentv1.Capability
	RequestUUID          uuid.UUID
	CorrelationUUID      uuid.UUID
	Digest               [32]byte
}

type rolloutDigestCapability struct {
	Name       int32  `json:"name"`
	APIVersion uint32 `json:"api_version"`
}

type rolloutDigestNodeArtifactBinding struct {
	NodeID, DeploymentID, EventID, ConfigVersionID, ArtifactID, RecipientKeyID string
	Attempt                                                                    uint32
}

type rolloutDigestPolicy struct {
	Strategy         string `json:"strategy"`
	CanarySize       uint32 `json:"canary_size"`
	BatchSize        uint32 `json:"batch_size"`
	FailureThreshold uint32 `json:"failure_threshold"`
	AutoStart        bool   `json:"auto_start"`
}

func normalizeRolloutRequest(request CreateRolloutRequest, now time.Time) (normalizedRolloutRequest, error) {
	return normalizeRolloutRequestWithDeadline(request, now, true)
}

func normalizeRolloutReplayRequest(request CreateRolloutRequest) (normalizedRolloutRequest, error) {
	return normalizeRolloutRequestWithDeadline(request, time.Time{}, false)
}

func normalizeRolloutRequestWithDeadline(
	request CreateRolloutRequest,
	now time.Time,
	requireFutureDeadline bool,
) (normalizedRolloutRequest, error) {
	if request.MaxAttempts == 0 {
		request.MaxAttempts = 3
	}
	requestUUID, requestErr := uuid.Parse(request.RequestID)
	correlationUUID, correlationErr := uuid.Parse(request.CorrelationID)
	if request.ConfigurationScopeID == uuid.Nil || request.ConfigVersionID == uuid.Nil || requestErr != nil || correlationErr != nil ||
		!validIdempotencyKey(request.IdempotencyKey) || len(request.NodeIDs) == 0 ||
		len(request.RequiredCapabilities) > maxRequiredCapabilities ||
		request.HealthCheck.ActivationTimeout <= 0 || request.HealthCheck.ObservationWindow <= 0 ||
		request.HealthCheck.ActivationTimeout%time.Millisecond != 0 || request.HealthCheck.ObservationWindow%time.Millisecond != 0 ||
		request.HealthCheck.RequiredConsecutiveSuccesses == 0 || request.Deadline.IsZero() ||
		requireFutureDeadline && !request.Deadline.After(now) ||
		request.MaxAttempts > 10 || (request.ContractVersion != 0 && request.ContractVersion != 1 && request.ContractVersion != 2) ||
		len(request.Traceparent) > 512 || strings.TrimSpace(request.Traceparent) != request.Traceparent ||
		(request.TaskID != nil && !identifierPattern.MatchString(*request.TaskID)) {
		return normalizedRolloutRequest{}, ErrInvalidInput
	}
	if request.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY &&
		request.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK {
		return normalizedRolloutRequest{}, ErrInvalidInput
	}
	var digestPolicy *rolloutDigestPolicy
	if request.ContractVersion == 2 {
		policy, err := normalizeRolloutPolicy(request.Rollout, len(request.NodeIDs))
		if err != nil {
			return normalizedRolloutRequest{}, err
		}
		request.Rollout = policy
		digestPolicy = &rolloutDigestPolicy{
			Strategy: policy.Strategy, CanarySize: policy.CanarySize, BatchSize: policy.BatchSize,
			FailureThreshold: policy.FailureThreshold, AutoStart: policy.AutoStart,
		}
	} else if request.Rollout != (RolloutPolicy{}) {
		return normalizedRolloutRequest{}, ErrInvalidInput
	}
	nodeIDs := slices.Clone(request.NodeIDs)
	for _, nodeID := range nodeIDs {
		if nodeID == uuid.Nil {
			return normalizedRolloutRequest{}, ErrInvalidInput
		}
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return bytes.Compare(nodeIDs[i][:], nodeIDs[j][:]) < 0 })
	if len(slices.Compact(slices.Clone(nodeIDs))) != len(nodeIDs) {
		return normalizedRolloutRequest{}, ErrInvalidInput
	}
	bindings := slices.Clone(request.NodeArtifactBindings)
	sort.Slice(bindings, func(i, j int) bool { return bytes.Compare(bindings[i].NodeID[:], bindings[j].NodeID[:]) < 0 })
	if len(bindings) != 0 {
		if request.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || request.MaxAttempts != 1 || len(bindings) != len(nodeIDs) {
			return normalizedRolloutRequest{}, ErrInvalidInput
		}
		seenDeployments := make(map[uuid.UUID]struct{}, len(bindings))
		seenEvents := make(map[uuid.UUID]struct{}, len(bindings))
		seenArtifacts := make(map[uuid.UUID]struct{}, len(bindings))
		seenRecipients := make(map[string]struct{}, len(bindings))
		for index, binding := range bindings {
			if binding.NodeID != nodeIDs[index] || binding.DeploymentID == uuid.Nil || binding.EventID == uuid.Nil ||
				binding.Attempt != 1 || binding.ConfigVersionID != request.ConfigVersionID || binding.ArtifactID == uuid.Nil ||
				!recipientKeyPattern.MatchString(binding.RecipientKeyID) {
				return normalizedRolloutRequest{}, ErrInvalidInput
			}
			if _, duplicate := seenDeployments[binding.DeploymentID]; duplicate {
				return normalizedRolloutRequest{}, ErrInvalidInput
			}
			if _, duplicate := seenEvents[binding.EventID]; duplicate {
				return normalizedRolloutRequest{}, ErrInvalidInput
			}
			if _, duplicate := seenArtifacts[binding.ArtifactID]; duplicate {
				return normalizedRolloutRequest{}, ErrInvalidInput
			}
			if _, duplicate := seenRecipients[binding.RecipientKeyID]; duplicate {
				return normalizedRolloutRequest{}, ErrInvalidInput
			}
			seenDeployments[binding.DeploymentID] = struct{}{}
			seenEvents[binding.EventID] = struct{}{}
			seenArtifacts[binding.ArtifactID] = struct{}{}
			seenRecipients[binding.RecipientKeyID] = struct{}{}
		}
	}

	capabilities := make([]*agentv1.Capability, len(request.RequiredCapabilities))
	for index, capability := range request.RequiredCapabilities {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || capability.ApiVersion == 0 {
			return normalizedRolloutRequest{}, ErrInvalidInput
		}
		if _, known := agentv1.CapabilityName_name[int32(capability.Name)]; !known {
			return normalizedRolloutRequest{}, ErrInvalidInput
		}
		capabilities[index] = proto.Clone(capability).(*agentv1.Capability)
	}
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i].Name < capabilities[j].Name })
	for index := 1; index < len(capabilities); index++ {
		if capabilities[index-1].Name == capabilities[index].Name {
			return normalizedRolloutRequest{}, ErrInvalidInput
		}
	}
	digestCapabilities := make([]rolloutDigestCapability, len(capabilities))
	for index, capability := range capabilities {
		digestCapabilities[index] = rolloutDigestCapability{int32(capability.Name), capability.ApiVersion}
	}
	digestBindings := make([]rolloutDigestNodeArtifactBinding, len(bindings))
	for index, binding := range bindings {
		digestBindings[index] = rolloutDigestNodeArtifactBinding{NodeID: binding.NodeID.String(), DeploymentID: binding.DeploymentID.String(),
			EventID: binding.EventID.String(), ConfigVersionID: binding.ConfigVersionID.String(), ArtifactID: binding.ArtifactID.String(),
			RecipientKeyID: binding.RecipientKeyID, Attempt: binding.Attempt}
	}
	encoded, err := json.Marshal(struct {
		ScopeID                      string                             `json:"scope_id"`
		ConfigVersionID              string                             `json:"config_version_id"`
		Action                       int32                              `json:"action"`
		NodeIDs                      []uuid.UUID                        `json:"node_ids"`
		Capabilities                 []rolloutDigestCapability          `json:"capabilities"`
		NodeArtifactBindings         []rolloutDigestNodeArtifactBinding `json:"node_artifact_bindings,omitempty"`
		ActivationTimeoutNS          int64                              `json:"activation_timeout_ns"`
		ObservationWindowNS          int64                              `json:"observation_window_ns"`
		RequiredConsecutiveSuccesses uint32                             `json:"required_consecutive_successes"`
		MaxAttempts                  uint32                             `json:"max_attempts"`
		ContractVersion              int16                              `json:"contract_version"`
		Rollout                      *rolloutDigestPolicy               `json:"rollout,omitempty"`
		Deadline                     string                             `json:"deadline"`
		RequestID                    string                             `json:"request_id"`
		CorrelationID                string                             `json:"correlation_id"`
		Traceparent                  string                             `json:"traceparent"`
		TaskID                       *string                            `json:"task_id,omitempty"`
	}{
		request.ConfigurationScopeID.String(), request.ConfigVersionID.String(), int32(request.Action), nodeIDs,
		digestCapabilities, digestBindings, int64(request.HealthCheck.ActivationTimeout), int64(request.HealthCheck.ObservationWindow),
		request.HealthCheck.RequiredConsecutiveSuccesses, request.MaxAttempts, request.ContractVersion, digestPolicy,
		request.Deadline.UTC().Format(time.RFC3339Nano),
		requestUUID.String(), correlationUUID.String(), request.Traceparent, request.TaskID,
	})
	if err != nil {
		return normalizedRolloutRequest{}, fmt.Errorf("encode rollout request digest: %w", err)
	}
	request.NodeIDs = nodeIDs
	request.NodeArtifactBindings = bindings
	request.RequiredCapabilities = capabilities
	return normalizedRolloutRequest{
		CreateRolloutRequest: request, NodeIDs: nodeIDs, RequiredCapabilities: capabilities,
		RequestUUID: requestUUID, CorrelationUUID: correlationUUID, Digest: sha256.Sum256(encoded),
	}, nil
}

func validLabel(value string) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= 128
}

func validIdempotencyKey(value string) bool {
	return identifierPattern.MatchString(value)
}
