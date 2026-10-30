package gatewayclient

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cloudflare/circl/hpke"
	"google.golang.org/protobuf/proto"
)

func validateCommand(command *agentv1.DeploymentCommand, config Config, now time.Time, activeIdentityCapability ...bool) error {
	if err := validateCommandIdentity(command, config, activeIdentityCapability...); err != nil {
		return err
	}
	if command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("%w: command event time is invalid", ErrInvalidMessage)
	}
	if command.Event.CausationId != nil && !canonicalUUID(command.Event.GetCausationId()) {
		return fmt.Errorf("%w: command causation ID is invalid", ErrInvalidMessage)
	}
	if !canonicalUUID(command.RolloutId) {
		return fmt.Errorf("%w: rollout ID is invalid", ErrInvalidMessage)
	}
	activeIdentityEnabled := len(activeIdentityCapability) == 1 && activeIdentityCapability[0]
	if command.PreviousConfigVersionId != nil &&
		((activeIdentityEnabled && !canonicalUUID(command.GetPreviousConfigVersionId())) ||
			(!activeIdentityEnabled && !safeIdentifier(command.GetPreviousConfigVersionId())) || command.GetPreviousConfigVersionId() == command.ConfigVersionId) {
		return fmt.Errorf("%w: previous config version is invalid", ErrInvalidMessage)
	}
	switch command.Action {
	case agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE:
		if len(command.Artifacts) != 1 {
			return fmt.Errorf("%w: exactly one configuration artifact is required", ErrUnsupportedCommand)
		}
		descriptor := command.Artifacts[0]
		if descriptor == nil || !canonicalUUID(descriptor.ArtifactId) {
			return fmt.Errorf("%w: unsupported artifact set", ErrUnsupportedCommand)
		}
		if descriptor.Kind == agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE && descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
			return fmt.Errorf("%w: node secret bundles must be encrypted", ErrInvalidMessage)
		}
		if descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || descriptor.MediaType != ConfigurationBundleMediaType {
			return fmt.Errorf("%w: unsupported artifact set", ErrUnsupportedCommand)
		}
		switch descriptor.EncryptionAlgorithm {
		case agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE:
			if descriptor.RecipientKeyId != nil {
				return fmt.Errorf("%w: plaintext artifact cannot name a recipient key", ErrInvalidMessage)
			}
		case agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM:
			if len(config.ArtifactDecryptionPrivateKey) != 32 || descriptor.RecipientKeyId == nil || descriptor.GetRecipientKeyId() != config.ArtifactEncryptionKeyID {
				return fmt.Errorf("%w: encrypted artifact recipient is unavailable", ErrUnsupportedCommand)
			}
			if descriptor.SizeBytes < uint64(hpke.KEM_X25519_HKDF_SHA256.Scheme().CiphertextSize()+hpkeTagSize) {
				return fmt.Errorf("%w: encrypted artifact envelope is truncated", ErrInvalidMessage)
			}
		default:
			return fmt.Errorf("%w: unsupported artifact encryption algorithm", ErrUnsupportedCommand)
		}
		if descriptor.SizeBytes == 0 || descriptor.SizeBytes > config.MaxArtifactBytes || len(descriptor.Sha256) != sha256.Size || len(descriptor.Signature) == 0 || !safeIdentifier(descriptor.SigningKeyId) {
			return fmt.Errorf("%w: artifact integrity metadata is invalid", ErrInvalidMessage)
		}
		if descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 && descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 {
			return fmt.Errorf("%w: unsupported artifact signature algorithm", ErrUnsupportedCommand)
		}
		if descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE && descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD {
			return fmt.Errorf("%w: unsupported artifact compression", ErrUnsupportedCommand)
		}
	case agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK:
		if command.PreviousConfigVersionId == nil {
			return fmt.Errorf("%w: rollback baseline is required", ErrInvalidMessage)
		}
		if len(command.Artifacts) != 0 {
			return fmt.Errorf("%w: rollback must not include artifacts", ErrInvalidMessage)
		}
	default:
		return fmt.Errorf("%w: deployment action is not implemented", ErrUnsupportedCommand)
	}
	if command.HealthCheck == nil || command.HealthCheck.ActivationTimeoutDuration == nil || command.HealthCheck.ObservationWindowDuration == nil || command.HealthCheck.ActivationTimeoutDuration.CheckValid() != nil || command.HealthCheck.ObservationWindowDuration.CheckValid() != nil || command.HealthCheck.ActivationTimeoutDuration.AsDuration() <= 0 || command.HealthCheck.ObservationWindowDuration.AsDuration() <= 0 || command.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return fmt.Errorf("%w: health policy is invalid", ErrInvalidMessage)
	}
	if command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil || !command.DeadlineTime.AsTime().After(now) {
		return fmt.Errorf("%w: command deadline has expired", ErrUnsupportedCommand)
	}
	localCapabilities := make(map[agentv1.CapabilityName]uint32, len(config.Capabilities.Features))
	for _, capability := range config.Capabilities.Features {
		localCapabilities[capability.Name] = capability.ApiVersion
	}
	if len(command.RequiredCapabilities) > 64 {
		return fmt.Errorf("%w: too many required capabilities", ErrInvalidMessage)
	}
	required := make(map[agentv1.CapabilityName]struct{}, len(command.RequiredCapabilities))
	for _, capability := range command.RequiredCapabilities {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || capability.ApiVersion == 0 {
			return fmt.Errorf("%w: required capability is invalid", ErrInvalidMessage)
		}
		if _, exists := required[capability.Name]; exists {
			return fmt.Errorf("%w: required capability is duplicated", ErrInvalidMessage)
		}
		required[capability.Name] = struct{}{}
		if localCapabilities[capability.Name] < capability.ApiVersion {
			return fmt.Errorf("%w: required capability is unavailable", ErrUnsupportedCommand)
		}
	}
	return nil
}

func validateCommandIdentity(command *agentv1.DeploymentCommand, config Config, activeIdentityCapability ...bool) error {
	if command == nil || proto.Size(command) > config.MaxCommandBytes {
		return fmt.Errorf("%w: command is missing or too large", ErrInvalidMessage)
	}
	if command.Event == nil || !canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) || !boundedMetadata(command.Event.Traceparent, false) || !boundedMetadata(command.Event.CorrelationId, false) {
		return fmt.Errorf("%w: command event metadata is invalid", ErrInvalidMessage)
	}
	if command.Event.TaskId != nil && !boundedMetadata(command.Event.GetTaskId(), true) {
		return fmt.Errorf("%w: command task metadata is invalid", ErrInvalidMessage)
	}
	activeIdentityEnabled := len(activeIdentityCapability) == 1 && activeIdentityCapability[0]
	if !canonicalUUID(command.DeploymentId) || command.Attempt == 0 ||
		(activeIdentityEnabled && !canonicalUUID(command.ConfigVersionId)) || (!activeIdentityEnabled && !safeIdentifier(command.ConfigVersionId)) {
		return fmt.Errorf("%w: command identity is invalid", ErrInvalidMessage)
	}
	return nil
}

func validateGatewayHello(hello *agentv1.GatewayHello, config Config) error {
	if hello == nil || !versionInRange(hello.SelectedProtocolVersion, config.SupportedVersions) || !canonicalUUID(hello.SessionId) || hello.SessionEpoch == 0 || hello.ServerTime == nil || hello.ServerTime.CheckValid() != nil || !boundedMetadata(hello.GatewayVersion, true) {
		return fmt.Errorf("%w: GatewayHello identity or version is invalid", ErrInvalidMessage)
	}
	if hello.HeartbeatIntervalDuration == nil || hello.HeartbeatIntervalDuration.CheckValid() != nil || hello.HeartbeatIntervalDuration.AsDuration() <= 0 || hello.OfflineAfterDuration == nil || hello.OfflineAfterDuration.CheckValid() != nil || hello.OfflineAfterDuration.AsDuration() <= hello.HeartbeatIntervalDuration.AsDuration() {
		return fmt.Errorf("%w: GatewayHello heartbeat policy is invalid", ErrInvalidMessage)
	}
	if hello.MaximumArtifactChunkBytes == 0 || hello.MaximumArtifactChunkBytes > config.MaxArtifactChunkBytes || hello.MessageIdReplayWindow == 0 {
		return fmt.Errorf("%w: GatewayHello limits are invalid", ErrInvalidMessage)
	}
	if len(hello.EnabledCapabilities) > 64 {
		return fmt.Errorf("%w: too many Gateway capabilities", ErrInvalidMessage)
	}
	seen := make(map[agentv1.CapabilityName]struct{}, len(hello.EnabledCapabilities))
	for _, capability := range hello.EnabledCapabilities {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || capability.ApiVersion == 0 {
			return fmt.Errorf("%w: Gateway capability is invalid", ErrInvalidMessage)
		}
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY && capability.ApiVersion != activeConfigIdentityAPIVersion {
			return fmt.Errorf("%w: Gateway active config identity capability is unsupported", ErrInvalidMessage)
		}
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT && capability.ApiVersion != deploymentStatusAckReceiptAPIVersion {
			return fmt.Errorf("%w: Gateway deployment status acknowledgement receipt capability is unsupported", ErrInvalidMessage)
		}
		if _, exists := seen[capability.Name]; exists {
			return fmt.Errorf("%w: Gateway capability is duplicated", ErrInvalidMessage)
		}
		seen[capability.Name] = struct{}{}
	}
	return nil
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f || strings.ContainsRune(`/\\`, character) {
			return false
		}
	}
	return true
}

func boundedMetadata(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateStreamProtocolError(value *commonv1.ProtocolError) error {
	if value == nil || value.Code == commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED || !boundedText(value.Message, true, 4096) {
		return fmt.Errorf("%w: malformed Gateway stream error", ErrInvalidMessage)
	}
	if _, known := commonv1.ErrorCode_name[int32(value.Code)]; !known {
		return fmt.Errorf("%w: unknown Gateway stream error code", ErrInvalidMessage)
	}
	if value.RetryAfterDuration != nil && (value.RetryAfterDuration.CheckValid() != nil || value.RetryAfterDuration.AsDuration() < 0) {
		return fmt.Errorf("%w: invalid Gateway retry duration", ErrInvalidMessage)
	}
	if len(value.FieldViolations) > 64 {
		return fmt.Errorf("%w: too many Gateway field violations", ErrInvalidMessage)
	}
	for _, violation := range value.FieldViolations {
		if violation == nil || !safeIdentifier(violation.Field) || !boundedText(violation.Description, true, 4096) {
			return fmt.Errorf("%w: invalid Gateway field violation", ErrInvalidMessage)
		}
	}
	return nil
}

func boundedText(value string, required bool, maximum int) bool {
	if value == "" {
		return !required
	}
	if len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character == 0 || character == 0x7f {
			return false
		}
	}
	return true
}
