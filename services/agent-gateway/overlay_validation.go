package gateway

import (
	"crypto/sha256"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const acmeHTTP01OverlayMediaType = "application/vnd.cdnca.acme-http01-overlay.v1+json"

func (g *Gateway) validateACMEHTTP01OverlayCommand(command *agentv1.AcmeHTTP01OverlayCommand) error {
	if command == nil || proto.Size(command) > g.config.MaxReceiveMessageBytes {
		return fmt.Errorf("overlay command is missing or exceeds its size limit")
	}
	if err := g.validateEventMetadata(command.Event); err != nil {
		return err
	}
	if command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("overlay command event time is invalid")
	}
	if err := g.validateUUID("overlay_command.deployment_id", command.OverlayDeploymentId); err != nil {
		return err
	}
	if command.Attempt == 0 || command.OverlayRevision == 0 {
		return fmt.Errorf("overlay command attempt and revision must be positive")
	}
	if err := g.validateUUID("overlay_command.version_id", command.OverlayVersionId); err != nil {
		return err
	}
	if (command.PreviousOverlayVersionId == nil) != (command.PreviousOverlayRevision == nil) {
		return fmt.Errorf("overlay command previous version and revision must be supplied together")
	}
	if command.PreviousOverlayVersionId != nil {
		if err := g.validateUUID("overlay_command.previous_version_id", command.GetPreviousOverlayVersionId()); err != nil {
			return err
		}
		if command.GetPreviousOverlayRevision() == 0 || command.GetPreviousOverlayRevision() >= command.OverlayRevision {
			return fmt.Errorf("overlay command previous revision is invalid")
		}
	}
	artifact := command.Artifact
	if artifact == nil || artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_ACME_HTTP01_OVERLAY ||
		artifact.MediaType != acmeHTTP01OverlayMediaType || artifact.SizeBytes == 0 ||
		artifact.SizeBytes > g.config.MaxArtifactBytes || len(artifact.Sha256) != sha256.Size ||
		len(artifact.Signature) == 0 || len(artifact.Signature) > g.config.MaxEventMetadataBytes ||
		artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
		artifact.RecipientKeyId != nil {
		return fmt.Errorf("overlay artifact descriptor is invalid")
	}
	if err := g.validateUUID("overlay_command.artifact_id", artifact.ArtifactId); err != nil {
		return err
	}
	if err := g.validateIdentifier("overlay_command.signing_key_id", artifact.SigningKeyId, true); err != nil {
		return err
	}
	if artifact.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 &&
		artifact.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 {
		return fmt.Errorf("overlay artifact signature algorithm is unsupported")
	}
	if artifact.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE &&
		artifact.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD {
		return fmt.Errorf("overlay artifact compression is unsupported")
	}
	if command.HealthCheck == nil || !validPositiveDuration(command.HealthCheck.ActivationTimeoutDuration) ||
		!validNonNegativeDuration(command.HealthCheck.ObservationWindowDuration) ||
		command.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return fmt.Errorf("overlay health policy is invalid")
	}
	if command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil {
		return fmt.Errorf("overlay command deadline is invalid")
	}
	if command.Purpose != agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_APPLY &&
		command.Purpose != agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY {
		return fmt.Errorf("overlay command purpose is invalid")
	}
	return nil
}

func (g *Gateway) validateACMEHTTP01OverlayStatus(status *agentv1.AcmeHTTP01OverlayStatus) error {
	if status == nil || proto.Size(status) > g.config.MaxReceiveMessageBytes {
		return fmt.Errorf("overlay status is missing or exceeds its size limit")
	}
	if err := g.validateEventMetadata(status.Event); err != nil {
		return err
	}
	if status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("overlay status event time is invalid")
	}
	if err := g.validateUUID("overlay_status.deployment_id", status.OverlayDeploymentId); err != nil {
		return err
	}
	if err := g.validateUUID("overlay_status.version_id", status.OverlayVersionId); err != nil {
		return err
	}
	if status.Attempt == 0 || status.OverlayRevision == 0 || status.TransitionSequence == 0 {
		return fmt.Errorf("overlay status attempt, revision, and sequence must be positive")
	}
	if _, known := agentv1.AcmeHTTP01OverlayState_name[int32(status.State)]; !known ||
		status.State == agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_UNSPECIFIED {
		return fmt.Errorf("overlay status state is invalid")
	}
	if _, known := agentv1.AcmeHTTP01OverlayResultCode_name[int32(status.ResultCode)]; !known ||
		status.ResultCode == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED {
		return fmt.Errorf("overlay status result code is invalid")
	}
	if !validACMEHTTP01OverlayStateResult(status.State, status.ResultCode) {
		return fmt.Errorf("overlay status state and result code are inconsistent")
	}
	if status.ActiveOverlayVersionId == nil {
		if status.ActiveOverlayRevision != 0 {
			return fmt.Errorf("overlay status active revision has no version")
		}
	} else {
		if err := g.validateUUID("overlay_status.active_version_id", status.GetActiveOverlayVersionId()); err != nil {
			return err
		}
		if status.ActiveOverlayRevision == 0 {
			return fmt.Errorf("overlay status active revision must be positive")
		}
	}
	if len(status.ActivationSummary) > g.config.MaxEventMetadataBytes || len(status.Checks) > g.config.MaxDeploymentChecks {
		return fmt.Errorf("overlay status details exceed their size limit")
	}
	checkNames := make(map[string]struct{}, len(status.Checks))
	for _, check := range status.Checks {
		if check == nil || g.validateIdentifier("overlay_status.check.name", check.Name, true) != nil ||
			len(check.Summary) > g.config.MaxEventMetadataBytes || !validNonNegativeDuration(check.LatencyDuration) {
			return fmt.Errorf("overlay status check is invalid")
		}
		if _, exists := checkNames[check.Name]; exists {
			return fmt.Errorf("overlay status check names must be unique")
		}
		checkNames[check.Name] = struct{}{}
	}
	if status.Error != nil {
		if err := g.validateProtocolError(status.Error); err != nil {
			return err
		}
	}
	if !validACMEHTTP01OverlayErrorPresence(status.State, status.Error != nil) {
		return fmt.Errorf("overlay status state and protocol error are inconsistent")
	}
	return nil
}

func validACMEHTTP01OverlayErrorPresence(state agentv1.AcmeHTTP01OverlayState, hasError bool) bool {
	switch state {
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_STAGED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_PRECHECKED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY:
		return !hasError
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED:
		return hasError
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED:
		return true
	default:
		return false
	}
}

func validACMEHTTP01OverlayStateResult(state agentv1.AcmeHTTP01OverlayState, result agentv1.AcmeHTTP01OverlayResultCode) bool {
	switch state {
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_STAGED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_PRECHECKED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED:
		return result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED &&
			result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK &&
			result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK &&
			result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED
	default:
		return false
	}
}
