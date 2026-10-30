package gateway

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func validAgentVersion(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._+:-", character) {
			continue
		}
		return false
	}
	return true
}

const minimumHPKEArtifactBytes = 32 + 16

const activeConfigIdentityAPIVersion uint32 = 1

const deploymentStatusAckReceiptAPIVersion uint32 = 1

const urlAuthArtifactMediaType = "application/vnd.cdnca.edge-url-auth-bundle+json;version=1"

func activeConfigIdentityCapability() *agentv1.Capability {
	return &agentv1.Capability{
		Name:       agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY,
		ApiVersion: activeConfigIdentityAPIVersion,
	}
}

func deploymentStatusAckReceiptCapability() *agentv1.Capability {
	return &agentv1.Capability{
		Name:       agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT,
		ApiVersion: deploymentStatusAckReceiptAPIVersion,
	}
}

func activeConfigIdentityCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY {
			continue
		}
		if seen {
			return false, fmt.Errorf("active config identity capability is duplicated")
		}
		seen = true
		if capability.ApiVersion != activeConfigIdentityAPIVersion {
			return false, fmt.Errorf("active config identity capability version is unsupported")
		}
	}
	return seen, nil
}

func deploymentStatusAckReceiptCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT {
			continue
		}
		if seen {
			return false, fmt.Errorf("deployment status acknowledgement receipt capability is duplicated")
		}
		seen = true
		if capability.ApiVersion != deploymentStatusAckReceiptAPIVersion {
			return false, fmt.Errorf("deployment status acknowledgement receipt capability version is unsupported")
		}
	}
	return seen, nil
}

func gatewayHelloHasActiveIdentityV1(hello *agentv1.GatewayHello) bool {
	if hello == nil {
		return false
	}
	for _, capability := range hello.EnabledCapabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY && capability.ApiVersion == activeConfigIdentityAPIVersion {
			return true
		}
	}
	return false
}

func (g *Gateway) validateActiveConfigIdentity(name string, identity *agentv1.ActiveConfigIdentity, expectedConfigVersionID string) error {
	if identity == nil {
		return nil
	}
	if identity.Schema != agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1 {
		return fmt.Errorf("%s schema is unsupported", name)
	}
	if err := g.validateUUID(name+".config_version_id", identity.ConfigVersionId); err != nil {
		return err
	}
	if expectedConfigVersionID != "" && identity.ConfigVersionId != expectedConfigVersionID {
		return fmt.Errorf("%s config version does not match its companion field", name)
	}
	if len(identity.ArtifactSha256) != 32 {
		return fmt.Errorf("%s artifact digest must be exactly 32 bytes", name)
	}
	return nil
}

func validateReportedActiveConfigIdentityCapability(capability *agentv1.Capability, negotiated, required bool) error {
	if !negotiated {
		if capability != nil {
			return fmt.Errorf("active config identity capability was not negotiated")
		}
		return nil
	}
	if capability == nil {
		if required {
			return fmt.Errorf("active config identity capability is required")
		}
		return nil
	}
	if capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY || capability.ApiVersion != activeConfigIdentityAPIVersion {
		return fmt.Errorf("active config identity capability is invalid")
	}
	return nil
}

func (g *Gateway) validateHelloActiveConfigIdentities(hello *agentv1.AgentHello, capable bool) error {
	if !capable && (hello.CurrentConfigIdentity != nil || hello.PreviousConfigIdentity != nil) {
		return fmt.Errorf("hello active config identity capability is missing")
	}
	currentID := ""
	if hello.CurrentConfigVersionId != nil {
		currentID = hello.GetCurrentConfigVersionId()
		if capable {
			if err := g.validateUUID("hello.current_config_version_id", currentID); err != nil {
				return err
			}
		}
	}
	previousID := ""
	if hello.PreviousConfigVersionId != nil {
		previousID = hello.GetPreviousConfigVersionId()
		if capable {
			if err := g.validateUUID("hello.previous_config_version_id", previousID); err != nil {
				return err
			}
		}
	}
	if hello.CurrentConfigIdentity != nil && currentID == "" || hello.PreviousConfigIdentity != nil && previousID == "" {
		return fmt.Errorf("hello active config identity has no companion version")
	}
	if err := g.validateActiveConfigIdentity("hello.current_config_identity", hello.CurrentConfigIdentity, currentID); err != nil {
		return err
	}
	if err := g.validateActiveConfigIdentity("hello.previous_config_identity", hello.PreviousConfigIdentity, previousID); err != nil {
		return err
	}
	for _, active := range hello.ActiveDeployments {
		if active == nil {
			continue
		}
		if !capable && active.ObservedActiveConfigIdentity != nil {
			return fmt.Errorf("active deployment identity capability is missing")
		}
		if capable {
			if err := g.validateUUID("hello.active_deployment.config_version_id", active.ConfigVersionId); err != nil {
				return err
			}
		}
		if err := g.validateActiveConfigIdentity("hello.active_deployment.observed_active_config_identity", active.ObservedActiveConfigIdentity, active.ConfigVersionId); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) validateHeartbeatActiveConfigIdentities(heartbeat *agentv1.Heartbeat, negotiated bool) error {
	if err := validateReportedActiveConfigIdentityCapability(heartbeat.ActiveConfigIdentityCapability, negotiated, negotiated); err != nil {
		return err
	}
	if !negotiated && (heartbeat.CurrentConfigIdentity != nil || heartbeat.PreviousConfigIdentity != nil || heartbeat.Runtime != nil && heartbeat.Runtime.LoadedConfigIdentity != nil) {
		return fmt.Errorf("heartbeat active config identity was not negotiated")
	}
	currentID := ""
	if heartbeat.CurrentConfigVersionId != nil {
		currentID = heartbeat.GetCurrentConfigVersionId()
		if negotiated {
			if err := g.validateUUID("heartbeat.current_config_version_id", currentID); err != nil {
				return err
			}
		}
	}
	previousID := ""
	if heartbeat.PreviousConfigVersionId != nil {
		previousID = heartbeat.GetPreviousConfigVersionId()
		if negotiated {
			if err := g.validateUUID("heartbeat.previous_config_version_id", previousID); err != nil {
				return err
			}
		}
	}
	if heartbeat.CurrentConfigIdentity != nil && currentID == "" || heartbeat.PreviousConfigIdentity != nil && previousID == "" {
		return fmt.Errorf("heartbeat active config identity has no companion version")
	}
	if err := g.validateActiveConfigIdentity("heartbeat.current_config_identity", heartbeat.CurrentConfigIdentity, currentID); err != nil {
		return err
	}
	if err := g.validateActiveConfigIdentity("heartbeat.previous_config_identity", heartbeat.PreviousConfigIdentity, previousID); err != nil {
		return err
	}
	if heartbeat.Runtime != nil {
		if _, known := agentv1.MarketProbeRole_name[int32(heartbeat.Runtime.MarketProbe)]; !known {
			return fmt.Errorf("heartbeat.runtime.market_probe is not a known role")
		}
		if !validNativeRuntimeStatus(heartbeat.Runtime.NativeRuntime) {
			return fmt.Errorf("heartbeat.runtime.native_runtime is invalid")
		}
		if summary := heartbeat.Runtime.ErrorLog; summary != nil {
			if len(summary.Recent) > 16 {
				return fmt.Errorf("heartbeat.runtime.error_log.recent exceeds 16 lines")
			}
			for _, line := range summary.Recent {
				if len(line) > 512 || !utf8.ValidString(line) {
					return fmt.Errorf("heartbeat.runtime.error_log.recent line is invalid")
				}
			}
			if summary.LastSevereTime != nil && summary.LastSevereTime.CheckValid() != nil {
				return fmt.Errorf("heartbeat.runtime.error_log.last_severe_time is invalid")
			}
		}
		loadedID := ""
		if heartbeat.Runtime.LoadedConfigVersionId != nil {
			loadedID = heartbeat.Runtime.GetLoadedConfigVersionId()
			if negotiated {
				if err := g.validateUUID("heartbeat.runtime.loaded_config_version_id", loadedID); err != nil {
					return err
				}
			}
		}
		if heartbeat.Runtime.LoadedConfigIdentity != nil && loadedID == "" {
			return fmt.Errorf("runtime active config identity has no companion version")
		}
		if err := g.validateActiveConfigIdentity("heartbeat.runtime.loaded_config_identity", heartbeat.Runtime.LoadedConfigIdentity, loadedID); err != nil {
			return err
		}
	}
	for _, active := range heartbeat.ActiveDeployments {
		if active == nil {
			continue
		}
		if !negotiated && active.ObservedActiveConfigIdentity != nil {
			return fmt.Errorf("heartbeat active deployment identity was not negotiated")
		}
		if negotiated {
			if err := g.validateUUID("heartbeat.active_deployment.config_version_id", active.ConfigVersionId); err != nil {
				return err
			}
		}
		if err := g.validateActiveConfigIdentity("heartbeat.active_deployment.observed_active_config_identity", active.ObservedActiveConfigIdentity, active.ConfigVersionId); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) validateDeploymentStatusActiveConfigIdentity(status *agentv1.DeploymentStatus, negotiated bool) error {
	terminal := status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY ||
		status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED ||
		status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED ||
		status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED
	if !terminal {
		if status.ActiveConfigIdentityCapability != nil || status.ActiveConfigIdentity != nil {
			return fmt.Errorf("nonterminal deployment status must not report active config identity")
		}
		return nil
	}
	if err := validateReportedActiveConfigIdentityCapability(status.ActiveConfigIdentityCapability, negotiated, status.ActiveConfigIdentity != nil); err != nil {
		return err
	}
	if !negotiated && status.ActiveConfigIdentity != nil {
		return fmt.Errorf("deployment status active config identity was not negotiated")
	}
	if status.ActiveConfigIdentity != nil &&
		status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
		status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
		return fmt.Errorf("only a healthy or reverted deployment status may report active config identity")
	}
	if status.ActiveConfigIdentity != nil && status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED &&
		!hasActiveConfigProbeEvidence(status) {
		return fmt.Errorf("reverted deployment status active config identity requires runtime probe evidence")
	}
	return g.validateActiveConfigIdentity("deployment_status.active_config_identity", status.ActiveConfigIdentity, status.ConfigVersionId)
}

func hasActiveConfigProbeEvidence(status *agentv1.DeploymentStatus) bool {
	for _, check := range status.GetChecks() {
		if check.GetName() == "edge_active_config_probe" && check.GetSucceeded() &&
			check.GetSummary() == "active config runtime probe passed" && check.GetLatencyDuration() != nil &&
			check.GetLatencyDuration().CheckValid() == nil && check.GetLatencyDuration().AsDuration() >= 0 {
			return true
		}
	}
	return false
}

func validateDeploymentStatusActiveIdentityCommandBinding(status *agentv1.DeploymentStatus, command *agentv1.DeploymentCommand) error {
	if status == nil || command == nil ||
		status.DeploymentId != command.DeploymentId || status.Attempt != command.Attempt || status.ConfigVersionId != command.ConfigVersionId {
		return fmt.Errorf("terminal deployment status has no matching command")
	}
	if status.Event == nil || command.Event == nil || status.Event.CausationId == nil ||
		status.Event.GetCausationId() != command.Event.EventId || status.Event.RequestId != command.Event.RequestId ||
		status.Event.Traceparent != command.Event.Traceparent || status.Event.CorrelationId != command.Event.CorrelationId ||
		(status.Event.TaskId == nil) != (command.Event.TaskId == nil) || status.Event.GetTaskId() != command.Event.GetTaskId() {
		return fmt.Errorf("terminal deployment status event does not match its command")
	}
	if status.ConfigurationScopeId != nil {
		if err := validateDeploymentStatusScopeCommandBinding(status, command); err != nil {
			return err
		}
	}
	if status.ActiveConfigIdentity == nil {
		return nil
	}
	switch status.State {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY:
		if command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE {
			return fmt.Errorf("deployment status active config identity has no signed apply artifact")
		}
		// A site object release (site runtime v8) runs its shared signed root.
		if len(command.Artifacts) != 1 && !deploymentCommandUsesSiteObjects(command) || command.Artifacts[0] == nil || command.Artifacts[0].Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || !bytes.Equal(status.ActiveConfigIdentity.ArtifactSha256, command.Artifacts[0].Sha256) {
			return fmt.Errorf("deployment status active config identity does not match the signed command artifact")
		}
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED:
		if command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK || len(command.Artifacts) != 0 {
			return fmt.Errorf("reverted deployment status active config identity has no signed rollback command")
		}
	default:
		return fmt.Errorf("deployment status active config identity is not terminal")
	}
	return nil
}

func (g *Gateway) validateDeploymentCommand(command *agentv1.DeploymentCommand, artifactEncryptionKeyID string, activeIdentityCapability ...bool) error {
	if command == nil || proto.Size(command) > g.config.MaxSendMessageBytes {
		return fmt.Errorf("deployment command is missing or exceeds its size limit")
	}
	if cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return fmt.Errorf("deployment command contains unknown fields")
	}
	if err := g.validateEventMetadata(command.Event); err != nil {
		return err
	}
	if command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("command event time is invalid")
	}
	if err := g.validateUUID("command.deployment_id", command.DeploymentId); err != nil {
		return err
	}
	if command.Attempt == 0 {
		return fmt.Errorf("command attempt must be positive")
	}
	if err := g.validateUUID("command.rollout_id", command.RolloutId); err != nil {
		return err
	}
	siteObjects := deploymentCommandUsesSiteObjects(command)
	if !siteObjects && deploymentCommandRequiresSiteRuntime(command) {
		// Site runtime releases reach nodes only as site objects (v2 root +
		// key envelope); the whole site runtime bundle is no longer sent.
		return fmt.Errorf("site runtime command must be a site object release")
	}
	urlAuth := deploymentCommandUsesURLAuth(command)
	errorPage := deploymentCommandUsesErrorPage(command)
	activeIdentityEnabled := len(activeIdentityCapability) == 1 && activeIdentityCapability[0]
	specialized := siteObjects || urlAuth || errorPage
	if activeIdentityEnabled || specialized {
		if err := g.validateUUID("command.config_version_id", command.ConfigVersionId); err != nil {
			return err
		}
		if specialized && command.ConfigVersionId == uuid.Nil.String() {
			return fmt.Errorf("specialized command config version must not be nil")
		}
	} else if err := g.validateIdentifier("command.config_version_id", command.ConfigVersionId, true); err != nil {
		return err
	}
	if command.ConfigurationScopeId != nil {
		if err := g.validateUUID("command.configuration_scope_id", command.GetConfigurationScopeId()); err != nil {
			return err
		}
		if specialized && command.GetConfigurationScopeId() == uuid.Nil.String() {
			return fmt.Errorf("specialized command configuration scope must not be nil")
		}
	} else if specialized {
		return fmt.Errorf("specialized command configuration scope is required")
	}
	if command.PreviousConfigVersionId != nil {
		if activeIdentityEnabled || specialized {
			if err := g.validateUUID("command.previous_config_version_id", command.GetPreviousConfigVersionId()); err != nil {
				return err
			}
		} else if err := g.validateIdentifier("command.previous_config_version_id", command.GetPreviousConfigVersionId(), true); err != nil {
			return err
		}
	}
	switch command.Action {
	case agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE:
		if len(command.Artifacts) == 0 || len(command.Artifacts) > g.config.MaxCommandArtifacts {
			return fmt.Errorf("command artifacts are missing or exceed their size limit")
		}
		if (urlAuth || errorPage) && len(command.Artifacts) != 1 {
			return fmt.Errorf("specialized command must contain exactly one artifact")
		}
		if siteObjects && len(command.Artifacts) != 2 {
			return fmt.Errorf("site object command must contain the root and one key envelope")
		}
	case agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK:
		if len(command.Artifacts) != 0 {
			return fmt.Errorf("rollback command must not include artifacts")
		}
	default:
		return fmt.Errorf("command action is invalid")
	}
	artifactIDs := make(map[string]struct{}, len(command.Artifacts))
	for _, artifact := range command.Artifacts {
		if err := g.validateArtifactDescriptor(artifact, artifactEncryptionKeyID); err != nil {
			return err
		}
		if _, exists := artifactIDs[artifact.ArtifactId]; exists {
			return fmt.Errorf("command artifact IDs must be unique")
		}
		artifactIDs[artifact.ArtifactId] = struct{}{}
	}
	if siteObjects && len(command.Artifacts) == 2 {
		root, envelope := command.Artifacts[0], command.Artifacts[1]
		if root.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || !siteObjectRootMediaType(root.MediaType) ||
			root.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
			root.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
			root.SizeBytes > siteobject.MaxRootBytes ||
			envelope.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || envelope.MediaType != siteobject.KeyMediaType ||
			envelope.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
			envelope.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
			return fmt.Errorf("site object command artifact contract is invalid")
		}
	}
	if urlAuth && len(command.Artifacts) > 0 {
		artifact := command.Artifacts[0]
		if artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
			artifact.MediaType != urlAuthArtifactMediaType ||
			artifact.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
			artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
			return fmt.Errorf("URL auth command artifact contract is invalid")
		}
	}
	if errorPage && len(command.Artifacts) > 0 {
		if err := ValidateErrorPageArtifactDescriptor(command.Artifacts[0], g.config.MaxArtifactBytes); err != nil {
			return err
		}
	}
	if len(command.RequiredCapabilities) > g.config.MaxCapabilities {
		return fmt.Errorf("command capabilities exceed their size limit")
	}
	capabilities := make(map[agentv1.CapabilityName]struct{}, len(command.RequiredCapabilities))
	var siteRuntimeVersion uint32
	for _, capability := range command.RequiredCapabilities {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || capability.ApiVersion == 0 {
			return fmt.Errorf("command capability is invalid")
		}
		if _, known := agentv1.CapabilityName_name[int32(capability.Name)]; !known {
			return fmt.Errorf("command capability is unknown")
		}
		if _, exists := capabilities[capability.Name]; exists {
			return fmt.Errorf("command capabilities must be unique")
		}
		capabilities[capability.Name] = struct{}{}
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			siteRuntimeVersion = capability.ApiVersion
		}
	}
	if siteObjects {
		// Site objects are dynamic routing (v2 root, site runtime 9).
		want := edgeconfig.DynamicRoutingSiteRuntimeVersion
		if siteRuntimeVersion != want {
			return fmt.Errorf("site object command requires site runtime %d", want)
		}
	}
	if command.HealthCheck == nil || !validPositiveDuration(command.HealthCheck.ActivationTimeoutDuration) || !validPositiveDuration(command.HealthCheck.ObservationWindowDuration) || command.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return fmt.Errorf("command health check policy is invalid")
	}
	if command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil {
		return fmt.Errorf("command deadline is invalid")
	}
	return nil
}

// deploymentCommandRequiresSiteRuntime: the command requires a site runtime
// capability.
func deploymentCommandRequiresSiteRuntime(command *agentv1.DeploymentCommand) bool {
	for _, capability := range command.RequiredCapabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			return true
		}
	}
	return false
}

// deploymentCommandUsesSiteObjects: a dynamic routing release, delivered as
// a signed root plus a key envelope (ADR 0009 §8.3).
func deploymentCommandUsesSiteObjects(command *agentv1.DeploymentCommand) bool {
	for _, artifact := range command.Artifacts {
		if artifact != nil && (siteObjectRootMediaType(artifact.MediaType) || artifact.MediaType == siteobject.KeyMediaType) {
			return true
		}
	}
	return false
}

// siteObjectRootMediaType: a site runtime v8 (v1) or dynamic routing (v2) root.
func siteObjectRootMediaType(mediaType string) bool {
	return mediaType == siteobject.RootMediaTypeV2
}

func deploymentCommandUsesURLAuth(command *agentv1.DeploymentCommand) bool {
	for _, artifact := range command.Artifacts {
		if artifact != nil && artifact.MediaType == urlAuthArtifactMediaType {
			return true
		}
	}
	return false
}

func deploymentCommandUsesErrorPage(command *agentv1.DeploymentCommand) bool {
	for _, artifact := range command.Artifacts {
		if artifact != nil && artifact.MediaType == ErrorPageArtifactMediaType {
			return true
		}
	}
	return false
}

func (g *Gateway) validateArtifactDescriptor(artifact *agentv1.ArtifactDescriptor, artifactEncryptionKeyID string) error {
	if artifact == nil {
		return fmt.Errorf("command artifact is required")
	}
	if err := g.validateUUID("command.artifact.artifact_id", artifact.ArtifactId); err != nil {
		return err
	}
	if artifact.Kind < agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || artifact.Kind > agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE || artifact.SizeBytes == 0 || artifact.SizeBytes > g.config.MaxArtifactBytes || artifact.SizeBytes > math.MaxInt64 || len(artifact.Sha256) != 32 || len(artifact.Signature) == 0 {
		return fmt.Errorf("command artifact integrity metadata is invalid")
	}
	if err := g.validateIdentifier("command.artifact.signing_key_id", artifact.SigningKeyId, true); err != nil {
		return err
	}
	if artifact.SignatureAlgorithm < agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 || artifact.SignatureAlgorithm > agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 {
		return fmt.Errorf("command artifact signature algorithm is invalid")
	}
	if artifact.Compression < agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE || artifact.Compression > agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD {
		return fmt.Errorf("command artifact compression is invalid")
	}
	if err := g.validateIdentifier("command.artifact.media_type", artifact.MediaType, true); err != nil {
		return err
	}
	switch artifact.EncryptionAlgorithm {
	case agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE:
		if artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || artifact.RecipientKeyId != nil {
			return fmt.Errorf("command plaintext artifact binding is invalid")
		}
	case agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM:
		if artifact.SizeBytes < minimumHPKEArtifactBytes || artifact.RecipientKeyId == nil {
			return fmt.Errorf("command encrypted artifact binding is invalid")
		}
		if err := g.validateIdentifier("session.artifact_encryption_key_id", artifactEncryptionKeyID, true); err != nil {
			return err
		}
		if err := g.validateIdentifier("command.artifact.recipient_key_id", artifact.GetRecipientKeyId(), true); err != nil {
			return err
		}
		if artifact.GetRecipientKeyId() != artifactEncryptionKeyID {
			return fmt.Errorf("command artifact recipient does not match the Agent session")
		}
	default:
		return fmt.Errorf("command artifact encryption is invalid")
	}
	return nil
}

// validateDeploymentStatus takes (activeIdentityEnabled, multiTenantEnabled).
func (g *Gateway) validateDeploymentStatus(status *agentv1.DeploymentStatus, activeIdentityCapability ...bool) error {
	activeIdentityEnabled := len(activeIdentityCapability) >= 1 && activeIdentityCapability[0]
	multiTenantEnabled := activeIdentityEnabled && len(activeIdentityCapability) >= 2 && activeIdentityCapability[1]
	if status == nil || proto.Size(status) > g.config.MaxReceiveMessageBytes {
		return fmt.Errorf("deployment status is missing or exceeds its size limit")
	}
	if err := g.validateEventMetadata(status.Event); err != nil {
		return err
	}
	if status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("deployment status event time is invalid")
	}
	if err := g.validateUUID("deployment_status.deployment_id", status.DeploymentId); err != nil {
		return err
	}
	if status.Attempt == 0 {
		return fmt.Errorf("deployment status attempt must be positive")
	}
	if activeIdentityEnabled {
		if err := g.validateUUID("deployment_status.config_version_id", status.ConfigVersionId); err != nil {
			return err
		}
	} else if err := g.validateIdentifier("deployment_status.config_version_id", status.ConfigVersionId, true); err != nil {
		return err
	}
	if _, known := agentv1.NodeDeploymentState_name[int32(status.State)]; !known || status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_UNSPECIFIED {
		return fmt.Errorf("deployment status state is invalid")
	}
	if status.TransitionSequence == 0 {
		return fmt.Errorf("deployment status transition sequence must be positive")
	}
	if status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED && !status.RunningConfigUnchanged {
		return fmt.Errorf("failed deployment status must preserve the running configuration")
	}
	if len(status.Checks) > g.config.MaxDeploymentChecks {
		return fmt.Errorf("deployment status checks exceed their size limit")
	}
	checkNames := make(map[string]struct{}, len(status.Checks))
	for _, check := range status.Checks {
		if check == nil || g.validateIdentifier("deployment_status.check.name", check.Name, true) != nil || len(check.Summary) > g.config.MaxEventMetadataBytes || !validNonNegativeDuration(check.LatencyDuration) {
			return fmt.Errorf("deployment status check is invalid")
		}
		if _, exists := checkNames[check.Name]; exists {
			return fmt.Errorf("deployment status check names must be unique")
		}
		checkNames[check.Name] = struct{}{}
	}
	if status.Error != nil {
		if err := g.validateProtocolError(status.Error); err != nil {
			return err
		}
	}
	if (status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED) && status.Error == nil {
		return fmt.Errorf("failed deployment status requires a protocol error")
	}
	if err := g.validateDeploymentStatusScope(status, multiTenantEnabled); err != nil {
		return err
	}
	return g.validateDeploymentStatusActiveConfigIdentity(status, activeIdentityEnabled)
}

func (g *Gateway) validateProtocolError(protocolError *commonv1.ProtocolError) error {
	if protocolError.Code == commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED || protocolError.Message == "" || len(protocolError.Message) > g.config.MaxEventMetadataBytes || !validNonNegativeDuration(protocolError.RetryAfterDuration) {
		return fmt.Errorf("deployment status protocol error is invalid")
	}
	if _, known := commonv1.ErrorCode_name[int32(protocolError.Code)]; !known || len(protocolError.FieldViolations) > g.config.MaxDeploymentChecks {
		return fmt.Errorf("deployment status protocol error is invalid")
	}
	for _, violation := range protocolError.FieldViolations {
		if violation == nil || g.validateIdentifier("deployment_status.error.field", violation.Field, true) != nil || violation.Description == "" || len(violation.Description) > g.config.MaxEventMetadataBytes {
			return fmt.Errorf("deployment status field violation is invalid")
		}
	}
	return nil
}

func validPositiveDuration(duration *durationpb.Duration) bool {
	return duration != nil && duration.CheckValid() == nil && duration.AsDuration() > 0
}

func validNonNegativeDuration(duration *durationpb.Duration) bool {
	return duration == nil || (duration.CheckValid() == nil && duration.AsDuration() >= 0)
}

func validateVersionRange(versionRange *commonv1.ProtocolVersionRange) error {
	if versionRange == nil || versionRange.Minimum == nil || versionRange.Maximum == nil {
		return fmt.Errorf("minimum and maximum versions are required")
	}
	if versionRange.Minimum.Major == 0 || versionRange.Maximum.Major == 0 {
		return fmt.Errorf("protocol major version must be positive")
	}
	if compareVersions(versionRange.Minimum, versionRange.Maximum) > 0 {
		return fmt.Errorf("minimum version exceeds maximum version")
	}
	return nil
}

func compareVersions(left, right *commonv1.ProtocolVersion) int {
	if left.Major < right.Major {
		return -1
	}
	if left.Major > right.Major {
		return 1
	}
	if left.Minor < right.Minor {
		return -1
	}
	if left.Minor > right.Minor {
		return 1
	}
	return 0
}

func negotiateVersion(ranges ...*commonv1.ProtocolVersionRange) (*commonv1.ProtocolVersion, bool) {
	if len(ranges) == 0 {
		return nil, false
	}
	var minimum, maximum *commonv1.ProtocolVersion
	for _, versionRange := range ranges {
		if validateVersionRange(versionRange) != nil {
			return nil, false
		}
		if minimum == nil || compareVersions(versionRange.Minimum, minimum) > 0 {
			minimum = versionRange.Minimum
		}
		if maximum == nil || compareVersions(versionRange.Maximum, maximum) < 0 {
			maximum = versionRange.Maximum
		}
	}
	if compareVersions(minimum, maximum) > 0 {
		return nil, false
	}
	return &commonv1.ProtocolVersion{Major: maximum.Major, Minor: maximum.Minor}, true
}

func (g *Gateway) validateIdentifier(name, value string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	if len(value) > g.config.MaxIdentifierBytes {
		return fmt.Errorf("%s exceeds its size limit", name)
	}
	return nil
}

func (g *Gateway) validateUUID(name, value string) error {
	if err := g.validateIdentifier(name, value, true); err != nil {
		return err
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return fmt.Errorf("%s must be a canonical UUID", name)
	}
	return nil
}

func (g *Gateway) validateRequestMetadata(metadata *commonv1.RequestMetadata) error {
	if metadata == nil || proto.Size(metadata) > g.config.MaxRequestMetadataBytes {
		return fmt.Errorf("request metadata is missing or exceeds its size limit")
	}
	if err := g.validateUUID("request.request_id", metadata.RequestId); err != nil {
		return err
	}
	if err := g.validateIdentifier("request.traceparent", metadata.Traceparent, false); err != nil {
		return err
	}
	return g.validateIdentifier("request.correlation_id", metadata.CorrelationId, false)
}

func (g *Gateway) validateEventMetadata(metadata *commonv1.EventMetadata) error {
	if metadata == nil || proto.Size(metadata) > g.config.MaxEventMetadataBytes {
		return fmt.Errorf("event metadata is missing or exceeds its size limit")
	}
	if err := g.validateUUID("event.event_id", metadata.EventId); err != nil {
		return err
	}
	if err := g.validateUUID("event.request_id", metadata.RequestId); err != nil {
		return err
	}
	if err := g.validateIdentifier("event.traceparent", metadata.Traceparent, false); err != nil {
		return err
	}
	if metadata.CausationId != nil {
		if err := g.validateUUID("event.causation_id", metadata.GetCausationId()); err != nil {
			return err
		}
	}
	if err := g.validateIdentifier("event.correlation_id", metadata.CorrelationId, false); err != nil {
		return err
	}
	if metadata.TaskId != nil {
		return g.validateIdentifier("event.task_id", metadata.GetTaskId(), true)
	}
	return nil
}

func (g *Gateway) validateStreamMetadata(metadata *commonv1.StreamMetadata) error {
	if metadata == nil {
		return fmt.Errorf("stream metadata is required")
	}
	if err := g.validateUUID("stream.message_id", metadata.MessageId); err != nil {
		return err
	}
	return g.validateIdentifier("stream.traceparent", metadata.Traceparent, false)
}

// validNativeRuntimeStatus: EdgeRuntimeStatus.native_runtime (node-runtime-
// upgrade) is absent or a known state with lowercase sha256 releases and an
// error code only after ROLLED_BACK.
func validNativeRuntimeStatus(status *agentv1.NativeRuntimeStatus) bool {
	if status == nil {
		return true
	}
	if _, known := agentv1.NativeRuntimeState_name[int32(status.State)]; !known ||
		status.State == agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNSPECIFIED {
		return false
	}
	for _, release := range []string{status.Release, status.PreviousRelease} {
		if release != "" && !lowerHexDigest(release) {
			return false
		}
	}
	if status.ErrorCode == "" {
		return true
	}
	if status.State != agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK || len(status.ErrorCode) > 64 ||
		status.ErrorCode[0] < 'A' || status.ErrorCode[0] > 'Z' {
		return false
	}
	for _, character := range status.ErrorCode {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
