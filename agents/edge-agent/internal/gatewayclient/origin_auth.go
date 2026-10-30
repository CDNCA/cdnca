package gatewayclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/originauth"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

const OriginAuthArtifactMediaType = originauth.ProductionSnapshotMediaType

// OriginAuthArtifactConsumer installs a signed, sealed origin authentication
// snapshot (COS/OSS/S3 origin request signing).
type OriginAuthArtifactConsumer interface {
	Install(context.Context, originauth.EncryptedProductionSnapshot) (originauth.Publication, error)
}

func WithOriginAuthArtifactConsumer(consumer OriginAuthArtifactConsumer) ClientOption {
	return func(client *Client) error {
		if consumer == nil {
			return fmt.Errorf("%w: origin auth artifact consumer is required", ErrInvalidConfiguration)
		}
		client.originAuth = consumer
		return nil
	}
}

func isOriginAuthCommand(command *agentv1.DeploymentCommand) bool {
	return command != nil && command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && len(command.Artifacts) == 1 &&
		command.Artifacts[0] != nil && command.Artifacts[0].Kind == agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE &&
		command.Artifacts[0].MediaType == OriginAuthArtifactMediaType
}

func validateOriginAuthRoutedCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	if !isOriginAuthCommand(command) {
		return validateChallengeRoutedCommand(command, config, now)
	}
	descriptor := command.Artifacts[0]
	if command.ConfigurationScopeId == nil || !canonicalUUID(command.GetConfigurationScopeId()) || command.Attempt != 1 ||
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE || descriptor.RecipientKeyId == nil ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 {
		return fmt.Errorf("%w: invalid origin auth artifact transport", ErrInvalidMessage)
	}
	validationCopy := proto.Clone(command).(*agentv1.DeploymentCommand)
	validationCopy.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
	validationCopy.Artifacts[0].MediaType = ConfigurationBundleMediaType
	return validateCommand(validationCopy, config, now)
}

func (c *Client) executeOriginAuthRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, record *durableRecord, command *agentv1.DeploymentCommand, maximumChunkBytes uint32) error {
	if c.originAuth == nil {
		return c.finishOriginAuthFailure(record.RecordKey, command, ErrUnsupportedCommand)
	}
	descriptor := command.Artifacts[0]
	if record.ArtifactOffset > descriptor.SizeBytes {
		return c.finishOriginAuthFailure(record.RecordKey, command, ErrArtifactIntegrity)
	}
	wire, err := fetchSignedArtifact(ctx, gateway, c.store, record, command, descriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		commandExpired := errors.Is(err, context.DeadlineExceeded) && !c.now().Before(command.DeadlineTime.AsTime())
		if ctx.Err() != nil || !errors.Is(err, ErrArtifactIntegrity) && !commandExpired {
			return err
		}
		return c.finishOriginAuthFailure(record.RecordKey, command, err)
	}
	signingKey, _ := c.trust.key(descriptor.SigningKeyId)
	publicKey, _ := signingKey.(ed25519.PublicKey)
	snapshot := originauth.EncryptedProductionSnapshot{
		ProductionArtifactTransport: originauth.ProductionArtifactTransport{
			EventID: command.Event.EventId, DeploymentID: command.DeploymentId, ConfigVersionID: command.ConfigVersionId,
			ArtifactID: descriptor.ArtifactId, NodeID: c.config.NodeID, RecipientKeyID: descriptor.GetRecipientKeyId(),
			SigningKeyID: descriptor.SigningKeyId, MediaType: descriptor.MediaType, Attempt: command.Attempt, Kind: descriptor.Kind,
			SizeBytes: descriptor.SizeBytes, SHA256: descriptor.Sha256, Signature: descriptor.Signature, SigningPublicKey: publicKey,
			SignatureAlgorithm: descriptor.SignatureAlgorithm, Compression: descriptor.Compression, EncryptionAlgorithm: descriptor.EncryptionAlgorithm,
		},
		WireBytes: wire, RecipientPrivateKey: c.config.ArtifactDecryptionPrivateKey,
		ExpectedNodeID: c.config.NodeID, ExpectedTenantScopeID: command.GetConfigurationScopeId(),
	}
	if _, err := c.originAuth.Install(ctx, snapshot); err != nil {
		if ctx.Err() != nil {
			return err
		}
		return c.finishOriginAuthFailure(record.RecordKey, command, err)
	}
	return c.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{
		statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, c.now(), false, "ORIGIN_AUTH_STAGED", "origin auth artifact staged", 0),
		statusFor(command, 3, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, c.now(), false, "ORIGIN_AUTH_PRECHECKED", "origin auth artifact verified", 0),
		statusFor(command, 4, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, c.now(), false, "ORIGIN_AUTH_INSTALLED", "origin auth policy installed", 0),
		statusFor(command, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, c.now(), false, "ORIGIN_AUTH_READY", "origin auth policy is ready", 0),
	}, true)
}

func (c *Client) finishOriginAuthFailure(key string, command *agentv1.DeploymentCommand, err error) error {
	code, summary := commonv1.ErrorCode_ERROR_CODE_INTERNAL, "origin auth operation failed"
	switch {
	case errors.Is(err, ErrArtifactIntegrity), errors.Is(err, originauth.ErrProductionArtifact):
		code, summary = commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "origin auth artifact was rejected"
	case errors.Is(err, originauth.ErrProductionActivation), errors.Is(err, originauth.ErrProductionRollback):
		code, summary = commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "origin auth policy could not be activated"
	case errors.Is(err, ErrUnsupportedCommand):
		code, summary = commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "origin auth consumer is unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		code, summary = commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED, "origin auth command deadline expired"
	}
	status := failedStatus(command, 2, c.now(), code, summary, false)
	status.RunningConfigUnchanged = true
	return c.store.appendStatuses(key, []*agentv1.DeploymentStatus{status}, true)
}
