package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

const URLAuthArtifactMediaType = "application/vnd.cdnca.edge-url-auth-bundle+json;version=1"

var ErrInvalidURLAuthArtifact = errors.New("invalid URL auth artifact")

type URLAuthArtifactConsumer interface {
	InstallJSON([]byte, urlauth.ArtifactBinding) (urlauth.Publication, error)
}

func WithURLAuthArtifactConsumer(consumer URLAuthArtifactConsumer) ClientOption {
	return func(client *Client) error {
		if consumer == nil {
			return fmt.Errorf("%w: URL auth artifact consumer is required", ErrInvalidConfiguration)
		}
		client.urlAuth = consumer
		return nil
	}
}

func isURLAuthCommand(command *agentv1.DeploymentCommand) bool {
	return command != nil && command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && len(command.Artifacts) == 1 &&
		command.Artifacts[0] != nil && command.Artifacts[0].Kind == agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE &&
		command.Artifacts[0].MediaType == URLAuthArtifactMediaType
}

func validateURLAuthRoutedCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	if !isURLAuthCommand(command) {
		return validateOriginAuthRoutedCommand(command, config, now)
	}
	descriptor := command.Artifacts[0]
	if command.ConfigurationScopeId == nil || !canonicalUUID(command.GetConfigurationScopeId()) ||
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
		return fmt.Errorf("%w: invalid URL auth artifact transport", ErrInvalidMessage)
	}
	validationCopy := proto.Clone(command).(*agentv1.DeploymentCommand)
	validationCopy.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
	validationCopy.Artifacts[0].MediaType = ConfigurationBundleMediaType
	return validateCommand(validationCopy, config, now)
}

func applyURLAuthArtifact(raw []byte, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, consumer URLAuthArtifactConsumer) (urlauth.Publication, error) {
	if command == nil || command.Event == nil || descriptor == nil || consumer == nil || len(command.Artifacts) != 1 ||
		command.Artifacts[0] == nil || command.Artifacts[0].ArtifactId != descriptor.ArtifactId || command.ConfigurationScopeId == nil ||
		descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE || descriptor.MediaType != URLAuthArtifactMediaType ||
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		descriptor.RecipientKeyId == nil {
		return urlauth.Publication{}, fmt.Errorf("%w: invalid URL auth artifact contract", ErrInvalidMessage)
	}
	binding, err := urlauth.DecodeArtifactBinding(raw)
	if err != nil {
		return urlauth.Publication{}, fmt.Errorf("%w: %v", ErrArtifactIntegrity, err)
	}
	if binding.EventID != command.Event.EventId || binding.DeploymentID != command.DeploymentId || binding.Attempt != command.Attempt ||
		binding.ConfigVersionID != command.ConfigVersionId || binding.ArtifactID != descriptor.ArtifactId ||
		binding.RecipientKeyID != descriptor.GetRecipientKeyId() || !urlAuthScopeMatches(binding, command.GetConfigurationScopeId()) {
		return urlauth.Publication{}, fmt.Errorf("%w: URL auth artifact command binding mismatch", ErrArtifactIntegrity)
	}
	return consumer.InstallJSON(raw, binding)
}

func (c *Client) executeURLAuthRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, record *durableRecord, command *agentv1.DeploymentCommand, maximumChunkBytes uint32) error {
	if c.urlAuth == nil {
		return c.finishURLAuthFailure(record.RecordKey, command, ErrUnsupportedCommand)
	}
	descriptor := command.Artifacts[0]
	if record.ArtifactOffset > descriptor.SizeBytes {
		return c.finishURLAuthFailure(record.RecordKey, command, ErrArtifactIntegrity)
	}
	raw, err := fetchURLAuthArtifact(ctx, gateway, c.store, record, command, descriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		commandExpired := errors.Is(err, context.DeadlineExceeded) && !c.now().Before(command.DeadlineTime.AsTime())
		if ctx.Err() != nil || !isURLAuthCandidateError(err) && !commandExpired {
			return err
		}
		return c.finishURLAuthFailure(record.RecordKey, command, err)
	}
	defer clearPlaintext(raw)
	publication, err := applyURLAuthArtifact(raw, command, descriptor, c.urlAuth)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return c.finishURLAuthFailure(record.RecordKey, command, err)
	}
	binding, err := urlauth.DecodeArtifactBinding(raw)
	if err != nil || publication.PolicyVersion != binding.PolicyVersion || publication.CurrentPath == "" {
		return c.finishURLAuthFailure(record.RecordKey, command, ErrInvalidURLAuthArtifact)
	}
	return c.store.appendStatuses(record.RecordKey, urlAuthSuccessStatuses(command, c.now()), true)
}

func (c *Client) finishURLAuthFailure(key string, command *agentv1.DeploymentCommand, err error) error {
	code, summary := classifyURLAuthError(err)
	status := failedStatus(command, 2, c.now(), code, summary, false)
	status.RunningConfigUnchanged = true
	return c.store.appendStatuses(key, []*agentv1.DeploymentStatus{status}, true)
}

func isURLAuthCandidateError(err error) bool {
	return errors.Is(err, ErrArtifactIntegrity) || errors.Is(err, ErrInvalidURLAuthArtifact) ||
		errors.Is(err, urlauth.ErrInvalidPolicy) || errors.Is(err, ErrUnsupportedCommand)
}

func classifyURLAuthError(err error) (commonv1.ErrorCode, string) {
	switch {
	case errors.Is(err, ErrArtifactIntegrity):
		return commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH, "URL auth artifact integrity check failed"
	case errors.Is(err, urlauth.ErrInvalidPolicy), errors.Is(err, ErrInvalidURLAuthArtifact):
		return commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "URL auth artifact was rejected"
	case errors.Is(err, context.DeadlineExceeded):
		return commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED, "URL auth command deadline expired"
	case errors.Is(err, ErrUnsupportedCommand):
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "URL auth consumer is unavailable"
	default:
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL, "URL auth operation failed"
	}
}

func urlAuthSuccessStatuses(command *agentv1.DeploymentCommand, at time.Time) []*agentv1.DeploymentStatus {
	return []*agentv1.DeploymentStatus{
		statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, at, false, "URL_AUTH_STAGED", "URL auth artifact staged", 0),
		statusFor(command, 3, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, at, false, "URL_AUTH_PRECHECKED", "URL auth artifact verified", 0),
		statusFor(command, 4, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, at, false, "URL_AUTH_INSTALLED", "URL auth policy installed", 0),
		statusFor(command, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, at, false, "URL_AUTH_READY", "URL auth policy is ready", 0),
	}
}

// urlAuthScopeMatches binds the artifact to the command's configuration scope.
// The configuration scope and the tenant are distinct identifiers, so the
// artifact must name its scope explicitly; a tenant id is never accepted in
// its place.
func urlAuthScopeMatches(binding urlauth.ArtifactBinding, commandScopeID string) bool {
	return binding.ConfigurationScopeID != "" && binding.ConfigurationScopeID == commandScopeID
}
