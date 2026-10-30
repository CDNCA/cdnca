package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

const ChallengeArtifactMediaType = "application/vnd.cdnca.edge-challenge-bundle+json;version=1"

var ErrInvalidChallengeArtifact = errors.New("invalid challenge artifact")

type ChallengeConsumer interface {
	InstallJSON([]byte, challenge.ArtifactBinding) (challenge.ArtifactResult, error)
}

func WithChallengeConsumer(consumer ChallengeConsumer) ClientOption {
	return func(client *Client) error {
		if consumer == nil {
			return fmt.Errorf("%w: challenge consumer is required", ErrInvalidConfiguration)
		}
		client.challenge = consumer
		return nil
	}
}

func isChallengeCommand(command *agentv1.DeploymentCommand) bool {
	return command != nil && command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && len(command.Artifacts) == 1 &&
		command.Artifacts[0] != nil && command.Artifacts[0].Kind == agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE &&
		command.Artifacts[0].MediaType == ChallengeArtifactMediaType
}

func validateChallengeRoutedCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	if !isChallengeCommand(command) {
		return validateRoutedCommand(command, config, now)
	}
	descriptor := command.Artifacts[0]
	if descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
		return fmt.Errorf("%w: challenge artifact must use HPKE", ErrInvalidMessage)
	}
	validationCopy := proto.Clone(command).(*agentv1.DeploymentCommand)
	validationCopy.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
	validationCopy.Artifacts[0].MediaType = ConfigurationBundleMediaType
	return validateCommand(validationCopy, config, now)
}

func (c *Client) executeChallengeRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, record *durableRecord, command *agentv1.DeploymentCommand, maximumChunkBytes uint32) error {
	if c.challenge == nil {
		return c.finishChallengeFailure(record.RecordKey, command, ErrUnsupportedCommand)
	}
	descriptor := command.Artifacts[0]
	if record.ArtifactOffset > descriptor.SizeBytes {
		return c.finishChallengeFailure(record.RecordKey, command, ErrArtifactIntegrity)
	}
	raw, binding, err := fetchChallengeArtifact(ctx, gateway, c.store, record, command, descriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		commandExpired := errors.Is(err, context.DeadlineExceeded) && !c.now().Before(command.DeadlineTime.AsTime())
		if ctx.Err() != nil || !isChallengeCandidateError(err) && !commandExpired {
			return err
		}
		return c.finishChallengeFailure(record.RecordKey, command, err)
	}
	defer clearPlaintext(raw)
	result, err := c.challenge.InstallJSON(raw, binding)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return c.finishChallengeFailure(record.RecordKey, command, err)
	}
	if result.PolicyID != binding.PolicyID || result.TenantID != binding.TenantID || result.PolicyVersion != binding.PolicyVersion ||
		result.CurrentPath == "" {
		return c.finishChallengeFailure(record.RecordKey, command, ErrInvalidChallengeArtifact)
	}
	return c.store.appendStatuses(record.RecordKey, challengeSuccessStatuses(command, c.now()), true)
}

func (c *Client) finishChallengeFailure(key string, command *agentv1.DeploymentCommand, err error) error {
	code, summary := classifyChallengeError(err)
	status := failedStatus(command, 2, c.now(), code, summary, false)
	status.RunningConfigUnchanged = true
	return c.store.appendStatuses(key, []*agentv1.DeploymentStatus{status}, true)
}

func isChallengeCandidateError(err error) bool {
	return errors.Is(err, ErrArtifactIntegrity) || errors.Is(err, ErrInvalidChallengeArtifact) ||
		errors.Is(err, challenge.ErrInvalidPolicy) || errors.Is(err, ErrUnsupportedCommand)
}

func classifyChallengeError(err error) (commonv1.ErrorCode, string) {
	switch {
	case errors.Is(err, ErrArtifactIntegrity):
		return commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH, "challenge artifact integrity check failed"
	case errors.Is(err, challenge.ErrInvalidPolicy), errors.Is(err, ErrInvalidChallengeArtifact):
		return commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "challenge artifact was rejected"
	case errors.Is(err, context.DeadlineExceeded):
		return commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED, "challenge command deadline expired"
	case errors.Is(err, ErrUnsupportedCommand):
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "challenge consumer is unavailable"
	default:
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL, "challenge operation failed"
	}
}

func challengeSuccessStatuses(command *agentv1.DeploymentCommand, at time.Time) []*agentv1.DeploymentStatus {
	return []*agentv1.DeploymentStatus{
		statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, at, false, "CHALLENGE_STAGED", "challenge artifact staged", 0),
		statusFor(command, 3, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, at, false, "CHALLENGE_PRECHECKED", "challenge artifact verified", 0),
		statusFor(command, 4, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, at, false, "CHALLENGE_INSTALLED", "challenge material installed", 0),
		statusFor(command, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, at, false, "CHALLENGE_READY", "challenge material is ready", 0),
	}
}
