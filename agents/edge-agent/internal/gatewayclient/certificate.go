package gatewayclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	CertificateArtifactMediaType     = "application/vnd.cdnca.edge-certificate-bundle+json;version=1"
	CertificateArtifactSchemaVersion = "cdnca.edge.certificate-artifact/v1"
)

var (
	ErrInvalidCertificateArtifact = errors.New("invalid certificate artifact")
	ErrInvalidCertificateResult   = errors.New("invalid certificate activation result")
)

type CertificateConsumer interface {
	ApplyWithActivation(context.Context, certstore.Bundle, certstore.ActivationMetadata) (certstore.Result, error)
}

type ClientOption func(*Client) error

func WithCertificateConsumer(consumer CertificateConsumer) ClientOption {
	return func(client *Client) error {
		if consumer == nil {
			return fmt.Errorf("%w: certificate consumer is required", ErrInvalidConfiguration)
		}
		client.certificate = consumer
		return nil
	}
}

func isCertificateCommand(command *agentv1.DeploymentCommand) bool {
	return command != nil && command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && len(command.Artifacts) == 1 &&
		command.Artifacts[0] != nil && command.Artifacts[0].Kind == agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE &&
		command.Artifacts[0].MediaType == CertificateArtifactMediaType
}

func validateRoutedCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	if isSiteObjectCommand(command) {
		return validateSiteObjectCommand(command, config, now)
	}
	if isCertificateCommand(command) {
		return validateCertificateCommand(command, config, now)
	}
	// A configuration release is a site object root (dynamic routing); the
	// whole site runtime bundle and the config-source v1 bundle are no
	// longer accepted.
	if command != nil && command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK {
		return fmt.Errorf("%w: configuration bundle is not supported (site objects only)", ErrUnsupportedCommand)
	}
	return validateCommand(command, config, now)
}

func validateCertificateCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	if !isCertificateCommand(command) {
		return fmt.Errorf("%w: unsupported certificate artifact set", ErrUnsupportedCommand)
	}
	descriptor := command.Artifacts[0]
	if descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
		return fmt.Errorf("%w: certificate artifact must use HPKE", ErrInvalidMessage)
	}
	validationCopy := proto.Clone(command).(*agentv1.DeploymentCommand)
	validationCopy.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
	validationCopy.Artifacts[0].MediaType = ConfigurationBundleMediaType
	return validateCommand(validationCopy, config, now)
}

func validateCertificateBinding(document certificateArtifactDocument, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor) error {
	activation := document.Activation
	if document.SchemaVersion != CertificateArtifactSchemaVersion || activation.SchemaVersion != certstore.ActivationSchemaVersion ||
		activation.ConfigVersionID != command.ConfigVersionId || activation.RecipientKeyID != descriptor.GetRecipientKeyId() ||
		activation.CommandEventID != command.Event.EventId || activation.DeploymentID != command.DeploymentId ||
		activation.Attempt != command.Attempt || activation.ArtifactID != descriptor.ArtifactId {
		return ErrInvalidCertificateArtifact
	}
	for _, revision := range activation.Certificates {
		hasVersionIdentity := revision.TenantScopeID != "" || revision.CertificateVersionID != ""
		if !hasVersionIdentity {
			continue
		}
		scopeID, scopeErr := uuid.Parse(revision.TenantScopeID)
		versionID, versionErr := uuid.Parse(revision.CertificateVersionID)
		if scopeErr != nil || versionErr != nil || scopeID == uuid.Nil || versionID == uuid.Nil ||
			scopeID.String() != revision.TenantScopeID || versionID.String() != revision.CertificateVersionID {
			return ErrInvalidCertificateArtifact
		}
	}
	return nil
}

func (c *Client) executeCertificateRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, record *durableRecord, command *agentv1.DeploymentCommand, maximumChunkBytes uint32) error {
	if c.certificate == nil {
		return c.finishCertificateFailure(record.RecordKey, command, ErrUnsupportedCommand, true)
	}
	descriptor := command.Artifacts[0]
	if record.ArtifactOffset > descriptor.SizeBytes {
		return c.finishCertificateFailure(record.RecordKey, command, ErrArtifactIntegrity, true)
	}
	document, err := fetchCertificateArtifact(ctx, gateway, c.store, record, command, descriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		commandExpired := errors.Is(err, context.DeadlineExceeded) && !c.now().Before(command.DeadlineTime.AsTime())
		if ctx.Err() != nil || !isCertificateCandidateError(err) && !commandExpired {
			return err
		}
		return c.finishCertificateFailure(record.RecordKey, command, err, true)
	}
	defer clearCertificateDocument(&document)
	result, err := c.certificate.ApplyWithActivation(ctx, document.Bundle, document.Activation)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return c.finishCertificateFailure(record.RecordKey, command, err, certificateRunningUnchanged(err, result))
	}
	if !validCertificateSuccessResult(document.Bundle, result) {
		return c.finishCertificateFailure(record.RecordKey, command, ErrInvalidCertificateResult, false)
	}
	return c.store.appendStatuses(record.RecordKey, certificateSuccessStatuses(command, result, c.now()), true)
}

func validCertificateSuccessResult(bundle certstore.Bundle, result certstore.Result) bool {
	digest, err := hex.DecodeString(result.Digest)
	return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == result.Digest &&
		result.VersionID == bundle.VersionID && result.ActiveVersionID == bundle.VersionID &&
		result.ActiveDigest == result.Digest && result.Changed != result.RunningVersionUnchanged &&
		result.ErrorCode == "" && !result.AppliedAt.IsZero()
}

func certificateRunningUnchanged(err error, result certstore.Result) bool {
	if errors.Is(err, certstore.ErrRollback) {
		return false
	}
	if isCertificateCandidateError(err) {
		return true
	}
	return result.RunningVersionUnchanged
}

func (c *Client) finishCertificateFailure(key string, command *agentv1.DeploymentCommand, err error, unchanged bool) error {
	code, summary := classifyCertificateError(err)
	status := failedStatus(command, 2, c.now(), code, summary, false)
	status.RunningConfigUnchanged = unchanged
	return c.store.appendStatuses(key, []*agentv1.DeploymentStatus{status}, true)
}

func isCertificateCandidateError(err error) bool {
	return errors.Is(err, ErrArtifactIntegrity) || errors.Is(err, ErrInvalidCertificateArtifact) ||
		errors.Is(err, certstore.ErrInvalidBundle) || errors.Is(err, certstore.ErrConflict) ||
		errors.Is(err, certstore.ErrStaleActivation) || errors.Is(err, certstore.ErrPrecheck) ||
		errors.Is(err, certstore.ErrActivation) || errors.Is(err, certstore.ErrHealth) ||
		errors.Is(err, certstore.ErrRollback) || errors.Is(err, certstore.ErrUnsafeState)
}

func classifyCertificateError(err error) (commonv1.ErrorCode, string) {
	switch {
	case errors.Is(err, ErrArtifactIntegrity):
		return commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH, "certificate artifact integrity check failed"
	case errors.Is(err, certstore.ErrStaleActivation):
		return commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT, "certificate version is stale"
	case errors.Is(err, certstore.ErrConflict):
		return commonv1.ErrorCode_ERROR_CODE_CONFLICT, "certificate version conflicts with immutable state"
	case errors.Is(err, ErrInvalidCertificateArtifact), errors.Is(err, certstore.ErrInvalidBundle):
		return commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "certificate artifact was rejected"
	case errors.Is(err, ErrInvalidCertificateResult):
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL, "certificate activation result was invalid"
	case errors.Is(err, certstore.ErrPrecheck), errors.Is(err, certstore.ErrActivation), errors.Is(err, certstore.ErrHealth):
		return commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "certificate activation failed"
	case errors.Is(err, context.DeadlineExceeded):
		return commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED, "certificate command deadline expired"
	case errors.Is(err, ErrUnsupportedCommand):
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "certificate consumer is unavailable"
	default:
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL, "certificate operation failed"
	}
}

func certificateSuccessStatuses(command *agentv1.DeploymentCommand, result certstore.Result, now time.Time) []*agentv1.DeploymentStatus {
	at := result.AppliedAt
	if at.IsZero() {
		at = now
	}
	unchanged := !result.Changed
	return []*agentv1.DeploymentStatus{
		statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, at, unchanged, "CERTIFICATE_STAGED", "certificate artifact staged", 0),
		statusFor(command, 3, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, at, unchanged, "CERTIFICATE_PRECHECKED", "certificate precheck passed", 0),
		statusFor(command, 4, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, at, unchanged, "CERTIFICATE_ACTIVATED", "certificate version activated", 0),
		statusFor(command, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, at, unchanged, "CERTIFICATE_HEALTHY", "certificate version is healthy", 0),
	}
}

func clearCertificateDocument(document *certificateArtifactDocument) {
	if document == nil {
		return
	}
	for index := range document.Bundle.Bindings {
		document.Bundle.Bindings[index].CertificateChainPEM = ""
		document.Bundle.Bindings[index].PrivateKeyPEM = ""
	}
	document.Bundle.Bindings = nil
	document.Activation.Certificates = nil
}
