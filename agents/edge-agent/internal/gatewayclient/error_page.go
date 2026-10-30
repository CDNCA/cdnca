package gatewayclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/errorpage"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ErrorPageArtifactMediaType = errorpage.ProductionSnapshotMediaType

var ErrInvalidErrorPageArtifact = errors.New("invalid error page artifact")

type ErrorPageArtifactConsumer interface {
	Install(context.Context, errorpage.SignedProductionSnapshot, errorpage.ProductionSnapshotBinding) (errorpage.ProductionSnapshotActivationReceipt, error)
	Reconcile(context.Context) (errorpage.ReconcileReceipt, error)
}

type errorPageTrustResolver struct {
	trust *TrustStore
}

func (resolver errorPageTrustResolver) ResolveProductionBundleKey(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	key, found := resolver.trust.key(keyID)
	publicKey, valid := key.(ed25519.PublicKey)
	if !found || !valid || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrArtifactIntegrity
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func NewErrorPageArtifactConsumer(publisher *errorpage.Publisher, trust *TrustStore) (ErrorPageArtifactConsumer, error) {
	if publisher == nil || trust == nil {
		return nil, ErrInvalidConfiguration
	}
	consumer, err := errorpage.NewProductionSnapshotInstaller(publisher, errorPageTrustResolver{trust: trust})
	if err != nil {
		return nil, fmt.Errorf("%w: configure error page artifact consumer", ErrInvalidConfiguration)
	}
	return consumer, nil
}

func WithErrorPageArtifactConsumer(consumer ErrorPageArtifactConsumer) ClientOption {
	return func(client *Client) error {
		if consumer == nil {
			return fmt.Errorf("%w: error page artifact consumer is required", ErrInvalidConfiguration)
		}
		reconcileCtx, cancel := context.WithTimeout(context.Background(), client.config.FetchTimeout)
		defer cancel()
		if _, err := consumer.Reconcile(reconcileCtx); err != nil {
			return fmt.Errorf("%w: reconcile error page artifact state", ErrInvalidConfiguration)
		}
		client.errorPage = consumer
		return nil
	}
}

func isErrorPageCommand(command *agentv1.DeploymentCommand) bool {
	return command != nil && command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && len(command.Artifacts) == 1 &&
		command.Artifacts[0] != nil && command.Artifacts[0].Kind == agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION &&
		command.Artifacts[0].MediaType == ErrorPageArtifactMediaType
}

func validateErrorPageRoutedCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	if !isErrorPageCommand(command) {
		return validateURLAuthRoutedCommand(command, config, now)
	}
	descriptor := command.Artifacts[0]
	if command.ConfigurationScopeId == nil || !canonicalUUID(command.GetConfigurationScopeId()) ||
		descriptor.SizeBytes == 0 || descriptor.SizeBytes > config.MaxArtifactBytes || len(descriptor.Sha256) != sha256.Size ||
		len(descriptor.Signature) != ed25519.SignatureSize || !safeIdentifier(descriptor.SigningKeyId) ||
		descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
		descriptor.RecipientKeyId != nil {
		return fmt.Errorf("%w: invalid error page artifact transport", ErrInvalidMessage)
	}
	validationCopy := proto.Clone(command).(*agentv1.DeploymentCommand)
	validationCopy.Artifacts[0].MediaType = ConfigurationBundleMediaType
	return validateCommand(validationCopy, config, now)
}

func (c *Client) executeErrorPageRecord(
	ctx context.Context,
	gateway agentv1.AgentGatewayServiceClient,
	record *durableRecord,
	command *agentv1.DeploymentCommand,
	maximumChunkBytes uint32,
) error {
	if c.errorPage == nil {
		return c.finishErrorPageFailure(record.RecordKey, command, errorpage.ProductionSnapshotActivationReceipt{}, ErrUnsupportedCommand)
	}
	descriptor := command.Artifacts[0]
	if record.ArtifactOffset > descriptor.SizeBytes {
		return c.finishErrorPageFailure(record.RecordKey, command, errorpage.ProductionSnapshotActivationReceipt{}, ErrArtifactIntegrity)
	}
	wire, err := fetchErrorPageArtifact(ctx, gateway, c.store, record, command, descriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		commandExpired := errors.Is(err, context.DeadlineExceeded) && !c.now().Before(command.DeadlineTime.AsTime())
		if ctx.Err() != nil || !isErrorPageCandidateError(err) && !commandExpired {
			return err
		}
		return c.finishErrorPageFailure(record.RecordKey, command, errorpage.ProductionSnapshotActivationReceipt{}, err)
	}
	binding, err := errorpage.DecodeProductionSnapshotBinding(wire)
	if err != nil {
		return c.finishErrorPageFailure(record.RecordKey, command, errorpage.ProductionSnapshotActivationReceipt{}, err)
	}
	digest := sha256.Sum256(wire)
	configID, artifactID := errorPageCommandIdentity(command.GetConfigurationScopeId(), binding, digest)
	if command.ConfigVersionId != configID || descriptor.ArtifactId != artifactID {
		return c.finishErrorPageFailure(record.RecordKey, command, errorpage.ProductionSnapshotActivationReceipt{Binding: binding}, ErrArtifactIntegrity)
	}
	receipt, err := c.errorPage.Install(ctx, errorpage.SignedProductionSnapshot{
		WireBytes: bytes.Clone(wire), SHA256: hex.EncodeToString(digest[:]),
		Signature: bytes.Clone(descriptor.Signature), SigningKeyID: descriptor.SigningKeyId,
	}, binding)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return c.finishErrorPageFailure(record.RecordKey, command, receipt, err)
	}
	if receipt.Schema != errorpage.ProductionSnapshotActivationReceiptSchema || receipt.State != errorpage.ActivationStateActivated ||
		receipt.Binding != binding || receipt.BundleSHA256 != hex.EncodeToString(digest[:]) || receipt.ActiveDigest == "" ||
		receipt.ReasonCode != "" {
		return c.finishErrorPageFailure(record.RecordKey, command, receipt, ErrInvalidErrorPageArtifact)
	}
	return c.store.appendStatuses(record.RecordKey, errorPageSuccessStatuses(command, c.now(), receipt.RunningConfigUnchanged), true)
}

func fetchErrorPageArtifact(
	ctx context.Context,
	client agentv1.AgentGatewayServiceClient,
	store *durableStore,
	record *durableRecord,
	command *agentv1.DeploymentCommand,
	descriptor *agentv1.ArtifactDescriptor,
	maximumChunkBytes uint32,
	config Config,
	trust *TrustStore,
	now func() time.Time,
) ([]byte, error) {
	file, err := store.openArtifact(record.RecordKey, record.ArtifactOffset)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	offset := record.ArtifactOffset
	for offset < descriptor.SizeBytes {
		requestID := uuid.NewString()
		fetchCtx, cancel := context.WithTimeout(ctx, config.FetchTimeout)
		stream, err := client.FetchArtifact(fetchCtx, &agentv1.FetchArtifactRequest{
			Request: &commonv1.RequestMetadata{
				RequestId: requestID, SentTime: timestamppb.New(now().UTC()), Traceparent: command.Event.Traceparent,
				CorrelationId: command.Event.CorrelationId, TaskId: command.Event.TaskId,
			},
			EventId: command.Event.EventId, DeploymentId: command.DeploymentId, Attempt: command.Attempt,
			ArtifactId: descriptor.ArtifactId, Offset: offset,
		})
		if err != nil {
			cancel()
			return nil, err
		}
		startOffset := offset
		ended := false
		for {
			response, receiveErr := stream.Recv()
			if errors.Is(receiveErr, io.EOF) {
				break
			}
			if receiveErr != nil {
				cancel()
				return nil, receiveErr
			}
			chunk := response.GetChunk()
			if err := validateArtifactChunk(chunk, requestID, descriptor, offset, maximumChunkBytes); err != nil {
				cancel()
				return nil, err
			}
			written, err := file.Write(chunk.Data)
			if err != nil || written != len(chunk.Data) {
				cancel()
				if err == nil {
					err = io.ErrShortWrite
				}
				return nil, fmt.Errorf("write error page artifact: %w", err)
			}
			if err := file.Sync(); err != nil {
				cancel()
				return nil, fmt.Errorf("sync error page artifact: %w", err)
			}
			offset += uint64(len(chunk.Data))
			if err := store.setArtifactOffset(record.RecordKey, offset); err != nil {
				cancel()
				return nil, err
			}
			if chunk.EndOfArtifact {
				ended = true
				break
			}
		}
		cancel()
		if ended {
			if offset != descriptor.SizeBytes {
				return nil, fmt.Errorf("%w: error page artifact ended at an unexpected offset", ErrArtifactIntegrity)
			}
			break
		}
		if offset == startOffset {
			return nil, errors.New("error page artifact stream ended without progress")
		}
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close error page artifact: %w", err)
	}
	wire, err := store.readArtifact(record.RecordKey, descriptor.SizeBytes)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(wire)
	if !bytes.Equal(digest[:], descriptor.Sha256) {
		return nil, fmt.Errorf("%w: error page artifact digest mismatch", ErrArtifactIntegrity)
	}
	if err := verifyArtifactSignature(descriptor, wire, trust); err != nil {
		return nil, err
	}
	if _, err := errorpage.DecodeProductionSnapshotBinding(wire); err != nil {
		return nil, ErrInvalidErrorPageArtifact
	}
	return wire, nil
}

func errorPageCommandIdentity(
	configurationScopeID string,
	binding errorpage.ProductionSnapshotBinding,
	digest [sha256.Size]byte,
) (string, string) {
	scopeID, scopeErr := uuid.Parse(configurationScopeID)
	bindingScopeID, bindingScopeErr := uuid.Parse(binding.ConfigurationScopeID)
	tenantID, tenantErr := uuid.Parse(binding.TenantID)
	if scopeErr != nil || bindingScopeErr != nil || tenantErr != nil || scopeID == uuid.Nil || tenantID == uuid.Nil ||
		scopeID.String() != configurationScopeID || bindingScopeID != scopeID || binding.PublicationRevision == 0 {
		return "", ""
	}
	identity := []byte("cdnca.error-page.snapshot.config/v1\x00" + binding.TenantID + "\x00" + binding.ConfigurationScopeID + "\x00" +
		fmt.Sprint(binding.PublicationRevision) + "\x00" + hex.EncodeToString(digest[:]))
	configID := uuid.NewSHA1(scopeID, identity)
	artifactID := uuid.NewSHA1(configID, append([]byte("cdnca.error-page.snapshot.artifact/v1\x00"), digest[:]...))
	return configID.String(), artifactID.String()
}

func (c *Client) finishErrorPageFailure(
	key string,
	command *agentv1.DeploymentCommand,
	receipt errorpage.ProductionSnapshotActivationReceipt,
	err error,
) error {
	code, summary := classifyErrorPageError(receipt, err)
	status := failedStatus(command, 2, c.now(), code, summary, false)
	status.RunningConfigUnchanged = true
	return c.store.appendStatuses(key, []*agentv1.DeploymentStatus{status}, true)
}

func isErrorPageCandidateError(err error) bool {
	return errors.Is(err, ErrArtifactIntegrity) || errors.Is(err, ErrInvalidErrorPageArtifact) ||
		errors.Is(err, errorpage.ErrInvalidProductionBundle) || errors.Is(err, ErrUnsupportedCommand)
}

func classifyErrorPageError(receipt errorpage.ProductionSnapshotActivationReceipt, err error) (commonv1.ErrorCode, string) {
	switch {
	case errors.Is(err, ErrArtifactIntegrity) || receipt.ReasonCode == errorpage.ActivationReasonBundleIntegrity:
		return commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH, "error page artifact integrity check failed"
	case receipt.ReasonCode == errorpage.ActivationReasonBindingMismatch:
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "error page artifact binding mismatch"
	case errors.Is(err, errorpage.ErrInvalidProductionBundle), errors.Is(err, ErrInvalidErrorPageArtifact),
		receipt.ReasonCode == errorpage.ActivationReasonPayloadInvalid:
		return commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "error page artifact was rejected"
	case errors.Is(err, context.DeadlineExceeded):
		return commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED, "error page command deadline expired"
	case errors.Is(err, ErrUnsupportedCommand):
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "error page consumer is unavailable"
	case receipt.ReasonCode != "":
		return commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "error page activation failed: " + receipt.ReasonCode
	default:
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL, "error page operation failed"
	}
}

func errorPageSuccessStatuses(command *agentv1.DeploymentCommand, at time.Time, unchanged bool) []*agentv1.DeploymentStatus {
	return []*agentv1.DeploymentStatus{
		statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, at, true, "ERROR_PAGE_STAGED", "error page artifact staged", 0),
		statusFor(command, 3, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, at, true, "ERROR_PAGE_PRECHECKED", "error page artifact verified", 0),
		statusFor(command, 4, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, at, unchanged, "ERROR_PAGE_ACTIVATED", "error page policy activated", 0),
		statusFor(command, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, at, unchanged, "ERROR_PAGE_HEALTHY", "error page policy is healthy", 0),
	}
}
