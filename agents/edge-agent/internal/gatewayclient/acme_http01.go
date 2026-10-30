package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/acmehttp01"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ACMEHTTP01OverlayArtifactMediaType = acmehttp01.ArtifactMediaType

func WithACMEHTTP01OverlayConsumer(consumer acmehttp01.Consumer) ClientOption {
	return func(client *Client) error {
		if consumer == nil {
			return fmt.Errorf("%w: ACME HTTP-01 overlay consumer is required", ErrInvalidConfiguration)
		}
		client.acmeHTTP01 = consumer
		return nil
	}
}

func validateACMEHTTP01OverlayCommandIdentity(command *agentv1.AcmeHTTP01OverlayCommand, config Config) error {
	if command == nil || proto.Size(command) > config.MaxCommandBytes {
		return fmt.Errorf("%w: overlay command is missing or too large", ErrInvalidMessage)
	}
	if command.Event == nil || !canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) ||
		!boundedMetadata(command.Event.Traceparent, false) || !boundedMetadata(command.Event.CorrelationId, false) {
		return fmt.Errorf("%w: overlay command event metadata is invalid", ErrInvalidMessage)
	}
	if command.Event.TaskId != nil && !boundedMetadata(command.Event.GetTaskId(), true) {
		return fmt.Errorf("%w: overlay command task metadata is invalid", ErrInvalidMessage)
	}
	if command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil ||
		command.Event.CausationId != nil && !canonicalUUID(command.Event.GetCausationId()) {
		return fmt.Errorf("%w: overlay command event time or causation is invalid", ErrInvalidMessage)
	}
	if !canonicalUUID(command.OverlayDeploymentId) || command.Attempt == 0 ||
		!canonicalUUID(command.OverlayVersionId) || command.OverlayRevision == 0 {
		return fmt.Errorf("%w: overlay command identity is invalid", ErrInvalidMessage)
	}
	if (command.PreviousOverlayVersionId == nil) != (command.PreviousOverlayRevision == nil) {
		return fmt.Errorf("%w: overlay command previous revision is incomplete", ErrInvalidMessage)
	}
	if command.PreviousOverlayVersionId != nil && (!canonicalUUID(command.GetPreviousOverlayVersionId()) ||
		command.GetPreviousOverlayRevision() == 0 || command.GetPreviousOverlayRevision() >= command.OverlayRevision) {
		return fmt.Errorf("%w: overlay command previous revision is invalid", ErrInvalidMessage)
	}
	return nil
}

func (c *Client) validateACMEHTTP01OverlayCommand(command *agentv1.AcmeHTTP01OverlayCommand) error {
	if err := validateACMEHTTP01OverlayCommandIdentity(command, c.config); err != nil {
		return err
	}
	if c.acmeHTTP01 == nil || !c.acmeHTTP01.Ready() {
		return fmt.Errorf("%w: ACME HTTP-01 overlay capability is unavailable", ErrUnsupportedCommand)
	}
	descriptor := command.Artifact
	if descriptor == nil || !canonicalUUID(descriptor.ArtifactId) ||
		descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_ACME_HTTP01_OVERLAY ||
		descriptor.MediaType != ACMEHTTP01OverlayArtifactMediaType || descriptor.SizeBytes == 0 ||
		descriptor.SizeBytes > c.config.MaxArtifactBytes || len(descriptor.Sha256) != sha256.Size ||
		len(descriptor.Signature) == 0 || !safeIdentifier(descriptor.SigningKeyId) ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
		descriptor.RecipientKeyId != nil {
		return fmt.Errorf("%w: overlay artifact descriptor is invalid", ErrInvalidMessage)
	}
	if descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 &&
		descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 {
		return fmt.Errorf("%w: overlay signature algorithm is unsupported", ErrUnsupportedCommand)
	}
	if descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE &&
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD {
		return fmt.Errorf("%w: overlay compression is unsupported", ErrUnsupportedCommand)
	}
	if command.HealthCheck == nil || command.HealthCheck.ActivationTimeoutDuration == nil ||
		command.HealthCheck.ObservationWindowDuration == nil || command.HealthCheck.ActivationTimeoutDuration.CheckValid() != nil ||
		command.HealthCheck.ObservationWindowDuration.CheckValid() != nil ||
		command.HealthCheck.ActivationTimeoutDuration.AsDuration() <= 0 ||
		command.HealthCheck.ObservationWindowDuration.AsDuration() < 0 ||
		command.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return fmt.Errorf("%w: overlay health policy is invalid", ErrInvalidMessage)
	}
	if command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil {
		return fmt.Errorf("%w: overlay command deadline is invalid", ErrInvalidMessage)
	}
	if overlayCommandPurpose(command) == "" {
		return fmt.Errorf("%w: overlay command purpose is invalid", ErrInvalidMessage)
	}
	return nil
}

// overlayCommandPurpose is the consumer purpose of a command, "" when unknown.
func overlayCommandPurpose(command *agentv1.AcmeHTTP01OverlayCommand) string {
	switch command.GetPurpose() {
	case agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_APPLY:
		return acmehttp01.PurposeApply
	case agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY:
		return acmehttp01.PurposeCleanupOnly
	}
	return ""
}

func (c *Client) executeACMEHTTP01OverlayRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, key string, maximumChunkBytes uint32) error {
	record, err := c.overlayStore.record(key)
	if err != nil {
		return err
	}
	if record == nil || record.ExecutionDone {
		return nil
	}
	command := overlayCommandFromBytes(record.Command)
	if command == nil {
		return fmt.Errorf("durable overlay command is corrupt")
	}
	if err := c.validateACMEHTTP01OverlayCommand(command); err != nil {
		return c.finishACMEHTTP01Failure(record.RecordKey, command, acmehttp01.Result{}, err, true)
	}
	if record.ArtifactOffset > command.Artifact.SizeBytes {
		return c.finishACMEHTTP01Failure(record.RecordKey, command, acmehttp01.Result{}, ErrArtifactIntegrity, true)
	}
	expired := !command.DeadlineTime.AsTime().After(c.now())
	if expired && record.ArtifactOffset < command.Artifact.SizeBytes {
		return c.finishACMEHTTP01Failure(record.RecordKey, command, acmehttp01.Result{}, acmehttp01.ErrExpired, true)
	}
	operationBase := ctx
	cancelDeadline := func() {}
	if !expired {
		operationBase, cancelDeadline = context.WithDeadline(ctx, command.DeadlineTime.AsTime())
	}
	defer cancelDeadline()
	operationCtx, cancel := context.WithTimeout(operationBase, command.HealthCheck.ActivationTimeoutDuration.AsDuration())
	defer cancel()
	snapshot, err := fetchACMEHTTP01OverlayArtifact(operationCtx, gateway, c.overlayStore, record, command, maximumChunkBytes, c.config, c.trust, c.now, expired)
	if err != nil {
		if ctx.Err() != nil || !errors.Is(err, ErrArtifactIntegrity) && !errors.Is(err, acmehttp01.ErrInvalidSnapshot) && !errors.Is(err, acmehttp01.ErrExpired) {
			return err
		}
		return c.finishACMEHTTP01Failure(record.RecordKey, command, acmehttp01.Result{}, err, true)
	}
	defer clearACMEHTTP01Snapshot(&snapshot)
	commandDigest := sha256.Sum256(record.Command)
	artifactDigest := [sha256.Size]byte(command.Artifact.Sha256)
	request := acmehttp01.Command{
		DeploymentID: command.OverlayDeploymentId, Attempt: command.Attempt,
		OverlayVersionID: command.OverlayVersionId, OverlayRevision: command.OverlayRevision,
		Purpose:        overlayCommandPurpose(command),
		ArtifactSHA256: artifactDigest, CommandSHA256: commandDigest, Snapshot: snapshot,
		Health: acmehttp01.HealthPolicy{
			ActivationTimeout:            command.HealthCheck.ActivationTimeoutDuration.AsDuration(),
			ObservationWindow:            command.HealthCheck.ObservationWindowDuration.AsDuration(),
			RequiredConsecutiveSuccesses: command.HealthCheck.RequiredConsecutiveSuccesses,
		},
		Deadline: command.DeadlineTime.AsTime(),
	}
	if command.PreviousOverlayVersionId != nil {
		previousVersion := command.GetPreviousOverlayVersionId()
		previousRevision := command.GetPreviousOverlayRevision()
		request.PreviousVersionID = &previousVersion
		request.PreviousRevision = &previousRevision
	}
	result, err := c.acmeHTTP01.Apply(operationCtx, request)
	if err != nil {
		return c.finishACMEHTTP01Failure(record.RecordKey, command, result, err, overlayActiveUnchanged(result))
	}
	return c.overlayStore.appendStatuses(record.RecordKey, acmeHTTP01StatusesForResult(command, result), true)
}

func fetchACMEHTTP01OverlayArtifact(ctx context.Context, client agentv1.AgentGatewayServiceClient, store *overlayDurableStore, record *overlayDurableRecord, command *agentv1.AcmeHTTP01OverlayCommand, maximumChunkBytes uint32, config Config, trust *TrustStore, now func() time.Time, allowExpired bool) (acmehttp01.Snapshot, error) {
	descriptor := command.Artifact
	file, err := store.openArtifact(record.RecordKey, record.ArtifactOffset)
	if err != nil {
		return acmehttp01.Snapshot{}, err
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
			EventId: command.Event.EventId, DeploymentId: command.OverlayDeploymentId,
			Attempt: command.Attempt, ArtifactId: descriptor.ArtifactId, Offset: offset,
		})
		if err != nil {
			cancel()
			return acmehttp01.Snapshot{}, err
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
				return acmehttp01.Snapshot{}, receiveErr
			}
			chunk := response.GetChunk()
			if err := validateArtifactChunk(chunk, requestID, descriptor, offset, maximumChunkBytes); err != nil {
				cancel()
				return acmehttp01.Snapshot{}, err
			}
			written, err := file.Write(chunk.Data)
			if err != nil || written != len(chunk.Data) {
				cancel()
				return acmehttp01.Snapshot{}, fmt.Errorf("write overlay artifact: %w", io.ErrShortWrite)
			}
			if err := file.Sync(); err != nil {
				cancel()
				return acmehttp01.Snapshot{}, err
			}
			offset += uint64(len(chunk.Data))
			if err := store.setArtifactOffset(record.RecordKey, offset); err != nil {
				cancel()
				return acmehttp01.Snapshot{}, err
			}
			if chunk.EndOfArtifact {
				ended = true
				break
			}
		}
		cancel()
		if ended {
			if offset != descriptor.SizeBytes {
				return acmehttp01.Snapshot{}, ErrArtifactIntegrity
			}
			break
		}
		if offset == startOffset {
			return acmehttp01.Snapshot{}, fmt.Errorf("overlay artifact stream ended without progress")
		}
	}
	if err := file.Close(); err != nil {
		return acmehttp01.Snapshot{}, err
	}
	wireBytes, err := store.readArtifact(record.RecordKey, descriptor.SizeBytes)
	if err != nil {
		return acmehttp01.Snapshot{}, err
	}
	digest := sha256.Sum256(wireBytes)
	if !bytes.Equal(digest[:], descriptor.Sha256) || verifyArtifactSignature(descriptor, wireBytes, trust) != nil {
		return acmehttp01.Snapshot{}, ErrArtifactIntegrity
	}
	decoded, err := decompressArtifact(descriptor.Compression, wireBytes, config.MaxDecompressedBytes)
	if err != nil {
		return acmehttp01.Snapshot{}, err
	}
	defer clearPlaintext(decoded)
	if err := rejectDuplicateJSONKeys(decoded); err != nil {
		return acmehttp01.Snapshot{}, ErrArtifactIntegrity
	}
	snapshot, err := acmehttp01.DecodeSnapshotStructure(decoded)
	if err != nil {
		return acmehttp01.Snapshot{}, err
	}
	if !allowExpired {
		if err := acmehttp01.ValidateSnapshot(snapshot, now().UTC()); err != nil {
			return acmehttp01.Snapshot{}, err
		}
	}
	// The signed snapshot names a cleanup_only purpose; an apply one names none.
	signedPurpose := acmehttp01.PurposeApply
	if snapshot.Purpose == acmehttp01.PurposeCleanupOnly {
		signedPurpose = acmehttp01.PurposeCleanupOnly
	}
	if snapshot.OverlayVersionID != command.OverlayVersionId || snapshot.OverlayRevision != command.OverlayRevision ||
		signedPurpose != overlayCommandPurpose(command) {
		clearACMEHTTP01Snapshot(&snapshot)
		return acmehttp01.Snapshot{}, ErrArtifactIntegrity
	}
	return snapshot, nil
}

func (c *Client) finishACMEHTTP01Failure(key string, command *agentv1.AcmeHTTP01OverlayCommand, result acmehttp01.Result, err error, unchanged bool) error {
	status := acmeHTTP01FailureStatus(command, result, err, unchanged, c.now())
	return c.overlayStore.appendStatuses(key, []*agentv1.AcmeHTTP01OverlayStatus{status}, true)
}

func acmeHTTP01DeliveredStatus(command *agentv1.AcmeHTTP01OverlayCommand, active acmehttp01.Pointer) *agentv1.AcmeHTTP01OverlayStatus {
	return acmeHTTP01StatusFor(command, 1, agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED,
		active, true, agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK,
		"overlay command delivered", command.Event.OccurredTime.AsTime())
}

func acmeHTTP01StatusesForResult(command *agentv1.AcmeHTTP01OverlayCommand, result acmehttp01.Result) []*agentv1.AcmeHTTP01OverlayStatus {
	statuses := make([]*agentv1.AcmeHTTP01OverlayStatus, 0, len(result.Transitions))
	for _, transition := range result.Transitions {
		statuses = append(statuses, acmeHTTP01StatusFor(command, transition.Sequence, overlayWireState(transition.State),
			result.Active, transition.ActiveUnchanged, overlayResultCode(transition.ResultCode), transition.Summary, transition.At))
	}
	return statuses
}

func acmeHTTP01FailureStatus(command *agentv1.AcmeHTTP01OverlayCommand, result acmehttp01.Result, err error, unchanged bool, at time.Time) *agentv1.AcmeHTTP01OverlayStatus {
	state := agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED
	sequence := uint64(2)
	active := result.Active
	if len(result.Transitions) > 0 {
		last := result.Transitions[len(result.Transitions)-1]
		state = overlayWireState(last.State)
		sequence = last.Sequence
	}
	code, protocolCode, summary := classifyACMEHTTP01Error(err)
	status := acmeHTTP01StatusFor(command, sequence, state, active, unchanged, code, summary, at)
	status.Error = &commonv1.ProtocolError{Code: protocolCode, Message: summary, Retryable: false}
	return status
}

func acmeHTTP01StatusFor(command *agentv1.AcmeHTTP01OverlayCommand, sequence uint64, state agentv1.AcmeHTTP01OverlayState, active acmehttp01.Pointer, unchanged bool, code agentv1.AcmeHTTP01OverlayResultCode, summary string, at time.Time) *agentv1.AcmeHTTP01OverlayStatus {
	at = notBeforeCommand(command.Event.OccurredTime, at)
	causationID := command.Event.EventId
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("acme-http01:%s:%d:%d", command.Event.EventId, sequence, state))).String()
	status := &agentv1.AcmeHTTP01OverlayStatus{
		Event: &commonv1.EventMetadata{
			EventId: eventID, RequestId: command.Event.RequestId, OccurredTime: timestamppb.New(at.UTC()),
			Traceparent: command.Event.Traceparent, CausationId: &causationID,
			CorrelationId: command.Event.CorrelationId, TaskId: command.Event.TaskId,
		},
		OverlayDeploymentId: command.OverlayDeploymentId, Attempt: command.Attempt,
		OverlayVersionId: command.OverlayVersionId, OverlayRevision: command.OverlayRevision,
		State: state, TransitionSequence: sequence, ActiveOverlayRevision: active.Revision,
		ActiveOverlayUnchanged: unchanged, ResultCode: code, ActivationSummary: sanitizeSummary(summary),
		Checks: []*agentv1.CheckResult{{
			Name: "acme_http01_overlay_transition", Succeeded: state != agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED &&
				state != agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED,
			Summary: sanitizeSummary(summary), LatencyDuration: durationpb.New(0),
		}},
	}
	if active.VersionID != "" {
		status.ActiveOverlayVersionId = &active.VersionID
	}
	return status
}

func overlayWireState(state acmehttp01.State) agentv1.AcmeHTTP01OverlayState {
	switch state {
	case acmehttp01.StateStaged:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_STAGED
	case acmehttp01.StatePrechecked:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_PRECHECKED
	case acmehttp01.StateActivated:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED
	case acmehttp01.StateHealthy:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY
	case acmehttp01.StateReverting:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING
	case acmehttp01.StateReverted:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED
	case acmehttp01.StateRollbackFailed:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED
	default:
		return agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED
	}
}

func overlayResultCode(code string) agentv1.AcmeHTTP01OverlayResultCode {
	switch code {
	case "OK":
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK
	case "INVALID_ARTIFACT":
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_INVALID_ARTIFACT
	case "PRECHECK_FAILED":
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_PRECHECK_FAILED
	case "ACTIVATION_FAILED":
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ACTIVATION_FAILED
	case "HEALTH_FAILED":
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED
	case "ROLLED_BACK":
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK
	case "ROLLBACK_FAILED":
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED
	default:
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED
	}
}

func classifyACMEHTTP01Error(err error) (agentv1.AcmeHTTP01OverlayResultCode, commonv1.ErrorCode, string) {
	switch {
	case errors.Is(err, ErrArtifactIntegrity), errors.Is(err, acmehttp01.ErrInvalidSnapshot):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_INVALID_ARTIFACT, commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH, "overlay artifact integrity check failed"
	case errors.Is(err, acmehttp01.ErrExpired):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_EXPIRED, commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "overlay challenge expired"
	case errors.Is(err, acmehttp01.ErrStaleAttempt):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_STALE_ATTEMPT, commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT, "overlay attempt is stale"
	case errors.Is(err, acmehttp01.ErrConflict):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_CONFLICT, commonv1.ErrorCode_ERROR_CODE_CONFLICT, "overlay state conflicts with command"
	case errors.Is(err, acmehttp01.ErrPrecheckFailed), errors.Is(err, acmehttp01.ErrRouteUnavailable):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_PRECHECK_FAILED, commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "overlay route precheck failed"
	case errors.Is(err, acmehttp01.ErrActivationFailed):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ACTIVATION_FAILED, commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "overlay activation failed"
	case errors.Is(err, acmehttp01.ErrRollbackFailed):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED, commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "overlay rollback failed"
	case errors.Is(err, acmehttp01.ErrHealthFailed):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK, commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, "overlay health check failed and previous version was restored"
	case errors.Is(err, ErrUnsupportedCommand):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSUPPORTED, commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "overlay capability is unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED, commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED, "overlay command deadline expired"
	default:
		return agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED, commonv1.ErrorCode_ERROR_CODE_INTERNAL, "overlay operation failed"
	}
}

func overlayActiveUnchanged(result acmehttp01.Result) bool {
	return result.Active.VersionID != result.VersionID || result.Active.Revision != result.Revision
}

func clearACMEHTTP01Snapshot(snapshot *acmehttp01.Snapshot) {
	if snapshot == nil {
		return
	}
	for index := range snapshot.Entries {
		snapshot.Entries[index].Value = ""
		snapshot.Entries[index].Token = ""
	}
}
