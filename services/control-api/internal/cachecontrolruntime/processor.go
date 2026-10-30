package cachecontrolruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	DispositionAck             = "ack"
	DispositionNak             = "nak"
	DispositionTerm            = "term"
	StatusReasonRetryExhausted = "retry_exhausted"
)

type TerminalStatusSnapshot struct {
	Succeeded     uint64 `json:"succeeded"`
	PartialFailed uint64 `json:"partial_failed"`
	Failed        uint64 `json:"failed"`
	Cancelled     uint64 `json:"cancelled"`
}

type RetryStatusSnapshot struct {
	Requeued          uint64 `json:"requeued"`
	RetryExhaustedDLQ uint64 `json:"retry_exhausted_dlq"`
	QuarantinedDLQ    uint64 `json:"quarantined_dlq"`
}

type StatusSnapshot struct {
	Terminal TerminalStatusSnapshot `json:"terminal"`
	Retry    RetryStatusSnapshot    `json:"retry"`
}

type statusCounters struct {
	succeeded         atomic.Uint64
	partialFailed     atomic.Uint64
	failed            atomic.Uint64
	cancelled         atomic.Uint64
	requeued          atomic.Uint64
	retryExhaustedDLQ atomic.Uint64
	quarantinedDLQ    atomic.Uint64
}

var stableCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (runtime *Runtime) ProcessStatusOnce(ctx context.Context) (string, error) {
	source, err := runtime.consumer.Next(ctx)
	if err != nil {
		return "", err
	}
	if source.Kind() == cancelReceiptKind {
		return runtime.processCancelReceipt(ctx, source)
	}
	status, reason := decodeStatus(source, runtime.config)
	if reason != "" {
		return runtime.quarantine(ctx, source, reason)
	}
	scopeID, _ := uuid.Parse(status.ScopeId)
	operationID, _ := uuid.Parse(status.ControlOperationId)
	nodeID, _ := uuid.Parse(status.NodeId)
	leaseID, _ := uuid.Parse(status.LeaseId)
	claim, err := runtime.control.ResolveClaim(ctx, cachecontrol.ClaimIdentity{
		ScopeID: scopeID, OperationID: operationID, NodeID: nodeID,
		LeaseID: leaseID, Attempt: status.Attempt,
	})
	if err != nil {
		if errors.Is(err, cachecontrol.ErrNotFound) || errors.Is(err, cachecontrol.ErrClaimLost) {
			return runtime.term(ctx, source, nil)
		}
		return runtime.nak(ctx, source, err)
	}
	command, err := buildCommand(claim)
	if err != nil || !commandMatchesStatus(command, status) {
		return runtime.quarantine(ctx, source, "identity_mismatch")
	}
	if status.State == agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED ||
		status.State == agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING {
		if len(status.Results) != 0 || status.ErrorCode != "" {
			return runtime.quarantine(ctx, source, "nonterminal_results")
		}
		return runtime.ack(ctx, source)
	}
	results, err := terminalResults(command, status)
	if err != nil {
		return runtime.quarantine(ctx, source, "terminal_results")
	}
	report, err := runtime.control.Report(ctx, cachecontrol.ReportRequest{
		ScopeID: claim.ScopeID, OperationID: claim.OperationID, NodeID: claim.NodeID,
		WorkerID: claim.WorkerID, LeaseID: claim.LeaseID, Attempt: claim.Attempt,
		Sequence: status.TransitionSequence, Results: results, RequestID: status.Event.EventId,
	})
	if err != nil {
		if errors.Is(err, cachecontrol.ErrClaimLost) || errors.Is(err, cachecontrol.ErrNotFound) ||
			errors.Is(err, cachecontrol.ErrReportConflict) || errors.Is(err, cachecontrol.ErrInvalidTransition) {
			return runtime.term(ctx, source, nil)
		}
		if errors.Is(err, cachecontrol.ErrInvalidInput) || errors.Is(err, cachecontrol.ErrPermissionDenied) {
			return runtime.quarantine(ctx, source, "report_rejected")
		}
		return runtime.nak(ctx, source, err)
	}
	if report.Applied && !report.Replayed {
		runtime.recordTerminalStatus(status.State)
	}
	return runtime.ack(ctx, source)
}

func (runtime *Runtime) StatusSnapshot() StatusSnapshot {
	if runtime == nil {
		return StatusSnapshot{}
	}
	return StatusSnapshot{
		Terminal: TerminalStatusSnapshot{
			Succeeded: runtime.status.succeeded.Load(), PartialFailed: runtime.status.partialFailed.Load(),
			Failed: runtime.status.failed.Load(), Cancelled: runtime.status.cancelled.Load(),
		},
		Retry: RetryStatusSnapshot{
			Requeued:          runtime.status.requeued.Load(),
			RetryExhaustedDLQ: runtime.status.retryExhaustedDLQ.Load(),
			QuarantinedDLQ:    runtime.status.quarantinedDLQ.Load(),
		},
	}
}

func (runtime *Runtime) recordTerminalStatus(state agentv1.CacheControlState) {
	switch state {
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED:
		runtime.status.succeeded.Add(1)
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED:
		runtime.status.partialFailed.Add(1)
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED:
		runtime.status.failed.Add(1)
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED:
		runtime.status.cancelled.Add(1)
	}
}

func decodeStatus(source delivery, config Config) (*agentv1.CacheControlStatus, string) {
	if source == nil || len(source.Data()) == 0 || len(source.Data()) > config.MaxPayloadBytes {
		return nil, "payload_size"
	}
	status := new(agentv1.CacheControlStatus)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(source.Data(), status); err != nil ||
		hasUnknownFields(status.ProtoReflect()) {
		return nil, "protobuf_invalid"
	}
	if status.Event == nil {
		return nil, "status_invalid"
	}
	nodeID, canonical := canonicalUUID(status.NodeId)
	if !canonical || source.Subject() != config.StatusSubjectPrefix+"."+nodeID.String() {
		return nil, "subject_mismatch"
	}
	for _, value := range []string{
		status.Event.GetEventId(), status.Event.GetRequestId(), status.Event.GetCorrelationId(),
		status.ScopeId, status.TenantId, status.SiteId, status.ControlOperationId, status.LeaseId,
		status.ConfigVersionId,
	} {
		if _, valid := canonicalUUID(value); !valid {
			return nil, "uuid_invalid"
		}
	}
	if status.Event.OccurredTime == nil ||
		status.Event.OccurredTime.CheckValid() != nil || status.Event.CausationId == nil ||
		status.Event.TaskId == nil || status.TransitionSequence == 0 ||
		len(status.RequestDigest) != 32 || !status.ActiveConfigUnchanged ||
		status.ErrorCode != "" && !stableCodePattern.MatchString(status.ErrorCode) ||
		len(status.Summary) > 1024 {
		return nil, "status_invalid"
	}
	expectedSequence := uint64(3)
	switch status.State {
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED:
		expectedSequence = 1
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING:
		expectedSequence = 2
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED:
	default:
		return nil, "state_invalid"
	}
	if status.TransitionSequence != expectedSequence {
		return nil, "sequence_invalid"
	}
	return status, ""
}

func hasUnknownFields(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if descriptor.IsList() && descriptor.Message() != nil {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if hasUnknownFields(list.Get(index).Message()) {
					unknown = true
					return false
				}
			}
		} else if descriptor.IsMap() && descriptor.MapValue().Message() != nil {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				unknown = hasUnknownFields(item.Message())
				return !unknown
			})
		} else if descriptor.Message() != nil && hasUnknownFields(value.Message()) {
			unknown = true
		}
		return !unknown
	})
	return unknown
}

func terminalResults(command *agentv1.CacheControlCommand, status *agentv1.CacheControlStatus) ([]cachecontrol.TargetResult, error) {
	if len(status.Results) != len(command.Targets) || len(status.Results) == 0 {
		return nil, cachecontrol.ErrInvalidInput
	}
	results := make([]cachecontrol.TargetResult, len(status.Results))
	succeeded := 0
	for index, result := range status.Results {
		target := command.Targets[index]
		if result == nil || result.Index != uint32(index) ||
			result.TargetOrdinal != target.TargetOrdinal || !bytes.Equal(result.Sha256, target.Sha256) ||
			result.CompletedTime == nil || result.CompletedTime.CheckValid() != nil || result.Attempts == 0 ||
			!stableCodePattern.MatchString(result.ResultCode) ||
			result.CauseCode != "" && !stableCodePattern.MatchString(result.CauseCode) {
			return nil, cachecontrol.ErrInvalidInput
		}
		mapped := cachecontrol.TargetResult{TargetOrdinal: int(result.TargetOrdinal)}
		switch result.State {
		case agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS,
			agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SKIPPED:
			mapped.State = cachecontrol.ItemSucceeded
			succeeded++
		case agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED:
			if status.State == agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED {
				mapped.State = cachecontrol.ItemCancelled
				mapped.ErrorCode = "cancelled"
			} else {
				mapped.State = cachecontrol.ItemFailed
				mapped.ErrorCode = firstStableCode(result.CauseCode, result.ResultCode, status.ErrorCode, "target_failed")
			}
		default:
			return nil, cachecontrol.ErrInvalidInput
		}
		results[index] = mapped
	}
	switch status.State {
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED:
		if succeeded != len(results) {
			return nil, cachecontrol.ErrInvalidInput
		}
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED:
		if succeeded != 0 {
			return nil, cachecontrol.ErrInvalidInput
		}
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED:
		// CACHE-ADD-07: the targets done before the cancel keep their
		// success; at least one target was stopped by it
		if succeeded == len(results) {
			return nil, cachecontrol.ErrInvalidInput
		}
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED:
		if succeeded == 0 || succeeded == len(results) {
			return nil, cachecontrol.ErrInvalidInput
		}
	default:
		return nil, cachecontrol.ErrInvalidInput
	}
	return results, nil
}

func firstStableCode(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if stableCodePattern.MatchString(value) {
			return value
		}
	}
	return "target_failed"
}

func (runtime *Runtime) quarantine(ctx context.Context, source delivery, reason string) (string, error) {
	if err := runtime.bus.PublishDLQ(ctx, source, reason); err != nil {
		return runtime.nak(ctx, source, err)
	}
	return runtime.termDLQ(ctx, source, nil, false)
}

func (runtime *Runtime) ack(ctx context.Context, source delivery) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	defer cancel()
	return DispositionAck, source.Ack(operationCtx)
}

func (runtime *Runtime) nak(ctx context.Context, source delivery, cause error) (string, error) {
	if source.NumDelivered() >= uint64(runtime.config.MaxDeliver) {
		if err := runtime.bus.PublishDLQ(ctx, source, StatusReasonRetryExhausted); err != nil {
			return DispositionNak, errors.Join(cause, err)
		}
		return runtime.termDLQ(ctx, source, cause, true)
	}
	delay := retryDelay(runtime.config.NakBaseDelay, runtime.config.NakMaximumDelay, source.NumDelivered())
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	defer cancel()
	if err := source.Nak(operationCtx, delay); err != nil {
		return DispositionNak, errors.Join(cause, err)
	}
	runtime.status.requeued.Add(1)
	return DispositionNak, cause
}

func (runtime *Runtime) termDLQ(
	ctx context.Context,
	source delivery,
	cause error,
	retryExhausted bool,
) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	defer cancel()
	if err := source.Term(operationCtx); err != nil {
		return DispositionTerm, errors.Join(cause, err)
	}
	if retryExhausted {
		runtime.status.retryExhaustedDLQ.Add(1)
	} else {
		runtime.status.quarantinedDLQ.Add(1)
	}
	return DispositionTerm, cause
}

func (runtime *Runtime) term(ctx context.Context, source delivery, cause error) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	defer cancel()
	if err := source.Term(operationCtx); err != nil {
		return DispositionTerm, errors.Join(cause, err)
	}
	return DispositionTerm, cause
}

func statusIdentity(status *agentv1.CacheControlStatus) string {
	return fmt.Sprintf("%s/%s/%d", status.GetControlOperationId(), status.GetNodeId(), status.GetAttempt())
}
