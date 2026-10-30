package dnscheck

import (
	"context"
	"time"

	"github.com/google/uuid"
)

func PrepareReconcile(request ReconcileRequest, now func() time.Time) (PreparedReconcile, error) {
	if now == nil {
		now = time.Now
	}
	return (&Reconciler{now: now}).PrepareApply(request)
}

// CheckpointFunc persists a complete reconciliation snapshot before execution
// advances to the next externally observable step.
type CheckpointFunc func(context.Context, ReconcileResult) error

// PreparedReconcile is the deterministic, side-effect-free input to a durable
// apply or commit execution.
type PreparedReconcile struct {
	IdempotencyKey string
	Request        CheckRequest
	Result         ReconcileResult
}

func (r *Reconciler) PrepareApply(request ReconcileRequest) (PreparedReconcile, error) {
	prepared, err := r.prepare(request, true)
	if err != nil {
		return PreparedReconcile{}, err
	}
	return PreparedReconcile{
		IdempotencyKey: request.IdempotencyKey,
		Request:        cloneCheckRequest(prepared.request),
		Result:         cloneReconcileResult(prepared.result),
	}, nil
}

func (r *Reconciler) ResumeApply(
	ctx context.Context,
	prepared PreparedReconcile,
	current ReconcileResult,
	checkpoint CheckpointFunc,
) (ReconcileResult, error) {
	if ctx == nil || !validPreparedReconcile(prepared, current) {
		return ReconcileResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return ReconcileResult{}, err
	}
	switch current.Status {
	case TaskDryRun, TaskApplying, TaskPropagating:
	case TaskReadyToCommit, TaskCommitted:
		return cloneReconcileResult(current), nil
	default:
		return ReconcileResult{}, ErrInvalidInput
	}
	private := preparedReconcile{request: cloneCheckRequest(prepared.Request), result: cloneReconcileResult(prepared.Result)}
	return r.executeApplyDurable(ctx, prepared.IdempotencyKey, private, current, checkpoint)
}

func (r *Reconciler) ResumeCommit(
	ctx context.Context,
	prepared PreparedReconcile,
	current ReconcileResult,
	checkpoint CheckpointFunc,
) (ReconcileResult, error) {
	if ctx == nil || !validPreparedReconcile(prepared, current) {
		return ReconcileResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return ReconcileResult{}, err
	}
	if current.Status == TaskCommitted {
		return cloneReconcileResult(current), nil
	}
	if current.Status != TaskReadyToCommit && current.Status != TaskCommitFailed {
		return ReconcileResult{}, ErrCommitNotReady
	}
	return r.executeCommitDurable(ctx, prepared.IdempotencyKey, cloneCheckRequest(prepared.Request), current, checkpoint)
}

func validPreparedReconcile(prepared PreparedReconcile, current ReconcileResult) bool {
	if !validIdempotencyKey(prepared.IdempotencyKey) || prepared.Request.TenantID == uuid.Nil ||
		prepared.Request.SiteID == uuid.Nil || prepared.Request.Provider.ZoneID == uuid.Nil ||
		prepared.Result.InitialRevision != prepared.Request.Provider.Revision ||
		current.InitialRevision != prepared.Result.InitialRevision ||
		current.TenantID != prepared.Request.TenantID || current.SiteID != prepared.Request.SiteID ||
		current.ZoneID != prepared.Request.Provider.ZoneID {
		return false
	}
	canonicalRequest, err := normalizeRequest(prepared.Request, prepared.Result.StartedAt)
	if err != nil {
		return false
	}
	canonicalPlan, err := buildRepairPlan(canonicalRequest)
	if err != nil {
		return false
	}
	preparedDigest, err := reconcilePayloadDigest(canonicalRequest, canonicalPlan)
	if err != nil || preparedDigest == "" || prepared.Result.PayloadDigest != preparedDigest ||
		current.PayloadDigest != preparedDigest {
		return false
	}
	samePlan := func(candidate RepairPlan) bool {
		if candidate.TenantID != canonicalPlan.TenantID || candidate.SiteID != canonicalPlan.SiteID ||
			candidate.ZoneID != canonicalPlan.ZoneID || candidate.PreconditionRevision != canonicalPlan.PreconditionRevision ||
			candidate.Digest != canonicalPlan.Digest || len(candidate.Operations) != len(canonicalPlan.Operations) {
			return false
		}
		for index := range canonicalPlan.Operations {
			if candidate.Operations[index] != canonicalPlan.Operations[index] {
				return false
			}
		}
		return true
	}
	if !samePlan(prepared.Result.Plan) || !samePlan(current.Plan) {
		return false
	}

	expectedOperations, expectedDeferred := safeOperationStages(canonicalPlan)
	if len(prepared.Result.Operations) != len(expectedOperations) || len(current.Operations) != len(expectedOperations) ||
		len(prepared.Result.DeferredDeletes) != len(expectedDeferred) || len(current.DeferredDeletes) != len(expectedDeferred) {
		return false
	}
	for index := range expectedOperations {
		expected := expectedOperations[index]
		expectedRequestID := operationRequestID(canonicalRequest.TenantID, prepared.IdempotencyKey,
			preparedDigest, "apply", expected.SourceSequence)
		if prepared.Result.Operations[index].SourceSequence != expected.SourceSequence ||
			prepared.Result.Operations[index].Operation != expected.Operation ||
			prepared.Result.Operations[index].ClientRequestID != expectedRequestID ||
			current.Operations[index].SourceSequence != expected.SourceSequence ||
			current.Operations[index].Operation != expected.Operation ||
			current.Operations[index].ClientRequestID != expectedRequestID {
			return false
		}
	}
	for index := range expectedDeferred {
		expected := expectedDeferred[index]
		currentRequestID := current.DeferredDeletes[index].ClientRequestID
		expectedRequestID := operationRequestID(canonicalRequest.TenantID, prepared.IdempotencyKey,
			preparedDigest, "commit", expected.SourceSequence)
		if prepared.Result.DeferredDeletes[index].SourceSequence != expected.SourceSequence ||
			prepared.Result.DeferredDeletes[index].Operation != expected.Operation ||
			prepared.Result.DeferredDeletes[index].ClientRequestID != "" ||
			current.DeferredDeletes[index].SourceSequence != expected.SourceSequence ||
			current.DeferredDeletes[index].Operation != expected.Operation ||
			currentRequestID != "" && currentRequestID != expectedRequestID {
			return false
		}
	}
	return true
}

func checkpointResult(ctx context.Context, checkpoint CheckpointFunc, result ReconcileResult) error {
	if checkpoint == nil {
		return nil
	}
	return checkpoint(ctx, cloneReconcileResult(result))
}

func cloneCheckRequest(source CheckRequest) CheckRequest {
	result := source
	result.Expected = append([]ExpectedRecord(nil), source.Expected...)
	for index := range result.Expected {
		result.Expected[index].Values = append([]string(nil), source.Expected[index].Values...)
	}
	result.AuthoritativeNS = append([]string(nil), source.AuthoritativeNS...)
	result.Provider.Records = append([]ProviderRecord(nil), source.Provider.Records...)
	if source.PropagationStartedAt != nil {
		started := *source.PropagationStartedAt
		result.PropagationStartedAt = &started
	}
	return result
}
