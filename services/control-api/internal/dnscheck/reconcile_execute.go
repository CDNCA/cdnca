package dnscheck

import (
	"context"
	"errors"
	"math"
	"time"
)

const maxProviderRetryAfter = time.Hour

func normalizeProviderRetryAfter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	if delay > maxProviderRetryAfter {
		return maxProviderRetryAfter
	}
	return delay
}

func (r *Reconciler) executeApply(ctx context.Context, key string, prepared preparedReconcile) ReconcileResult {
	result, _ := r.executeApplyDurable(ctx, key, prepared, prepared.result, nil)
	return result
}

func (r *Reconciler) executeApplyDurable(
	ctx context.Context,
	key string,
	prepared preparedReconcile,
	current ReconcileResult,
	checkpoint CheckpointFunc,
) (ReconcileResult, error) {
	result := cloneReconcileResult(current)
	expectedRevision := result.InitialRevision
	operationsComplete := true
	for _, operation := range result.Operations {
		if operation.Status == OperationSucceeded {
			expectedRevision = maximumRevision(expectedRevision, operation.ProviderRevision)
		} else {
			operationsComplete = false
		}
	}
	revision := expectedRevision
	resumePropagation := result.Status == TaskPropagating && operationsComplete
	resumeUnknown := (result.Status == TaskApplying || result.Status == TaskPropagating) &&
		hasProviderRecoveryPending(result)
	if !resumePropagation {
		resuming := result.Status == TaskApplying || resumeUnknown
		if resumeUnknown {
			result.CompensationPlan = nil
		}
		if !resuming {
			result.Status = TaskApplying
			result.UpdatedAt = r.now().UTC()
			if err := checkpointResult(ctx, checkpoint, result); err != nil {
				return result, err
			}
			var class ProviderErrorClass
			var code string
			var ok bool
			revision, class, code, ok = r.readProviderRevision(ctx, prepared.request)
			if !ok {
				r.finishTaskFailure(&result, ctx, class, code)
				return result, checkpointResult(ctx, checkpoint, result)
			}
			if revision != expectedRevision {
				result.Status = TaskFailed
				result.ErrorClass = ProviderErrorRevisionConflict
				result.ErrorCode = "revision_conflict"
				result.UpdatedAt = r.now().UTC()
				return result, checkpointResult(ctx, checkpoint, result)
			}
			result.ProviderRevision = revision
		}
		if resumeUnknown {
			// A provider may have accepted the command before the response was
			// lost. Retry the same client request id and let the adapter replay
			// it before applying the revision precondition.
			revision = expectedRevision
		}

		for index := range result.Operations {
			if result.Operations[index].Status == OperationSucceeded {
				revision = result.Operations[index].ProviderRevision
				result.ProviderRevision = revision
				continue
			}
			if isTerminalOperation(result.Operations[index].Status) &&
				!(resumeUnknown && isDurableProviderRecoveryPending(result.Operations[index])) &&
				result.Operations[index].Status != OperationSkipped {
				for skipped := index + 1; skipped < len(result.Operations); skipped++ {
					result.Operations[skipped].Status = OperationSkipped
					result.Operations[skipped].ErrorCode = "prior_operation_failed"
				}
				result.CompensationPlan = compensationForApplied(result.Operations)
				r.finishTaskFailure(&result, ctx, result.Operations[index].ErrorClass,
					result.Operations[index].ErrorCode)
				return result, checkpointResult(ctx, checkpoint, result)
			}
			if isDurableProviderRecoveryPending(result.Operations[index]) && result.Operations[index].RetryAfter > 0 {
				if err := r.sleep(ctx, normalizeProviderRetryAfter(result.Operations[index].RetryAfter)); err != nil {
					return result, checkpointResult(ctx, checkpoint, result)
				}
				result.Operations[index].RetryAfter = 0
				result.UpdatedAt = r.now().UTC()
				if err := checkpointResult(ctx, checkpoint, result); err != nil {
					return result, err
				}
			}
			result.Operations[index].Status = OperationPlanned
			result.Operations[index].ErrorClass = ProviderErrorNone
			result.Operations[index].ErrorCode = ""
			result.Operations[index].Status = OperationRunning
			result.Operations[index].ReportSequence++
			result.UpdatedAt = r.now().UTC()
			if err := checkpointResult(ctx, checkpoint, result); err != nil {
				return result, err
			}
			operation := r.executeProviderOperation(ctx, result.Operations[index], prepared.request, revision)
			result.Operations[index] = operation
			result.ProviderRevision = maximumRevision(result.ProviderRevision, operation.ProviderRevision)
			result.UpdatedAt = r.now().UTC()
			if err := checkpointResult(ctx, checkpoint, result); err != nil {
				return result, err
			}
			if operation.Status != OperationSucceeded {
				if isProviderRecoveryPending(operation) {
					result.Status = TaskPropagating
					result.ErrorClass = operation.ErrorClass
					result.ErrorCode = operation.ErrorCode
					result.CompensationPlan = nil
					result.UpdatedAt = r.now().UTC()
					return result, checkpointResult(ctx, checkpoint, result)
				}
				for skipped := index + 1; skipped < len(result.Operations); skipped++ {
					result.Operations[skipped].Status = OperationSkipped
					result.Operations[skipped].ErrorCode = "prior_operation_failed"
				}
				result.ProviderRevision = maximumRevision(result.ProviderRevision, operation.ProviderRevision)
				result.CompensationPlan = compensationForApplied(result.Operations)
				r.finishTaskFailure(&result, ctx, operation.ErrorClass, operation.ErrorCode)
				return result, checkpointResult(ctx, checkpoint, result)
			}
			revision = operation.ProviderRevision
			result.ProviderRevision = revision
		}

		result.Status = TaskPropagating
		result.ErrorClass = ProviderErrorNone
		result.ErrorCode = ""
		if err := checkpointResult(ctx, checkpoint, result); err != nil {
			return result, err
		}
	}
	started := r.now().UTC()
	checkRequest := prepared.request
	checkRequest.PropagationStartedAt = &started
	if result.Status == TaskPropagating && result.ErrorCode == "dependency_unavailable" &&
		len(result.Propagation) > 0 && !result.Propagation[len(result.Propagation)-1].DependencyUnavailable {
		// Results persisted before DependencyUnavailable existed decode the
		// field as false. The task-level reason is the compatibility authority.
		for index := range result.Propagation {
			result.Propagation[index].DependencyUnavailable = true
		}
	}
	consecutive := 0
	if len(result.Propagation) > 0 {
		last := result.Propagation[len(result.Propagation)-1]
		if !last.DependencyUnavailable {
			consecutive = last.ConsecutiveHealthy
		}
	}
	pollsUsed := 0
	for _, attempt := range result.Propagation {
		if !attempt.DependencyUnavailable {
			pollsUsed++
		}
	}
	for pollsUsed < r.pollAttempts {
		if err := ctx.Err(); err != nil {
			result.CompensationPlan = compensationForApplied(result.Operations)
			r.finishTaskFailure(&result, ctx, ProviderErrorNone, "")
			return result, checkpointResult(ctx, checkpoint, result)
		}
		check, err := r.checker.Check(ctx, checkRequest)
		if err != nil {
			result.CompensationPlan = compensationForApplied(result.Operations)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				r.finishTaskFailure(&result, ctx, ProviderErrorNone, "")
			} else {
				r.finishTaskFailure(&result, ctx, ProviderErrorPermanent, "checker_failed")
			}
			return result, checkpointResult(ctx, checkpoint, result)
		}
		result.LastCheck = &check
		dependencyUnavailable := checkHasDependencyUnavailable(check)
		if dependencyUnavailable {
			consecutive = 0
		} else if check.Status == ClassificationHealthy {
			consecutive++
		} else {
			consecutive = 0
		}
		if !dependencyUnavailable {
			pollsUsed++
		}
		result.Propagation = append(result.Propagation, PropagationAttempt{
			Number: len(result.Propagation) + 1, CheckedAt: check.CheckedAt, Status: check.Status,
			ConsecutiveHealthy: consecutive, DependencyUnavailable: dependencyUnavailable,
		})
		result.UpdatedAt = r.now().UTC()
		if err := checkpointResult(ctx, checkpoint, result); err != nil {
			return result, err
		}
		if dependencyUnavailable {
			result.Status = TaskPropagating
			result.ErrorClass = ProviderErrorTransient
			result.ErrorCode = "dependency_unavailable"
			result.CompensationPlan = nil
			result.UpdatedAt = r.now().UTC()
			return result, checkpointResult(ctx, checkpoint, result)
		}
		if consecutive >= r.requiredConsecutive {
			ready := r.now().UTC()
			result.ReadyAt = &ready
			result.ErrorClass = ProviderErrorNone
			result.ErrorCode = ""
			if len(result.DeferredDeletes) == 0 {
				result.Status = TaskCommitted
			} else {
				result.Status = TaskReadyToCommit
			}
			return result, checkpointResult(ctx, checkpoint, result)
		}
		if pollsUsed < r.pollAttempts {
			if err := r.sleep(ctx, r.backoff(pollsUsed, 0)); err != nil {
				result.CompensationPlan = compensationForApplied(result.Operations)
				r.finishTaskFailure(&result, ctx, ProviderErrorNone, "")
				return result, checkpointResult(ctx, checkpoint, result)
			}
		}
	}
	result.Status = TaskFailed
	result.ErrorClass = ProviderErrorPermanent
	result.ErrorCode = "propagation_not_converged"
	result.CompensationPlan = compensationForApplied(result.Operations)
	result.UpdatedAt = r.now().UTC()
	return result, checkpointResult(ctx, checkpoint, result)
}

func (r *Reconciler) executeCommit(ctx context.Context, key string, checkRequest CheckRequest, result ReconcileResult) (ReconcileResult, error) {
	return r.executeCommitDurable(ctx, key, checkRequest, result, nil)
}

func isProviderRecoveryPending(operation OperationResult) bool {
	if operation.ErrorCode == "provider_recovery_pending" || operation.ErrorCode == "provider_recovery_persistence_failed" {
		return true
	}
	return operation.Status == OperationRunning && retryableProviderClass(operation.ErrorClass) && operation.RetryAfter > 0
}

func hasProviderRecoveryPending(result ReconcileResult) bool {
	for _, operation := range result.Operations {
		if isDurableProviderRecoveryPending(operation) {
			return true
		}
	}
	return false
}

func isDurableProviderRecoveryPending(operation OperationResult) bool {
	if isProviderRecoveryPending(operation) {
		return true
	}
	return operation.Status == OperationTransientFailed && operation.ErrorCode != "dependency_unavailable" &&
		retryableProviderClass(operation.ErrorClass)
}

func checkHasDependencyUnavailable(check CheckResult) bool {
	for _, observation := range check.Observations {
		if observation.ErrorCode == "dependency_unavailable" {
			return true
		}
		switch observation.Status {
		case ClassificationSERVFAIL, ClassificationTimeout, ClassificationResolverFailure,
			ClassificationMalformedResponse:
			return true
		case ClassificationHealthy, ClassificationMissing, ClassificationWrongValue,
			ClassificationCNAMEChain, ClassificationCNAMELoop, ClassificationCNAMEDepthExceeded,
			ClassificationNXDOMAIN, ClassificationNODATA:
			continue
		default:
			// An observation added by a newer checker is not safe to interpret as
			// convergence. Keep the task recoverable until this process understands it.
			return true
		}
	}
	return false
}

func (r *Reconciler) executeCommitDurable(
	ctx context.Context,
	key string,
	checkRequest CheckRequest,
	result ReconcileResult,
	checkpoint CheckpointFunc,
) (ReconcileResult, error) {
	result = cloneReconcileResult(result)
	for _, item := range result.DeferredDeletes {
		if item.Status == OperationPermanentFailed || item.Status == OperationRevisionConflict {
			return result, ErrCommitNotReady
		}
	}
	check, err := r.checker.Check(ctx, checkRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return result, err
		}
		result.ErrorClass = ProviderErrorPermanent
		result.ErrorCode = "commit_check_failed"
		result.UpdatedAt = r.now().UTC()
		if checkpointErr := checkpointResult(ctx, checkpoint, result); checkpointErr != nil {
			return result, checkpointErr
		}
		return result, ErrCommitNotReady
	}
	result.LastCheck = &check
	if checkHasDependencyUnavailable(check) {
		result.Status = TaskReadyToCommit
		result.ErrorClass = ProviderErrorTransient
		result.ErrorCode = "dependency_unavailable"
		result.CompensationPlan = nil
		result.UpdatedAt = r.now().UTC()
		if checkpointErr := checkpointResult(ctx, checkpoint, result); checkpointErr != nil {
			return result, checkpointErr
		}
		return result, ErrCommitNotReady
	}
	if check.Status != ClassificationHealthy {
		result.ErrorClass = ProviderErrorPermanent
		result.ErrorCode = "commit_convergence_lost"
		result.UpdatedAt = r.now().UTC()
		if checkpointErr := checkpointResult(ctx, checkpoint, result); checkpointErr != nil {
			return result, checkpointErr
		}
		return result, ErrCommitNotReady
	}
	revision := result.ProviderRevision
	result.ErrorClass = ProviderErrorNone
	result.ErrorCode = ""
	for index := range result.DeferredDeletes {
		item := result.DeferredDeletes[index]
		if item.Status == OperationSucceeded {
			revision = item.ProviderRevision
			continue
		}
		if isProviderRecoveryPending(item) && item.RetryAfter > 0 {
			if err := r.sleep(ctx, normalizeProviderRetryAfter(item.RetryAfter)); err != nil {
				return result, checkpointResult(ctx, checkpoint, result)
			}
			item.RetryAfter = 0
			result.DeferredDeletes[index] = item
			result.UpdatedAt = r.now().UTC()
			if err := checkpointResult(ctx, checkpoint, result); err != nil {
				return result, err
			}
		}
		item.Status = OperationPlanned
		item.ErrorClass = ProviderErrorNone
		item.ErrorCode = ""
		item.ClientRequestID = operationRequestID(result.TenantID, key, result.PayloadDigest, "commit", item.SourceSequence)
		item.Status = OperationRunning
		item.ReportSequence++
		result.DeferredDeletes[index] = item
		result.UpdatedAt = r.now().UTC()
		if err := checkpointResult(ctx, checkpoint, result); err != nil {
			return result, err
		}
		item = r.executeProviderOperation(ctx, item, checkRequest, revision)
		result.DeferredDeletes[index] = item
		result.ProviderRevision = maximumRevision(result.ProviderRevision, item.ProviderRevision)
		result.UpdatedAt = r.now().UTC()
		if err := checkpointResult(ctx, checkpoint, result); err != nil {
			return result, err
		}
		if item.Status != OperationSucceeded {
			if isProviderRecoveryPending(item) {
				result.Status = TaskReadyToCommit
				result.ErrorClass = item.ErrorClass
				result.ErrorCode = item.ErrorCode
				result.CompensationPlan = nil
				result.UpdatedAt = r.now().UTC()
				return result, checkpointResult(ctx, checkpoint, result)
			}
			for skipped := index + 1; skipped < len(result.DeferredDeletes); skipped++ {
				result.DeferredDeletes[skipped].Status = OperationSkipped
				result.DeferredDeletes[skipped].ErrorCode = "prior_operation_failed"
			}
			result.Status = TaskCommitFailed
			result.ErrorClass = item.ErrorClass
			result.ErrorCode = item.ErrorCode
			result.ProviderRevision = maximumRevision(result.ProviderRevision, item.ProviderRevision)
			result.CompensationPlan = compensationForCommittedDeletes(result.DeferredDeletes)
			result.UpdatedAt = r.now().UTC()
			return result, checkpointResult(ctx, checkpoint, result)
		}
		revision = item.ProviderRevision
		result.ProviderRevision = revision
	}
	result.Status = TaskCommitted
	result.CompensationPlan = nil
	result.UpdatedAt = r.now().UTC()
	return result, checkpointResult(ctx, checkpoint, result)
}

func (r *Reconciler) readProviderRevision(ctx context.Context, request CheckRequest) (int64, ProviderErrorClass, string, bool) {
	revisionRequest := ProviderRevisionRequest{TenantID: request.TenantID, SiteID: request.SiteID, ZoneID: request.Provider.ZoneID}
	var lastClass ProviderErrorClass
	var lastCode string
	for attempt := 1; attempt <= r.providerAttempts; attempt++ {
		attemptContext, cancel := context.WithTimeout(ctx, r.providerTimeout)
		revision, err := r.provider.CurrentRevision(attemptContext, revisionRequest)
		cancel()
		if err == nil {
			if revision < 1 {
				return 0, ProviderErrorPermanent, "invalid_provider_revision", false
			}
			return revision, ProviderErrorNone, "", true
		}
		lastClass, lastCode, _, _ = classifyProviderFailure(err)
		if ctx.Err() != nil {
			lastClass, lastCode, _, _ = classifyProviderFailure(ctx.Err())
			return 0, lastClass, lastCode, false
		}
		if !retryableProviderClass(lastClass) || attempt == r.providerAttempts {
			return 0, lastClass, lastCode, false
		}
		if err := r.sleep(ctx, r.backoff(attempt, 0)); err != nil {
			lastClass, lastCode, _, _ = classifyProviderFailure(err)
			return 0, lastClass, lastCode, false
		}
	}
	return 0, lastClass, lastCode, false
}

func (r *Reconciler) executeProviderOperation(ctx context.Context, result OperationResult, request CheckRequest, expectedRevision int64) OperationResult {
	mutation := ProviderMutation{
		ClientRequestID: result.ClientRequestID, TenantID: request.TenantID, SiteID: request.SiteID,
		ZoneID: request.Provider.ZoneID, ExpectedRevision: expectedRevision, Operation: result.Operation,
	}
	attemptBase := result.Attempts
	if attemptBase < 0 || attemptBase > int(^uint(0)>>1)-r.providerAttempts {
		result.Status = OperationPermanentFailed
		result.ErrorClass = ProviderErrorPermanent
		result.ErrorCode = "invalid_provider_attempts"
		result.ReportSequence++
		return result
	}
	for attempt := 1; attempt <= r.providerAttempts; attempt++ {
		result.Attempts = attemptBase + attempt
		attemptContext, cancel := context.WithTimeout(ctx, r.providerTimeout)
		providerResult, err := r.provider.Mutate(attemptContext, mutation)
		cancel()
		if err == nil {
			recordID := result.Operation.RecordID
			if result.Operation.Action == ProviderCreate {
				recordID = providerResult.RecordID
			}
			validProviderRequestID := validProviderIdentifier(providerResult.ProviderRequestID)
			if validProviderRequestID {
				result.ProviderRequestID = providerResult.ProviderRequestID
			}
			if !validProviderRequestID || !validProviderIdentifier(recordID) ||
				providerResult.Revision <= expectedRevision {
				result.Status = OperationPermanentFailed
				result.ErrorClass = ProviderErrorPermanent
				result.ErrorCode = "invalid_provider_response"
				result.ReportSequence++
				return result
			}
			result.ProviderRecordID = recordID
			result.ProviderRevision = providerResult.Revision
			result.Status = OperationSucceeded
			result.RetryAfter = 0
			result.ErrorClass = ProviderErrorNone
			result.ErrorCode = ""
			result.ReportSequence++
			return result
		}
		class, code, retryAfter, providerRequestID := classifyProviderFailure(err)
		if ctx.Err() != nil {
			class, code, retryAfter, providerRequestID = classifyProviderFailure(ctx.Err())
		}
		if providerRequestID != "" {
			result.ProviderRequestID = providerRequestID
		}
		result.ErrorClass = class
		result.ErrorCode = code
		result.RetryAfter = normalizeProviderRetryAfter(retryAfter)
		result.Status = operationFailureStatus(class)
		result.ReportSequence++
		if code == "provider_recovery_pending" || code == "provider_recovery_persistence_failed" {
			result.Status = OperationRunning
			return result
		}
		if !retryableProviderClass(class) || attempt == r.providerAttempts {
			if attempt == r.providerAttempts && retryableProviderClass(class) && result.RetryAfter > 0 {
				result.Status = OperationRunning
			}
			return result
		}
		if err := r.sleep(ctx, r.backoff(attempt, retryAfter)); err != nil {
			class, code, _, providerRequestID = classifyProviderFailure(err)
			if providerRequestID != "" {
				result.ProviderRequestID = providerRequestID
			}
			result.ErrorClass = class
			result.ErrorCode = code
			result.RetryAfter = 0
			result.Status = operationFailureStatus(class)
			result.ReportSequence++
			return result
		}
		result.Status = OperationRunning
		result.ReportSequence++
	}
	return result
}

func (r *Reconciler) backoff(attempt int, retryAfter time.Duration) time.Duration {
	exponent := attempt - 1
	if exponent > 30 {
		exponent = 30
	}
	base := float64(r.initialBackoff) * math.Pow(2, float64(exponent))
	if base > float64(r.maximumBackoff) {
		base = float64(r.maximumBackoff)
	}
	random := r.random()
	if random < 0 || random >= 1 || math.IsNaN(random) {
		random = 0.5
	}
	delay := time.Duration(base * (1 + (2*random-1)*r.jitterFraction))
	if retryAfter > delay {
		delay = retryAfter
	}
	if delay > r.maximumBackoff {
		delay = r.maximumBackoff
	}
	if delay < 0 {
		return 0
	}
	return delay
}

func compensationForApplied(results []OperationResult) []ProviderOperation {
	compensation := make([]ProviderOperation, 0, len(results))
	for index := len(results) - 1; index >= 0; index-- {
		result := results[index]
		if result.Status != OperationSucceeded {
			continue
		}
		switch result.Operation.Action {
		case ProviderCreate:
			if result.ProviderRecordID != "" {
				compensation = append(compensation, ProviderOperation{
					Action: ProviderDelete, RecordID: result.ProviderRecordID, Name: result.Operation.Name,
					Type: result.Operation.Type, Value: result.Operation.Value, TTL: result.Operation.TTL,
					Line: result.Operation.Line, Weight: result.Operation.Weight, Reason: "compensate_created_record",
				})
			}
		case ProviderUpdate:
			if result.Operation.PreviousValue != "" {
				compensation = append(compensation, ProviderOperation{
					Action: ProviderUpdate, RecordID: result.Operation.RecordID, Name: result.Operation.Name,
					Type: result.Operation.Type, Value: result.Operation.PreviousValue, TTL: result.Operation.PreviousTTL,
					Line: result.Operation.PreviousLine, Weight: result.Operation.PreviousWeight,
					PreviousValue: result.Operation.Value, PreviousTTL: result.Operation.TTL,
					PreviousLine: result.Operation.Line, PreviousWeight: result.Operation.Weight, Reason: "compensate_updated_record",
				})
			}
		}
	}
	sequenceOperations(compensation)
	return compensation
}

func CompensationForApplied(results []OperationResult) []ProviderOperation {
	return compensationForApplied(results)
}

func compensationForCommittedDeletes(results []OperationResult) []ProviderOperation {
	compensation := make([]ProviderOperation, 0, len(results))
	for index := len(results) - 1; index >= 0; index-- {
		result := results[index]
		if result.Status == OperationSucceeded && result.Operation.Action == ProviderDelete {
			compensation = append(compensation, ProviderOperation{
				Action: ProviderCreate, Name: result.Operation.Name, Type: result.Operation.Type,
				Value: result.Operation.Value, TTL: result.Operation.TTL,
				Line: result.Operation.Line, Weight: result.Operation.Weight, Reason: "compensate_deleted_record",
			})
		}
	}
	sequenceOperations(compensation)
	return compensation
}

func sequenceOperations(operations []ProviderOperation) {
	for index := range operations {
		operations[index].Sequence = index + 1
	}
}

func (r *Reconciler) finishTaskFailure(result *ReconcileResult, ctx context.Context, class ProviderErrorClass, code string) {
	if ctx.Err() != nil {
		class, code, _, _ = classifyProviderFailure(ctx.Err())
	}
	switch class {
	case ProviderErrorCancelled:
		result.Status = TaskCancelled
	case ProviderErrorTimeout:
		result.Status = TaskTimedOut
	default:
		result.Status = TaskFailed
	}
	result.ErrorClass = class
	result.ErrorCode = normalizeProviderCode(code)
	result.UpdatedAt = r.now().UTC()
}

func operationFailureStatus(class ProviderErrorClass) OperationStatus {
	switch class {
	case ProviderErrorTransient, ProviderErrorTimeout:
		return OperationTransientFailed
	case ProviderErrorRevisionConflict:
		return OperationRevisionConflict
	case ProviderErrorCancelled:
		return OperationCancelled
	default:
		return OperationPermanentFailed
	}
}

func retryableProviderClass(class ProviderErrorClass) bool {
	return class == ProviderErrorTransient || class == ProviderErrorTimeout
}

func validProviderIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 256 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' &&
			character != ':' && character != '/' && character != '-' {
			return false
		}
	}
	return true
}

func ValidProviderIdentifier(value string) bool {
	return validProviderIdentifier(value)
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func maximumRevision(left, right int64) int64 {
	if right > left {
		return right
	}
	return left
}

func cloneReconcileResult(source ReconcileResult) ReconcileResult {
	result := source
	result.Plan.Operations = append([]ProviderOperation(nil), source.Plan.Operations...)
	result.Operations = append([]OperationResult(nil), source.Operations...)
	result.DeferredDeletes = append([]OperationResult(nil), source.DeferredDeletes...)
	result.CompensationPlan = append([]ProviderOperation(nil), source.CompensationPlan...)
	result.Propagation = append([]PropagationAttempt(nil), source.Propagation...)
	if source.ReadyAt != nil {
		ready := *source.ReadyAt
		result.ReadyAt = &ready
	}
	if source.LastCheck != nil {
		check := cloneCheckResult(*source.LastCheck)
		result.LastCheck = &check
	}
	return result
}

func cloneCheckResult(source CheckResult) CheckResult {
	result := source
	result.Observations = append([]Observation(nil), source.Observations...)
	for index := range result.Observations {
		result.Observations[index].Values = append([]string(nil), source.Observations[index].Values...)
		result.Observations[index].CNAMEChain = append([]string(nil), source.Observations[index].CNAMEChain...)
	}
	result.RepairPlan.Operations = append([]ProviderOperation(nil), source.RepairPlan.Operations...)
	return result
}
