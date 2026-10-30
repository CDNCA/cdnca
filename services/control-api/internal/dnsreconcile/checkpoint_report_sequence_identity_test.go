package dnsreconcile

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

func TestValidateResultAdvanceReportSequenceIdentity(t *testing.T) {
	for _, phase := range []checkpointTestPhase{checkpointTestApply, checkpointTestCommit} {
		t.Run("exact replay/"+string(phase), func(t *testing.T) {
			current := checkpointIdentityResult()
			requireResultAdvance(t, current, cloneCheckpointIdentityResult(current), phase, true)
		})
	}

	t.Run("apply phase accepts empty deferred representation change", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.DeferredDeletes = make([]dnscheck.OperationResult, 0)
		next := cloneCheckpointIdentityResult(current)
		next.DeferredDeletes = nil
		requireResultAdvance(t, current, next, checkpointTestApply, true)
	})

	t.Run("commit phase accepts empty apply representation change", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.Operations = make([]dnscheck.OperationResult, 0)
		next := cloneCheckpointIdentityResult(current)
		next.Operations = nil
		requireResultAdvance(t, current, next, checkpointTestCommit, true)
	})

	drifts := []struct {
		name   string
		mutate func(*dnscheck.OperationResult)
	}{
		{name: "client request id", mutate: func(item *dnscheck.OperationResult) { item.ClientRequestID = "client-drift" }},
		{name: "provider request id", mutate: func(item *dnscheck.OperationResult) { item.ProviderRequestID = "request-drift" }},
		{name: "provider record id", mutate: func(item *dnscheck.OperationResult) { item.ProviderRecordID = "record-drift" }},
		{name: "provider revision", mutate: func(item *dnscheck.OperationResult) { item.ProviderRevision++ }},
		{name: "attempts", mutate: func(item *dnscheck.OperationResult) { item.Attempts++ }},
		{name: "status", mutate: func(item *dnscheck.OperationResult) { item.Status = dnscheck.OperationSucceeded }},
		{name: "error class", mutate: func(item *dnscheck.OperationResult) { item.ErrorClass = dnscheck.ProviderErrorTransient }},
		{name: "error code", mutate: func(item *dnscheck.OperationResult) { item.ErrorCode = "provider_drift" }},
	}
	for _, collection := range checkpointIdentityCollections() {
		for _, drift := range drifts {
			t.Run("same sequence/"+collection.name+"/"+drift.name, func(t *testing.T) {
				current := checkpointIdentityResult()
				next := cloneCheckpointIdentityResult(current)
				drift.mutate(collection.item(&next))
				requireResultAdvance(t, current, next, collection.phase, false)
			})
		}

		t.Run("report sequence rollback/"+collection.name, func(t *testing.T) {
			current := checkpointIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			collection.item(&next).ReportSequence--
			requireResultAdvance(t, current, next, collection.phase, false)
		})

		t.Run("higher sequence provider progress/"+collection.name, func(t *testing.T) {
			current := checkpointIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			item := collection.item(&next)
			item.ReportSequence++
			item.Status = dnscheck.OperationSucceeded
			item.ProviderRequestID = "provider-request-succeeded"
			item.ProviderRecordID = "provider-record-succeeded"
			item.ProviderRevision++
			item.Attempts++
			item.ErrorClass = dnscheck.ProviderErrorNone
			item.ErrorCode = ""
			requireResultAdvance(t, current, next, collection.phase, true)
		})

		for _, drift := range []struct {
			name   string
			mutate func(*dnscheck.OperationResult)
		}{
			{name: "source sequence", mutate: func(item *dnscheck.OperationResult) { item.SourceSequence++ }},
			{name: "operation", mutate: func(item *dnscheck.OperationResult) { item.Operation.RecordID = "operation-drift" }},
			{name: "client request id", mutate: func(item *dnscheck.OperationResult) { item.ClientRequestID = "client-drift" }},
		} {
			t.Run("higher sequence immutable/"+collection.name+"/"+drift.name, func(t *testing.T) {
				current := checkpointIdentityResult()
				next := cloneCheckpointIdentityResult(current)
				item := collection.item(&next)
				item.ReportSequence++
				drift.mutate(item)
				requireResultAdvance(t, current, next, collection.phase, false)
			})
		}
	}

	t.Run("false delete success cannot reuse report sequence", func(t *testing.T) {
		current := checkpointIdentityResult()
		next := cloneCheckpointIdentityResult(current)
		next.DeferredDeletes[0].Status = dnscheck.OperationSucceeded
		requireResultAdvance(t, current, next, checkpointTestCommit, false)
	})

	t.Run("deferred client request id fill requires sequence growth", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.DeferredDeletes[0].ClientRequestID = ""
		next := cloneCheckpointIdentityResult(current)
		next.DeferredDeletes[0].ClientRequestID = "commit-client-request"
		requireResultAdvance(t, current, next, checkpointTestCommit, false)

		next.DeferredDeletes[0].ReportSequence++
		requireResultAdvance(t, current, next, checkpointTestCommit, true)
	})

	for _, collection := range checkpointIdentityCollections() {
		t.Run("untouched skipped/"+collection.name, func(t *testing.T) {
			current := checkpointSkippedResult(collection.name)
			next := cloneCheckpointIdentityResult(current)
			item := collection.item(&next)
			item.Status = dnscheck.OperationSkipped
			item.ErrorCode = "prior_operation_failed"
			requireResultAdvance(t, current, next, collection.phase, true)
		})

		for _, drift := range []struct {
			name   string
			mutate func(*dnscheck.OperationResult)
		}{
			{name: "source sequence", mutate: func(item *dnscheck.OperationResult) { item.SourceSequence++ }},
			{name: "operation", mutate: func(item *dnscheck.OperationResult) { item.Operation.RecordID = "operation-drift" }},
			{name: "client request id", mutate: func(item *dnscheck.OperationResult) { item.ClientRequestID = "client-drift" }},
			{name: "provider request id", mutate: func(item *dnscheck.OperationResult) { item.ProviderRequestID = "request-drift" }},
			{name: "provider record id", mutate: func(item *dnscheck.OperationResult) { item.ProviderRecordID = "record-drift" }},
			{name: "provider revision", mutate: func(item *dnscheck.OperationResult) { item.ProviderRevision = 1 }},
			{name: "attempts", mutate: func(item *dnscheck.OperationResult) { item.Attempts = 1 }},
			{name: "error class", mutate: func(item *dnscheck.OperationResult) { item.ErrorClass = dnscheck.ProviderErrorPermanent }},
			{name: "wrong error code", mutate: func(item *dnscheck.OperationResult) { item.ErrorCode = "wrong_skip_reason" }},
		} {
			t.Run("skipped drift/"+collection.name+"/"+drift.name, func(t *testing.T) {
				current := checkpointSkippedResult(collection.name)
				next := cloneCheckpointIdentityResult(current)
				item := collection.item(&next)
				item.Status = dnscheck.OperationSkipped
				item.ErrorCode = "prior_operation_failed"
				drift.mutate(item)
				requireResultAdvance(t, current, next, collection.phase, false)
			})
		}
	}

	t.Run("unchanged operations allow task propagation checkpoint", func(t *testing.T) {
		current := checkpointIdentityResult()
		next := cloneCheckpointIdentityResult(current)
		next.Status = dnscheck.TaskPropagating
		next.ProviderRevision++
		next.Propagation = append(next.Propagation, dnscheck.PropagationAttempt{
			Number: 2, Status: dnscheck.ClassificationHealthy, ConsecutiveHealthy: 1,
		})
		next.LastCheck = &dnscheck.CheckResult{Status: dnscheck.ClassificationHealthy, Compliant: true}
		requireResultAdvance(t, current, next, checkpointTestApply, true)
	})

	for _, status := range []dnscheck.TaskStatus{dnscheck.TaskReadyToCommit, dnscheck.TaskCommitted} {
		t.Run("running apply cannot reach "+string(status), func(t *testing.T) {
			current := checkpointIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			next.Status = status
			requireResultAdvance(t, current, next, checkpointTestApply, false)
		})
	}

	t.Run("running deferred delete cannot reach committed", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.Operations[0].Status = dnscheck.OperationSucceeded
		next := cloneCheckpointIdentityResult(current)
		next.Status = dnscheck.TaskCommitted
		requireResultAdvance(t, current, next, checkpointTestCommit, false)
	})

	for _, deferredStatus := range []dnscheck.OperationStatus{
		dnscheck.OperationDeferred, dnscheck.OperationRunning,
	} {
		t.Run("persisted apply success allows ready with deferred "+string(deferredStatus), func(t *testing.T) {
			current := checkpointIdentityResult()
			current.Operations[0].Status = dnscheck.OperationSucceeded
			current.DeferredDeletes[0].Status = deferredStatus
			next := cloneCheckpointIdentityResult(current)
			next.Status = dnscheck.TaskReadyToCommit
			requireResultAdvance(t, current, next, checkpointTestApply, true)
		})
	}

	t.Run("persisted apply and delete success allow committed", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.Status = dnscheck.TaskReadyToCommit
		current.Operations[0].Status = dnscheck.OperationSucceeded
		current.DeferredDeletes[0].Status = dnscheck.OperationSucceeded
		next := cloneCheckpointIdentityResult(current)
		next.Status = dnscheck.TaskCommitted
		requireResultAdvance(t, current, next, checkpointTestCommit, true)
	})

	t.Run("persisted apply success without deferred allows committed", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.Status = dnscheck.TaskReadyToCommit
		current.Operations[0].Status = dnscheck.OperationSucceeded
		current.DeferredDeletes = nil
		next := cloneCheckpointIdentityResult(current)
		next.Status = dnscheck.TaskCommitted
		requireResultAdvance(t, current, next, checkpointTestApply, true)
	})

	t.Run("empty operation sets allow committed", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.Operations = nil
		current.DeferredDeletes = nil
		next := cloneCheckpointIdentityResult(current)
		next.Status = dnscheck.TaskCommitted
		requireResultAdvance(t, current, next, checkpointTestApply, true)
	})

	t.Run("apply phase cannot advance deferred delete into committed", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.Operations[0].Status = dnscheck.OperationSucceeded
		next := cloneCheckpointIdentityResult(current)
		next.DeferredDeletes[0].ReportSequence++
		next.DeferredDeletes[0].Status = dnscheck.OperationSucceeded
		next.DeferredDeletes[0].ProviderRevision++
		next.Status = dnscheck.TaskCommitted
		requireResultAdvance(t, current, next, checkpointTestApply, false)
	})

	for _, drift := range []struct {
		name   string
		mutate func(*dnscheck.OperationResult)
	}{
		{name: "sequence", mutate: func(item *dnscheck.OperationResult) { item.ReportSequence++ }},
		{name: "status", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.Status = dnscheck.OperationSucceeded
		}},
		{name: "provider request id", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ProviderRequestID = "commit-request-progress"
		}},
		{name: "provider record id", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ProviderRecordID = "commit-record-progress"
		}},
		{name: "provider revision", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ProviderRevision++
		}},
		{name: "attempts", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.Attempts++
		}},
		{name: "error", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ErrorClass = dnscheck.ProviderErrorTransient
			item.ErrorCode = "commit_progress"
		}},
	} {
		t.Run("apply phase freezes deferred/"+drift.name, func(t *testing.T) {
			current := checkpointIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			drift.mutate(&next.DeferredDeletes[0])
			requireResultAdvance(t, current, next, checkpointTestApply, false)
		})
	}

	t.Run("apply phase freezes deferred client fill", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.DeferredDeletes[0].ClientRequestID = ""
		next := cloneCheckpointIdentityResult(current)
		next.DeferredDeletes[0].ReportSequence++
		next.DeferredDeletes[0].ClientRequestID = "commit-client-request"
		requireResultAdvance(t, current, next, checkpointTestApply, false)
	})

	t.Run("apply phase freezes deferred skipped transition", func(t *testing.T) {
		current := checkpointSkippedResult("deferred delete")
		next := cloneCheckpointIdentityResult(current)
		next.DeferredDeletes[0].Status = dnscheck.OperationSkipped
		next.DeferredDeletes[0].ErrorCode = "prior_operation_failed"
		requireResultAdvance(t, current, next, checkpointTestApply, false)
	})

	for _, drift := range []struct {
		name   string
		mutate func(*dnscheck.OperationResult)
	}{
		{name: "sequence", mutate: func(item *dnscheck.OperationResult) { item.ReportSequence++ }},
		{name: "running to succeeded", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.Status = dnscheck.OperationSucceeded
		}},
		{name: "provider request id", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ProviderRequestID = "apply-request-progress"
		}},
		{name: "provider record id", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ProviderRecordID = "apply-record-progress"
		}},
		{name: "provider revision", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ProviderRevision++
		}},
		{name: "attempts", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.Attempts++
		}},
		{name: "error", mutate: func(item *dnscheck.OperationResult) {
			item.ReportSequence++
			item.ErrorClass = dnscheck.ProviderErrorTransient
			item.ErrorCode = "apply_progress"
		}},
	} {
		t.Run("commit phase freezes apply/"+drift.name, func(t *testing.T) {
			current := checkpointIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			drift.mutate(&next.Operations[0])
			requireResultAdvance(t, current, next, checkpointTestCommit, false)
		})
	}

	t.Run("commit phase freezes apply skipped transition", func(t *testing.T) {
		current := checkpointSkippedResult("apply")
		next := cloneCheckpointIdentityResult(current)
		next.Operations[0].Status = dnscheck.OperationSkipped
		next.Operations[0].ErrorCode = "prior_operation_failed"
		requireResultAdvance(t, current, next, checkpointTestCommit, false)
	})

	t.Run("commit phase delete progress allows committed", func(t *testing.T) {
		current := checkpointIdentityResult()
		current.Status = dnscheck.TaskReadyToCommit
		current.Operations[0].Status = dnscheck.OperationSucceeded
		next := cloneCheckpointIdentityResult(current)
		next.DeferredDeletes[0].ReportSequence++
		next.DeferredDeletes[0].Status = dnscheck.OperationSucceeded
		next.DeferredDeletes[0].ProviderRevision++
		next.Status = dnscheck.TaskCommitted
		requireResultAdvance(t, current, next, checkpointTestCommit, true)
	})
}

type checkpointTestPhase string

const (
	checkpointTestApply  checkpointTestPhase = "apply"
	checkpointTestCommit checkpointTestPhase = "commit"
)

type checkpointIdentityCollection struct {
	name  string
	phase checkpointTestPhase
	item  func(*dnscheck.ReconcileResult) *dnscheck.OperationResult
}

func checkpointIdentityCollections() []checkpointIdentityCollection {
	return []checkpointIdentityCollection{
		{name: "apply", phase: checkpointTestApply, item: func(result *dnscheck.ReconcileResult) *dnscheck.OperationResult {
			return &result.Operations[0]
		}},
		{name: "deferred delete", phase: checkpointTestCommit, item: func(result *dnscheck.ReconcileResult) *dnscheck.OperationResult {
			return &result.DeferredDeletes[0]
		}},
	}
}

func checkpointIdentityResult() dnscheck.ReconcileResult {
	return dnscheck.ReconcileResult{
		TenantID:      uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		SiteID:        uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		ZoneID:        uuid.MustParse("30000000-0000-4000-8000-000000000001"),
		PayloadDigest: "checkpoint-payload",
		Plan:          dnscheck.RepairPlan{Digest: "checkpoint-plan"},
		Status:        dnscheck.TaskApplying,
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1,
			Operation: dnscheck.ProviderOperation{
				Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
			},
			ClientRequestID: "apply-client", ProviderRequestID: "apply-provider-request",
			ProviderRecordID: "apply-provider-record", ProviderRevision: 11,
			Status: dnscheck.OperationRunning, Attempts: 1, ReportSequence: 7,
		}},
		DeferredDeletes: []dnscheck.OperationResult{{
			SourceSequence: 2,
			Operation: dnscheck.ProviderOperation{
				Sequence: 2, Action: dnscheck.ProviderDelete, RecordID: "old-record",
				Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.9", TTL: 300,
			},
			ClientRequestID: "delete-client", ProviderRequestID: "delete-provider-request",
			ProviderRecordID: "old-record", ProviderRevision: 12,
			Status: dnscheck.OperationRunning, Attempts: 1, ReportSequence: 9,
		}},
		Propagation: []dnscheck.PropagationAttempt{{Number: 1, Status: dnscheck.ClassificationPublicPropagating}},
	}
}

func checkpointSkippedResult(collection string) dnscheck.ReconcileResult {
	result := checkpointIdentityResult()
	var item *dnscheck.OperationResult
	if collection == "apply" {
		item = &result.Operations[0]
		item.Status = dnscheck.OperationPlanned
	} else {
		item = &result.DeferredDeletes[0]
		item.Status = dnscheck.OperationDeferred
	}
	item.ClientRequestID = ""
	item.ProviderRequestID = ""
	item.ProviderRecordID = ""
	item.ProviderRevision = 0
	item.Attempts = 0
	item.ErrorClass = dnscheck.ProviderErrorNone
	item.ErrorCode = ""
	item.ReportSequence = 0
	return result
}

func cloneCheckpointIdentityResult(source dnscheck.ReconcileResult) dnscheck.ReconcileResult {
	result := source
	result.Operations = append([]dnscheck.OperationResult(nil), source.Operations...)
	result.DeferredDeletes = append([]dnscheck.OperationResult(nil), source.DeferredDeletes...)
	result.Propagation = append([]dnscheck.PropagationAttempt(nil), source.Propagation...)
	if source.LastCheck != nil {
		lastCheck := *source.LastCheck
		result.LastCheck = &lastCheck
	}
	return result
}

func requireResultAdvance(t *testing.T, current, next dnscheck.ReconcileResult,
	phase checkpointTestPhase, allowed bool) {
	t.Helper()
	err := validateResultAdvance(current, next, checkpointPhase(phase))
	if allowed && err != nil {
		t.Fatalf("validateResultAdvance() error = %v", err)
	}
	if !allowed && !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("validateResultAdvance() error = %v, want ErrInvalidInput", err)
	}
}
