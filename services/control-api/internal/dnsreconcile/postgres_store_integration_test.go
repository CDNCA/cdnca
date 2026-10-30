//go:build integration

package dnsreconcile

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresStoreRequiresDependencies(t *testing.T) {
	if _, err := NewPostgresStore(nil, nil, time.Now); err == nil {
		t.Fatal("NewPostgresStore accepted missing PostgreSQL and jobstate dependencies")
	}
}

func TestPostgresStoreConcurrentIdempotencyAndRestart(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "concurrent")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "concurrent-key", "192.0.2.10")
	foreignJobID := uuid.New()
	foreignDigest := sha256.Sum256([]byte("foreign"))
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO background_jobs(
			id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,
			state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at
		) VALUES($1,$2,'foreign_job','foreign',$3,$4,'foreign-request','','queued',0,1,$5,1,$5,$5)`,
			foreignJobID, tenantID, request.IdempotencyKey, foreignDigest[:], clock.Now()); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO background_job_items(
			tenant_id,job_id,ordinal,item_id,state
		) VALUES($1,$2,1,'foreign','pending')`, tenantID, foreignJobID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	const callers = 12
	type outcome struct {
		task     Task
		replayed bool
		err      error
	}
	outcomes := make(chan outcome, callers)
	var start sync.WaitGroup
	start.Add(1)
	for range callers {
		go func() {
			start.Wait()
			task, replayed, err := store.Create(context.Background(), request, prepared)
			outcomes <- outcome{task: task, replayed: replayed, err: err}
		}()
	}
	start.Done()
	var taskID uuid.UUID
	created := 0
	for range callers {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatal(outcome.err)
		}
		if taskID == uuid.Nil {
			taskID = outcome.task.ID
		} else if outcome.task.ID != taskID {
			t.Fatalf("concurrent task IDs differ: %s and %s", taskID, outcome.task.ID)
		}
		if !outcome.replayed {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("new task count=%d, want 1", created)
	}

	restarted := newDNSReconcileStore(t, pool, clock)
	persisted, err := restarted.Get(t.Context(), tenantID, taskID)
	if err != nil || persisted.Prepared.IdempotencyKey != request.IdempotencyKey ||
		persisted.Result.PayloadDigest != prepared.Result.PayloadDigest || persisted.Job.Kind != JobKind {
		t.Fatalf("restart Get() = (%#v, %v)", persisted, err)
	}

	differentRequest, differentPrepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, request.IdempotencyKey, "192.0.2.11")
	if _, _, err := restarted.Create(t.Context(), differentRequest, differentPrepared); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different payload Create() error=%v", err)
	}
	_, otherSite := seedDNSReconcileStoreSiteForTenant(t, pool, tenantID, "other-site")
	otherRequest, otherPrepared := dnsReconcileStoreRequest(t, pool, tenantID, otherSite, request.IdempotencyKey, "192.0.2.10")
	if _, _, err := restarted.Create(t.Context(), otherRequest, otherPrepared); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different site Create() error=%v", err)
	}

	var jobs, roots, requiredConsecutive int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM background_jobs WHERE tenant_id=$1 AND kind='dns_reconcile'),
		(SELECT count(*) FROM dns_reconcile_tasks WHERE tenant_id=$1 AND idempotency_key=$2),
		(SELECT required_consecutive FROM dns_reconcile_tasks WHERE tenant_id=$1 AND idempotency_key=$2)`,
		tenantID, request.IdempotencyKey).Scan(&jobs, &roots, &requiredConsecutive); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || roots != 1 || requiredConsecutive != request.RequiredConsecutive {
		t.Fatalf("persisted jobs=%d roots=%d required=%d", jobs, roots, requiredConsecutive)
	}
}

func TestPostgresStoreExpiredApplyLeaseFencesOldWorker(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "lease")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "lease-key", "192.0.2.10")
	if _, _, err := store.Create(t.Context(), request, prepared); err != nil {
		t.Fatal(err)
	}
	first := claimDNSReconcileStore(t, store, tenantID, "worker-old", time.Second)
	applying := first.Task.Result
	applying.Status = dnscheck.TaskApplying
	applying.UpdatedAt = clock.Now()
	if _, err := store.CheckpointApply(t.Context(), first, applying); err != nil {
		t.Fatal(err)
	}

	clock.Advance(2 * time.Second)
	second := reclaimExpiredDNSReconcileStore(t, store, clock, tenantID, "worker-new", 30*time.Second)
	if second.Attempt != first.Attempt+1 || second.LeaseID == first.LeaseID {
		t.Fatalf("recovered lease=%#v after %#v", second, first)
	}
	propagating := applying
	propagating.Status = dnscheck.TaskPropagating
	propagating.UpdatedAt = clock.Now()
	if _, err := store.CheckpointApply(t.Context(), first, propagating); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("stale CheckpointApply() error=%v", err)
	}
	if _, err := store.CheckpointApply(t.Context(), second, propagating); err != nil {
		t.Fatalf("recovered CheckpointApply() error=%v", err)
	}
	persisted, err := newDNSReconcileStore(t, pool, clock).Get(t.Context(), tenantID, second.Task.ID)
	if err != nil || persisted.Result.Status != dnscheck.TaskPropagating || persisted.Job.Attempt != second.Attempt {
		t.Fatalf("restarted task=%#v err=%v", persisted, err)
	}
}

func TestPostgresStoreResumesPropagationAcrossApplyAttempts(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "propagation_resume")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "propagation-resume-key", "192.0.2.10")
	if _, _, err := store.Create(t.Context(), request, prepared); err != nil {
		t.Fatal(err)
	}
	first := claimDNSReconcileStore(t, store, tenantID, "worker-propagation-old", time.Second)
	propagating := readyDNSReconcileResult(first.Task.Result, clock.Now())
	propagating.Status = dnscheck.TaskPropagating
	propagating.ReadyAt = nil
	propagating.Propagation = propagating.Propagation[:1]
	if _, err := store.CheckpointApply(t.Context(), first, propagating); err != nil {
		t.Fatal(err)
	}

	clock.Advance(2 * time.Second)
	second := reclaimExpiredDNSReconcileStore(t, store, clock, tenantID, "worker-propagation-new", 30*time.Second)
	resumed := second.Task.Result
	resumed.Propagation = append(resumed.Propagation, dnscheck.PropagationAttempt{
		Number: 2, CheckedAt: clock.Now(), Status: dnscheck.ClassificationHealthy, ConsecutiveHealthy: 2,
	})
	resumed.UpdatedAt = clock.Now()
	checkpointed, err := store.CheckpointApply(t.Context(), second, resumed)
	if err != nil || len(checkpointed.Result.Propagation) != 2 || checkpointed.Job.Attempt != second.Attempt {
		t.Fatalf("resumed propagation CheckpointApply() = (%#v, %v)", checkpointed, err)
	}
}

func TestPostgresStorePersistsOutOfOrderProviderReports(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "reports")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "report-key", "192.0.2.10")
	if _, _, err := store.Create(t.Context(), request, prepared); err != nil {
		t.Fatal(err)
	}
	lease := claimDNSReconcileStore(t, store, tenantID, "worker-report", 10*time.Minute)
	applying := lease.Task.Result
	applying.Status = dnscheck.TaskApplying
	applying.UpdatedAt = clock.Now()
	checkpointed, err := store.CheckpointApply(t.Context(), lease, applying)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	clientRequestID := checkpointed.Result.Operations[0].ClientRequestID
	firstRequest := ProviderReportRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: checkpointed.ID,
		WorkloadID: lease.WorkerID, JobAttempt: lease.Attempt, LeaseID: lease.LeaseID,
		IdempotencyKey: "provider-report-command-1", ExpectedRevision: checkpointed.Revision,
		RequestID: "provider-report-1", Traceparent: "trace-provider-report-1", Report: dnscheck.ProviderReport{
			ClientRequestID: clientRequestID, ProviderRequestID: "provider-running",
			ProviderRecordID: "record-running", ProviderRevision: 100,
			Status: dnscheck.OperationRunning, Sequence: 5,
		},
	}
	first, err := store.RecordProviderReport(t.Context(), firstRequest)
	if err != nil || !first.Accepted {
		t.Fatalf("first RecordProviderReport() = (%#v, %v)", first, err)
	}
	invalidSuccess := firstRequest
	invalidSuccess.IdempotencyKey = "provider-report-command-invalid-success"
	invalidSuccess.ExpectedRevision = first.Task.Revision
	invalidSuccess.Report = dnscheck.ProviderReport{
		ClientRequestID: clientRequestID, ProviderRequestID: "provider-invalid",
		ProviderRecordID: "record-invalid", Status: dnscheck.OperationSucceeded, Sequence: 6,
	}
	if _, err := store.RecordProviderReport(t.Context(), invalidSuccess); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid successful RecordProviderReport() error=%v", err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, triggerErr := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_reports(
		id,tenant_id,job_id,phase,operation_ordinal,source,command_idempotency_key,
		command_digest,request_id,traceparent,expected_task_revision,report_sequence,status,
		provider_request_id,provider_record_id,provider_revision,error_class,error_code,
		accepted,disposition,reported_at,received_at
	) VALUES($1,$2,$3,'apply',1,'workload','provider-trigger-regression',$4,
		'provider-trigger-request','provider-trigger-trace',$5,6,'succeeded',
		'provider-trigger','record-trigger',99,'',NULL,true,'accepted',$6,$6)`,
		uuid.New(), tenantID, checkpointed.ID, []byte(strings.Repeat("x", sha256.Size)), first.Task.Revision, clock.Now())
	_ = tx.Rollback(context.WithoutCancel(t.Context()))
	var triggerPGError *pgconn.PgError
	if !errors.As(triggerErr, &triggerPGError) || triggerPGError.Code != "55000" {
		t.Fatalf("provider revision regression trigger error=%v", triggerErr)
	}
	replayRequest := firstRequest
	replayRequest.RequestID = "provider-report-1-retry"
	replayed, err := store.RecordProviderReport(t.Context(), replayRequest)
	if err != nil || !replayed.Accepted || !replayed.Task.Replayed || replayed.Task.Revision != first.Task.Revision {
		t.Fatalf("replayed RecordProviderReport() = (%#v, %v)", replayed, err)
	}
	conflictRequest := firstRequest
	conflictRequest.Report.Sequence = 6
	if _, err := store.RecordProviderReport(t.Context(), conflictRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting RecordProviderReport() error=%v", err)
	}
	stale, err := store.RecordProviderReport(t.Context(), ProviderReportRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: checkpointed.ID,
		WorkloadID: lease.WorkerID, JobAttempt: lease.Attempt, LeaseID: lease.LeaseID,
		IdempotencyKey: "provider-report-command-stale", ExpectedRevision: first.Task.Revision,
		RequestID: "provider-report-stale", Traceparent: "trace-provider-report-stale", Report: dnscheck.ProviderReport{
			ClientRequestID: clientRequestID, Status: dnscheck.OperationRunning, Sequence: 4,
		},
	})
	if err != nil || stale.Accepted || stale.Task.Revision != first.Task.Revision ||
		stale.Task.Result.Operations[0].ReportSequence != 5 {
		t.Fatalf("stale RecordProviderReport() = (%#v, %v)", stale, err)
	}
	validSuccess := invalidSuccess
	validSuccess.IdempotencyKey = "provider-report-command-regressed-success"
	validSuccess.Report.ProviderRevision = checkpointed.Result.InitialRevision + 1
	if _, err := store.RecordProviderReport(t.Context(), validSuccess); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("regressed successful RecordProviderReport() error=%v", err)
	}
	validSuccess.IdempotencyKey = "provider-report-command-success"
	validSuccess.Report.ProviderRevision = firstRequest.Report.ProviderRevision + 1
	// Once the running report bound the provider identity, a success must carry the same
	// provider request/record IDs (dnscheck.MergeProviderReport rejects a different one).
	validSuccess.Report.ProviderRequestID = firstRequest.Report.ProviderRequestID
	validSuccess.Report.ProviderRecordID = firstRequest.Report.ProviderRecordID
	succeeded, err := store.RecordProviderReport(t.Context(), validSuccess)
	if err != nil || !succeeded.Accepted ||
		succeeded.Task.Result.ProviderRevision != validSuccess.Report.ProviderRevision {
		t.Fatalf("successful RecordProviderReport() = (%#v, %v)", succeeded, err)
	}
	var raw, accepted, staleFacts, fencedFacts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),
		count(*) FILTER (WHERE accepted),count(*) FILTER (WHERE disposition='stale_sequence'),
		count(*) FILTER (WHERE source='workload' AND job_attempt=$3 AND lease_id=$4 AND worker_id=$5)
		FROM dns_reconcile_provider_reports WHERE tenant_id=$1 AND job_id=$2`,
		tenantID, checkpointed.ID, lease.Attempt, lease.LeaseID, lease.WorkerID).
		Scan(&raw, &accepted, &staleFacts, &fencedFacts); err != nil {
		t.Fatal(err)
	}
	if raw != 3 || accepted != 2 || staleFacts != 1 || fencedFacts != 3 {
		t.Fatalf("provider report facts raw=%d accepted=%d stale=%d fenced=%d",
			raw, accepted, staleFacts, fencedFacts)
	}
}

func TestPostgresStoreCommitLeaseRecoveryAndReplay(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "commit")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "commit-key", "192.0.2.10")
	if _, _, err := store.Create(t.Context(), request, prepared); err != nil {
		t.Fatal(err)
	}
	applyLease := claimDNSReconcileStore(t, store, tenantID, "worker-apply", 30*time.Second)
	ready := readyDNSReconcileResult(applyLease.Task.Result, clock.Now())
	// N22: ready needs every provider write confirmed (not consecutive
	// propagation checks): a ready result with an unconfirmed write is refused.
	unconfirmed := ready
	unconfirmed.Operations = append([]dnscheck.OperationResult(nil), ready.Operations...)
	unconfirmed.Operations[0].Status = dnscheck.OperationRunning
	if _, err := store.CheckpointApply(t.Context(), applyLease, unconfirmed); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unconfirmed-write CheckpointApply() error=%v", err)
	}
	readyTask, err := store.FinishApply(t.Context(), applyLease, ready)
	if err != nil || readyTask.Result.Status != dnscheck.TaskReadyToCommit || readyTask.Job.State != jobstate.StateSucceeded {
		t.Fatalf("FinishApply() = (%#v, %v)", readyTask, err)
	}
	command := CommitRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: readyTask.ID,
		ActorUserID:    request.ActorUserID,
		IdempotencyKey: "commit-command-key", RequestID: "commit-1", Traceparent: "trace-commit-1",
		ExpectedRevision: readyTask.Revision,
	}
	first, replayed, err := store.AcquireCommit(t.Context(), command, "commit-old", time.Second)
	if err != nil || replayed {
		t.Fatalf("first AcquireCommit() = (%#v, %t, %v)", first, replayed, err)
	}
	first, err = store.HeartbeatCommit(t.Context(), first, time.Second)
	if err != nil {
		t.Fatalf("HeartbeatCommit() error=%v", err)
	}
	activeReplay := command
	activeReplay.RequestID = "commit-active-retry"
	active, replayed, err := store.AcquireCommit(t.Context(), activeReplay, "commit-other", time.Second)
	if err != nil || !replayed || active.LeaseID != first.LeaseID || active.WorkerID != first.WorkerID {
		t.Fatalf("active replay AcquireCommit() = (%#v, %t, %v)", active, replayed, err)
	}
	clock.Advance(2 * time.Second)
	second, replayed, err := store.AcquireCommit(t.Context(), command, "commit-new", 30*time.Second)
	if err != nil || replayed || second.Attempt != first.Attempt+1 {
		t.Fatalf("recovered AcquireCommit() = (%#v, %t, %v)", second, replayed, err)
	}
	// N25: delete request IDs derive from the task's apply key, not the commit command's.
	committed := committedDNSReconcileResult(ready, prepared.IdempotencyKey, clock.Now())
	if _, err := store.CheckpointCommit(t.Context(), first, committed); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("stale CheckpointCommit() error=%v", err)
	}
	finished, err := store.CheckpointCommit(t.Context(), second, committed)
	if err != nil || finished.Result.Status != dnscheck.TaskCommitted {
		t.Fatalf("recovered CheckpointCommit() = (%#v, %v)", finished, err)
	}
	terminalReplay := command
	terminalReplay.RequestID = "commit-terminal-retry"
	replayedLease, replayed, err := store.AcquireCommit(t.Context(), terminalReplay, "commit-new", 30*time.Second)
	if err != nil || !replayed || replayedLease.Task.Result.Status != dnscheck.TaskCommitted {
		t.Fatalf("committed AcquireCommit() = (%#v, %t, %v)", replayedLease, replayed, err)
	}
	conflicting := command
	conflicting.ExpectedRevision++
	if _, _, err := store.AcquireCommit(t.Context(), conflicting, "commit-new", 30*time.Second); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting AcquireCommit() error=%v", err)
	}
	var claims, deletes, commits int
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE event_type='claimed'),
		count(*) FILTER (WHERE event_type='delete_succeeded'),
		count(*) FILTER (WHERE event_type='committed')
		FROM dns_reconcile_commit_facts WHERE tenant_id=$1 AND job_id=$2`,
		tenantID, readyTask.ID).Scan(&claims, &deletes, &commits); err != nil {
		t.Fatal(err)
	}
	if claims != 2 || deletes != len(committed.DeferredDeletes) || commits != 1 {
		t.Fatalf("commit facts claims=%d deletes=%d commits=%d", claims, deletes, commits)
	}
}

func TestPostgresStoreCancelAndFailureFacts(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "terminal")

	cancelRequest, cancelPrepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "cancel-key", "192.0.2.10")
	cancelTask, _, err := store.Create(t.Context(), cancelRequest, cancelPrepared)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, replayed, err := store.Cancel(t.Context(), CancelRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: cancelTask.ID,
		ActorUserID:    cancelRequest.ActorUserID,
		IdempotencyKey: "cancel-command-key", RequestID: "cancel-request", Traceparent: "trace-cancel-request",
		ExpectedRevision: cancelTask.Revision,
	})
	if err != nil || replayed || cancelled.Result.Status != dnscheck.TaskCancelled ||
		cancelled.Job.State != jobstate.StateCancelled {
		t.Fatalf("Cancel() = (%#v, %t, %v)", cancelled, replayed, err)
	}
	replayedCancel, replayed, err := store.Cancel(t.Context(), CancelRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: cancelTask.ID,
		ActorUserID:    cancelRequest.ActorUserID,
		IdempotencyKey: "cancel-command-key", RequestID: "cancel-request-retry", Traceparent: "trace-cancel-request-retry",
		ExpectedRevision: cancelTask.Revision,
	})
	if err != nil || !replayed || replayedCancel.Result.Status != dnscheck.TaskCancelled {
		t.Fatalf("replayed Cancel() = (%#v, %t, %v)", replayedCancel, replayed, err)
	}
	if _, _, err := store.Cancel(t.Context(), CancelRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: cancelTask.ID,
		ActorUserID:    cancelRequest.ActorUserID,
		IdempotencyKey: "cancel-command-key", RequestID: "cancel-conflict", Traceparent: "trace-cancel-conflict",
		ExpectedRevision: cancelTask.Revision + 1,
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting Cancel() error=%v", err)
	}
	var cancelFacts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_reconcile_cancel_facts
		WHERE tenant_id=$1 AND job_id=$2`, tenantID, cancelTask.ID).Scan(&cancelFacts); err != nil || cancelFacts != 1 {
		t.Fatalf("cancel facts=%d error=%v", cancelFacts, err)
	}

	failureRequest, failurePrepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "failure-key", "192.0.2.11")
	if _, _, err := store.Create(t.Context(), failureRequest, failurePrepared); err != nil {
		t.Fatal(err)
	}
	lease := claimDNSReconcileStore(t, store, tenantID, "worker-failure", 30*time.Second)
	failed := lease.Task.Result
	failed.Status = dnscheck.TaskFailed
	failed.ErrorClass = dnscheck.ProviderErrorPermanent
	failed.ErrorCode = "provider_failed"
	failed.UpdatedAt = clock.Now()
	failed.CompensationPlan = []dnscheck.ProviderOperation{failed.Operations[0].Operation}
	failed.Operations[0].Status = dnscheck.OperationPermanentFailed
	failed.Operations[0].ErrorClass = dnscheck.ProviderErrorPermanent
	failed.Operations[0].ErrorCode = "provider_failed"
	failed.Operations[0].ReportSequence = 2
	finished, err := store.FinishApply(t.Context(), lease, failed)
	if err != nil || finished.Result.Status != dnscheck.TaskFailed || finished.Job.State != jobstate.StateFailed {
		t.Fatalf("failed FinishApply() = (%#v, %v)", finished, err)
	}
	var compensationLength, failureReports int
	if err := pool.QueryRow(t.Context(), `SELECT
		jsonb_array_length(event.compensation_plan),
		(SELECT count(*) FROM dns_reconcile_provider_reports report
		 WHERE report.tenant_id=$1 AND report.job_id=$2 AND report.accepted)
		FROM dns_reconcile_task_events event
		WHERE event.tenant_id=$1 AND event.job_id=$2 ORDER BY event_sequence DESC LIMIT 1`,
		tenantID, lease.Task.ID).Scan(&compensationLength, &failureReports); err != nil {
		t.Fatal(err)
	}
	if compensationLength != 1 || failureReports != 1 {
		t.Fatalf("failure facts compensation=%d reports=%d", compensationLength, failureReports)
	}

	timeoutRequest, timeoutPrepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "timeout-key", "192.0.2.12")
	if _, _, err := store.Create(t.Context(), timeoutRequest, timeoutPrepared); err != nil {
		t.Fatal(err)
	}
	timeoutLease := claimDNSReconcileStore(t, store, tenantID, "worker-timeout", 30*time.Second)
	timedOut := timeoutLease.Task.Result
	timedOut.Status = dnscheck.TaskTimedOut
	timedOut.ErrorClass = dnscheck.ProviderErrorTimeout
	timedOut.ErrorCode = "timeout"
	timedOut.UpdatedAt = clock.Now()
	timedOut.CompensationPlan = []dnscheck.ProviderOperation{timedOut.Operations[0].Operation}
	timeoutTask, err := store.FinishApply(t.Context(), timeoutLease, timedOut)
	if err != nil || timeoutTask.Result.Status != dnscheck.TaskTimedOut || timeoutTask.Job.State != jobstate.StateFailed {
		t.Fatalf("timed-out FinishApply() = (%#v, %v)", timeoutTask, err)
	}
}

func TestPostgresStoreSnapshotDoesNotMixCancellationFacts(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "snapshot_cancel")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "snapshot-cancel-apply", "192.0.2.10")
	task, _, err := store.Create(t.Context(), request, prepared)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	snapshotTask, err := loadDNSReconcileTask(t.Context(), tx, tenantID, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Cancel(t.Context(), CancelRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: task.ID,
		ActorUserID:    request.ActorUserID,
		IdempotencyKey: "snapshot-cancel-command", RequestID: "snapshot-cancel",
		Traceparent: "trace-snapshot-cancel", ExpectedRevision: task.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	snapshotJob, err := loadDNSReconcileJob(t.Context(), tx, tenantID, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotTask.Result.Status != dnscheck.TaskDryRun || snapshotJob.State != jobstate.StateQueued {
		t.Fatalf("repeatable snapshot task/job=%s/%s", snapshotTask.Result.Status, snapshotJob.State)
	}
	latest, err := store.Get(t.Context(), tenantID, task.ID)
	if err != nil || latest.Result.Status != dnscheck.TaskCancelled || latest.Job.State != jobstate.StateCancelled {
		t.Fatalf("latest task/job=(%s/%s, %v)", latest.Result.Status, latest.Job.State, err)
	}
}

func TestPostgresStoreCancelIsAtomicAndFencesLiveWorker(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "cancel_atomic")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "cancel-atomic-apply", "192.0.2.10")
	task, _, err := store.Create(t.Context(), request, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_dns_cancel_test() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'reject cancel'; END $$;
		CREATE TRIGGER reject_dns_cancel_test BEFORE UPDATE ON background_jobs
		FOR EACH ROW WHEN (NEW.state='cancelled') EXECUTE FUNCTION reject_dns_cancel_test()`); err != nil {
		t.Fatal(err)
	}
	cancel := CancelRequest{TenantID: tenantID, SiteID: siteID, TaskID: task.ID, ActorUserID: request.ActorUserID,
		IdempotencyKey: "cancel-atomic-command", RequestID: "cancel-atomic", Traceparent: "trace-cancel-atomic",
		ExpectedRevision: task.Revision}
	if _, _, err := store.Cancel(t.Context(), cancel); err == nil {
		t.Fatal("Cancel() succeeded despite forced jobstate failure")
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_dns_cancel_test ON background_jobs;
		DROP FUNCTION reject_dns_cancel_test()`); err != nil {
		t.Fatal(err)
	}
	unchanged, err := store.Get(t.Context(), tenantID, task.ID)
	if err != nil || unchanged.Result.Status != dnscheck.TaskDryRun || unchanged.Job.State != jobstate.StateQueued {
		t.Fatalf("task after rolled-back cancel = (%#v, %v)", unchanged, err)
	}
	var events, facts int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM dns_reconcile_task_events WHERE job_id=$1),
		(SELECT count(*) FROM dns_reconcile_cancel_facts WHERE job_id=$1)`, task.ID).Scan(&events, &facts); err != nil || events != 0 || facts != 0 {
		t.Fatalf("rolled-back cancel events/facts=%d/%d error=%v", events, facts, err)
	}

	lease := claimDNSReconcileStore(t, store, tenantID, "cancel-live-worker", 30*time.Second)
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION delay_dns_cancel_test() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.25); RETURN NEW; END $$;
		CREATE TRIGGER delay_dns_cancel_test BEFORE UPDATE ON background_jobs
		FOR EACH ROW WHEN (NEW.state='cancelled') EXECUTE FUNCTION delay_dns_cancel_test()`); err != nil {
		t.Fatal(err)
	}
	cancel.ExpectedRevision = lease.Task.Revision
	cancelResult := make(chan error, 1)
	go func() {
		_, _, err := store.Cancel(context.Background(), cancel)
		cancelResult <- err
	}()
	time.Sleep(50 * time.Millisecond)
	applying := lease.Task.Result
	applying.Status = dnscheck.TaskApplying
	applying.UpdatedAt = clock.Now()
	if _, err := store.CheckpointApply(t.Context(), lease, applying); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("live worker checkpoint after cancel error=%v", err)
	}
	if err := <-cancelResult; err != nil {
		t.Fatalf("concurrent Cancel() error=%v", err)
	}
	final, err := store.Get(t.Context(), tenantID, task.ID)
	if err != nil || final.Result.Status != dnscheck.TaskCancelled || final.Job.State != jobstate.StateCancelled {
		t.Fatalf("final cancelled task = (%#v, %v)", final, err)
	}
}

func TestPostgresStoreCancelWaitsForInFlightProviderFact(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "cancel_in_flight")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "cancel-in-flight-key", "192.0.2.10")
	task, _, err := store.Create(t.Context(), request, prepared)
	if err != nil {
		t.Fatal(err)
	}
	lease := claimDNSReconcileStore(t, store, tenantID, "worker-cancel-in-flight", 30*time.Second)
	running := lease.Task.Result
	running.Status = dnscheck.TaskApplying
	running.Operations[0].Status = dnscheck.OperationRunning
	running.Operations[0].ReportSequence = 1
	running.UpdatedAt = clock.Now()
	checkpointed, err := store.CheckpointApply(t.Context(), lease, running)
	if err != nil {
		t.Fatal(err)
	}
	cancel := CancelRequest{
		TenantID: tenantID, SiteID: siteID, TaskID: task.ID,
		ActorUserID:    request.ActorUserID,
		IdempotencyKey: "cancel-in-flight-command", RequestID: "cancel-in-flight-request",
		Traceparent: "cancel-in-flight-trace", ExpectedRevision: checkpointed.Revision,
	}
	if _, _, err := store.Cancel(t.Context(), cancel); !errors.Is(err, ErrOperationInFlight) {
		t.Fatalf("Cancel() during provider operation error=%v", err)
	}
	stillRunning, err := store.Get(t.Context(), tenantID, task.ID)
	if err != nil || stillRunning.Job.State != jobstate.StateRunning ||
		stillRunning.Result.Operations[0].Status != dnscheck.OperationRunning {
		t.Fatalf("in-flight task changed = (%#v, %v)", stillRunning, err)
	}
	running.Operations[0].Status = dnscheck.OperationSucceeded
	running.Operations[0].ProviderRequestID = "provider-cancel-in-flight"
	running.Operations[0].ProviderRecordID = "record-cancel-in-flight"
	running.Operations[0].ProviderRevision = running.InitialRevision + 1
	running.Operations[0].ReportSequence = 2
	running.ProviderRevision = running.InitialRevision + 1
	running.UpdatedAt = clock.Now()
	completed, err := store.CheckpointApply(t.Context(), lease, running)
	if err != nil {
		t.Fatal(err)
	}
	cancel.ExpectedRevision = completed.Revision
	cancelled, _, err := store.Cancel(t.Context(), cancel)
	if err != nil || cancelled.Result.Status != dnscheck.TaskCancelled ||
		len(cancelled.Result.CompensationPlan) != 1 {
		t.Fatalf("Cancel() after provider fact = (%#v, %v)", cancelled, err)
	}
}

var dnsReconcileStoreNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

type dnsReconcileStoreClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *dnsReconcileStoreClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}

func (clock *dnsReconcileStoreClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.value = clock.value.Add(duration)
	clock.mu.Unlock()
}

func newDNSReconcileStore(t *testing.T, pool *pgxpool.Pool, clock *dnsReconcileStoreClock) *PostgresStore {
	t.Helper()
	jobs, err := jobstate.NewStore(pool, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgresStore(pool, jobs, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func claimDNSReconcileStore(
	t *testing.T,
	store *PostgresStore,
	tenantID uuid.UUID,
	workerID string,
	duration time.Duration,
) ApplyLease {
	t.Helper()
	claims, err := store.Claim(t.Context(), ClaimRequest{
		TenantID: tenantID, WorkerID: workerID, Limit: 1, LeaseDuration: duration,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("Claim() = (%#v, %v)", claims, err)
	}
	return claims[0]
}

// reclaimExpiredDNSReconcileStore follows the jobstate lease contract: the first claim
// after expiry only requeues the expired attempt behind the retry backoff (5s for
// attempt 1, jobstate/store_commands.go retryDelay), and the job is claimable again
// once that backoff has passed.
func reclaimExpiredDNSReconcileStore(
	t *testing.T,
	store *PostgresStore,
	clock *dnsReconcileStoreClock,
	tenantID uuid.UUID,
	workerID string,
	duration time.Duration,
) ApplyLease {
	t.Helper()
	early, err := store.Claim(t.Context(), ClaimRequest{
		TenantID: tenantID, WorkerID: workerID, Limit: 1, LeaseDuration: duration,
	})
	if err != nil || len(early) != 0 {
		t.Fatalf("expired lease ignored retry backoff: claims=%#v err=%v", early, err)
	}
	clock.Advance(5 * time.Second)
	return claimDNSReconcileStore(t, store, tenantID, workerID, duration)
}

func dnsReconcileStoreRequest(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID, siteID uuid.UUID,
	key, expectedValue string,
) (ApplyRequest, dnscheck.PreparedReconcile) {
	t.Helper()
	// The accepted-command audit row references users(id), so the actor must be a real
	// user: the seeded site owner is a tenant member, like a production caller.
	var actorUserID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT owner_user_id FROM sites WHERE id=$1`, siteID).
		Scan(&actorUserID); err != nil {
		t.Fatal(err)
	}
	check := dnscheck.CheckRequest{
		TenantID: tenantID, SiteID: siteID, Name: "www.example.test",
		Expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordA, Values: []string{expectedValue}}},
		TTL:      60, PropagationWindow: 5 * time.Minute,
		Provider: dnscheck.ProviderSnapshot{
			TenantID: tenantID, SiteID: siteID, ZoneID: uuid.New(), Revision: 7,
			Records: []dnscheck.ProviderRecord{{
				RecordID: "record-old", Name: "www.example.test", Type: dnscheck.RecordA,
				Value: "192.0.2.99", TTL: 60,
			}},
		},
	}
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{IdempotencyKey: key, Check: check},
		func() time.Time { return dnsReconcileStoreNow })
	if err != nil {
		t.Fatal(err)
	}
	return ApplyRequest{
		TenantID: tenantID, SiteID: siteID, ActorUserID: actorUserID, IdempotencyKey: key,
		RequestID: "request-" + key, Traceparent: "trace-" + key,
		ExpectedRevision: check.Provider.Revision, RequiredConsecutive: 3, Check: check,
	}, prepared
}

func readyDNSReconcileResult(result dnscheck.ReconcileResult, now time.Time) dnscheck.ReconcileResult {
	result.Status = dnscheck.TaskReadyToCommit
	result.ProviderRevision = result.InitialRevision + 1
	result.UpdatedAt = now
	readyAt := now
	result.ReadyAt = &readyAt
	for index := range result.Operations {
		result.Operations[index].Status = dnscheck.OperationSucceeded
		result.Operations[index].ProviderRequestID = fmt.Sprintf("provider-apply-%d", index+1)
		result.Operations[index].ProviderRecordID = fmt.Sprintf("record-new-%d", index+1)
		result.Operations[index].ProviderRevision = result.ProviderRevision
		result.Operations[index].ReportSequence = 2
	}
	result.Propagation = []dnscheck.PropagationAttempt{
		{Number: 1, CheckedAt: now, Status: dnscheck.ClassificationHealthy, ConsecutiveHealthy: 1},
		{Number: 2, CheckedAt: now, Status: dnscheck.ClassificationHealthy, ConsecutiveHealthy: 2},
		{Number: 3, CheckedAt: now, Status: dnscheck.ClassificationHealthy, ConsecutiveHealthy: 3},
	}
	// Migration 129 requires persisted checks to carry both an authoritative and a
	// public recursive observation, like the real propagation checker produces.
	result.LastCheck = &dnscheck.CheckResult{
		TenantID: result.TenantID, SiteID: result.SiteID, Name: "www.example.test",
		Status: dnscheck.ClassificationHealthy, Compliant: true, CheckedAt: now,
		Observations: []dnscheck.Observation{
			{Role: dnscheck.ResolverAuthoritative, Resolver: "ns1.example.test", RecordType: dnscheck.RecordA,
				Status: dnscheck.ClassificationHealthy, Values: []string{"192.0.2.10"}, Attempts: 1, MinimumTTL: 60},
			{Role: dnscheck.ResolverPublic, Resolver: "public-default", RecordType: dnscheck.RecordA,
				Status: dnscheck.ClassificationHealthy, Values: []string{"192.0.2.10"}, Attempts: 1, MinimumTTL: 60},
		},
	}
	return result
}

func committedDNSReconcileResult(result dnscheck.ReconcileResult, commandKey string, now time.Time) dnscheck.ReconcileResult {
	result.Status = dnscheck.TaskCommitted
	result.ProviderRevision++
	result.UpdatedAt = now
	for index := range result.DeferredDeletes {
		result.DeferredDeletes[index].Status = dnscheck.OperationSucceeded
		result.DeferredDeletes[index].ClientRequestID = operationRequestID(
			result.TenantID, commandKey, result.PayloadDigest, "commit",
			result.DeferredDeletes[index].SourceSequence,
		)
		result.DeferredDeletes[index].ProviderRequestID = fmt.Sprintf("provider-delete-%d", index+1)
		result.DeferredDeletes[index].ProviderRecordID = result.DeferredDeletes[index].Operation.RecordID
		result.DeferredDeletes[index].ProviderRevision = result.ProviderRevision
		result.DeferredDeletes[index].ReportSequence = 2
	}
	return result
}

func seedDNSReconcileStoreSite(t *testing.T, pool *pgxpool.Pool, suffix string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, "DNS "+suffix); err != nil {
		t.Fatal(err)
	}
	return seedDNSReconcileStoreSiteForTenant(t, pool, tenantID, suffix)
}

func seedDNSReconcileStoreSiteForTenant(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID uuid.UUID,
	suffix string,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var scopeID uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE tenant_id=$1`, tenantID).Scan(&scopeID)
	if err == pgx.ErrNoRows {
		scopeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	username := "dns076" + strings.ReplaceAll(userID.String(), "-", "")[:20]
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$3,'hash')`, userID, username, "DNS "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	siteID := uuid.New()
	domain := strings.ReplaceAll(suffix, "_", "-") + ".example.test"
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET CONSTRAINTS ALL DEFERRED`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id
		) VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`,
			siteID, scopeID, userID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port)
			VALUES($1,1,'origin.example.test',80)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return tenantID, siteID
}

func openDNSReconcileStoreDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// The store reads columns added after 076 (112 actor receipts and later), so the
	// schema is migrated to the release head like production.
	if pool := databasetest.ClonedMigratedPool(t, func(config *pgxpool.Config) { config.MaxConns = 16 }); pool != nil {
		return pool
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dnsreconcile_store_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^dnsreconcile_store_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.MaxConns = 16
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop DNS reconcile store schema: %v", err)
		}
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
