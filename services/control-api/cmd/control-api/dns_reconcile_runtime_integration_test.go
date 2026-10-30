//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDNSReconcileRuntimeRestartRequeuesTerminalRecoveredApply(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	fixture := seedDNSRuntimeRecovery(t, pool, 1)
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind, WorkerID: "dns-runtime-test",
		Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim job=(%+v,%v)", claims, err)
	}
	if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
		TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claims[0].WorkerID,
		LeaseID: claims[0].LeaseID, Report: jobstate.Report{
			ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
			Code: "provider_recovery_pending", Attempt: claims[0].Job.Attempt, Sequence: 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	operation := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
	}
	result := dnscheck.ReconcileResult{
		TenantID: fixture.tenantID, SiteID: fixture.siteID, ZoneID: fixture.zoneID,
		Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
		ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1, Operation: operation, ClientRequestID: fixture.clientRequestID,
			ProviderRequestID: fixture.providerRequestID, Status: dnscheck.OperationTransientFailed,
			ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
			ReportSequence: 2, Attempts: 3,
		}},
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at
	) VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient',
		'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
		t.Fatal(err)
	}
	claimID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_mutation_claims(
		tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,zone_id,provider_id,
		claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,
		expected_provider_revision,site_config_digest,operation_digest,authority_digest,
		provider_config_digest,credential_digest,provider_request_id,claimed_at
	) SELECT operation.tenant_id,operation.client_request_id,operation.job_id,operation.phase,
		operation.ordinal,task.site_id,task.zone_id,provider.id,$1,statement_timestamp()+interval '2 minutes',
		'claimed',site.revision,zone.revision,provider.revision,
		dns_reconcile_site_config_digest_089(site),dns_reconcile_operation_digest_089(operation.operation),
		dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider),
		dns_reconcile_provider_config_digest_089(zone,provider),
		dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext),
		$4,statement_timestamp()
	FROM dns_reconcile_operations operation
	JOIN dns_reconcile_tasks task ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
	JOIN sites site ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id
	JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
	JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
	WHERE operation.tenant_id=$2 AND operation.client_request_id=$3`, claimID,
		fixture.tenantID, fixture.clientRequestID, fixture.providerRequestID); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
			SET state='succeeded',provider_record_id='record-1',final_zone_revision=2,
			    finalized_at=clock_timestamp()
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
			fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE dns_zones SET revision=2,updated_at=clock_timestamp()
			WHERE id=$1 AND revision=1`, fixture.zoneID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	pending, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	source := &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending}
	tenants, err := source.PendingTenants(t.Context(), 10)
	if err != nil || len(tenants) != 1 || tenants[0] != fixture.tenantID {
		t.Fatalf("recovery tenants=(%v,%v)", tenants, err)
	}
	candidates, err := source.dueUncertainCandidates(t.Context(), fixture.tenantID, 10)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("recovery candidates=(%+v,%v)", candidates, err)
	}
	if _, err := prepareDNSReconcileRecoveryResult(candidates[0]); err != nil {
		t.Fatalf("prepare recovery candidate=%+v: %v", candidates[0], err)
	}
	if err := source.requeueDueUncertain(t.Context(), candidates[0]); err != nil {
		t.Fatal(err)
	}

	var jobState, itemState, eventStatus string
	var jobAttempt, maxAttempts, itemAttempt, itemSequence, attemptRows, continuationRows int
	var continuationConsumed bool
	var snapshot []byte
	if err := pool.QueryRow(t.Context(), `SELECT job.state,job.attempt,job.max_attempts,
		item.state,item.attempt,item.sequence,event.status,event.result_snapshot,
		(SELECT count(*) FROM background_job_attempts attempt
		 WHERE attempt.tenant_id=job.tenant_id AND attempt.job_id=job.id),
		(SELECT count(*) FROM dns_reconcile_provider_recovery_continuations continuation
		 WHERE continuation.tenant_id=job.tenant_id AND continuation.job_id=job.id),
		EXISTS(SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
		 WHERE continuation.tenant_id=job.tenant_id AND continuation.job_id=job.id
		   AND continuation.consumed_at IS NOT NULL)
		FROM background_jobs job
		JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
		JOIN LATERAL (
			SELECT status,result_snapshot FROM dns_reconcile_task_events
			WHERE tenant_id=job.tenant_id AND job_id=job.id ORDER BY event_sequence DESC LIMIT 1
		) event ON true WHERE job.tenant_id=$1 AND job.id=$2`, fixture.tenantID, fixture.jobID).
		Scan(&jobState, &jobAttempt, &maxAttempts, &itemState, &itemAttempt, &itemSequence,
			&eventStatus, &snapshot, &attemptRows, &continuationRows, &continuationConsumed); err != nil {
		t.Fatal(err)
	}
	var recovered dnscheck.ReconcileResult
	if json.Unmarshal(snapshot, &recovered) != nil || jobState != "queued" || itemState != "pending" ||
		eventStatus != "applying" || recovered.Status != dnscheck.TaskApplying ||
		recovered.Operations[0].Status != dnscheck.OperationPlanned ||
		recovered.Operations[0].Attempts != 3 || itemAttempt != 1 || itemSequence != 1 ||
		recovered.Operations[0].ClientRequestID != fixture.clientRequestID || maxAttempts != jobAttempt+1 {
		t.Fatalf("recovered job=%s attempt=%d/%d item=%s event=%s result=%+v",
			jobState, jobAttempt, maxAttempts, itemState, eventStatus, recovered)
	}
	if attemptRows != 1 || continuationRows != 1 || !continuationConsumed {
		t.Fatalf("recovery history attempts=%d continuations=%d consumed=%t",
			attemptRows, continuationRows, continuationConsumed)
	}

	restartedPending, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	restartedSource := &dnsReconcileRecoveryTenantSource{pool: pool, pending: restartedPending}
	if candidates, err := restartedSource.dueUncertainCandidates(t.Context(), fixture.tenantID, 10); err != nil || len(candidates) != 0 {
		t.Fatalf("restart recovery candidates=(%+v,%v), want none after atomic requeue", candidates, err)
	}
	restartedJobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	continued, err := restartedJobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind, WorkerID: "dns-runtime-restart",
		Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(continued) != 1 || int(continued[0].Job.Attempt) != maxAttempts {
		t.Fatalf("restart continuation=(%+v,%v), want exact recovery attempt %d", continued, err, maxAttempts)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM background_job_attempts
		WHERE tenant_id=$1 AND job_id=$2`, fixture.tenantID, fixture.jobID).Scan(&attemptRows); err != nil {
		t.Fatal(err)
	}
	if attemptRows != 2 {
		t.Fatalf("background attempt rows=%d, want immutable history plus continuation", attemptRows)
	}
	duplicate, err := restartedJobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind, WorkerID: "dns-runtime-duplicate",
		Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(duplicate) != 0 {
		t.Fatalf("duplicate recovery continuation=(%+v,%v)", duplicate, err)
	}
}

func TestDNSReconcileRuntimeTerminalRecoveryBypassesExhaustedMutationAttempts(t *testing.T) {
	for _, claimState := range []string{
		string(dnsproviderremote.MutationConflict),
		string(dnsproviderremote.MutationNotApplied),
	} {
		t.Run(claimState, func(t *testing.T) {
			pool := newDashboardCompositionTestPool(t)
			fixture := seedDNSRuntimeRecovery(t, pool, 1)
			jobs, err := jobstate.NewStore(pool, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
				TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind, WorkerID: "dns-runtime-terminal-test",
				Limit: 1, LeaseDuration: time.Minute,
			})
			if err != nil || len(claims) != 1 {
				t.Fatalf("claim job=(%+v,%v)", claims, err)
			}
			if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
				TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claims[0].WorkerID,
				LeaseID: claims[0].LeaseID, Report: jobstate.Report{
					ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
					Code: "provider_recovery_pending", Attempt: claims[0].Job.Attempt, Sequence: 1,
				},
			}); err != nil {
				t.Fatal(err)
			}
			operation := dnscheck.ProviderOperation{
				Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
			}
			result := dnscheck.ReconcileResult{
				TenantID: fixture.tenantID, SiteID: fixture.siteID, ZoneID: fixture.zoneID,
				Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
				ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
				Operations: []dnscheck.OperationResult{{
					SourceSequence: 1, Operation: operation, ClientRequestID: fixture.clientRequestID,
					ProviderRequestID: fixture.providerRequestID, Status: dnscheck.OperationTransientFailed,
					ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
					ReportSequence: 2, Attempts: 3,
				}},
			}
			resultJSON, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
				tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
				compensation_plan,error_class,error_code,occurred_at
			) VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient',
				'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
				t.Fatal(err)
			}
			claimID := uuid.New()
			if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_mutation_claims(
				tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,zone_id,provider_id,
				claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,
				expected_provider_revision,site_config_digest,operation_digest,authority_digest,
				provider_config_digest,credential_digest,provider_request_id,claimed_at
			) SELECT operation.tenant_id,operation.client_request_id,operation.job_id,operation.phase,
				operation.ordinal,task.site_id,task.zone_id,provider.id,$1,statement_timestamp()+interval '2 minutes',
				'claimed',site.revision,zone.revision,provider.revision,
				dns_reconcile_site_config_digest_089(site),dns_reconcile_operation_digest_089(operation.operation),
				dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider),
				dns_reconcile_provider_config_digest_089(zone,provider),
				dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext),
				$4,statement_timestamp()
			FROM dns_reconcile_operations operation
			JOIN dns_reconcile_tasks task ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
			JOIN sites site ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id
			JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
			JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
			WHERE operation.tenant_id=$2 AND operation.client_request_id=$3`, claimID,
				fixture.tenantID, fixture.clientRequestID, fixture.providerRequestID); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
				SET state=$4,lease_expires_at=clock_timestamp(),final_zone_revision=expected_zone_revision,
				    finalized_at=clock_timestamp()
				WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`, fixture.tenantID,
				fixture.clientRequestID, claimID, claimState); err != nil {
				t.Fatal(err)
			}

			pending, err := dnsreconcile.NewPostgresTenantSource(pool)
			if err != nil {
				t.Fatal(err)
			}
			source := &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending}
			candidates, err := source.dueUncertainCandidates(t.Context(), fixture.tenantID, 10)
			if err != nil || len(candidates) != 1 {
				t.Fatalf("recovery candidates=(%+v,%v)", candidates, err)
			}
			if err := source.requeueDueUncertain(t.Context(), candidates[0]); err != nil {
				t.Fatalf("terminal %s recovery: %v", claimState, err)
			}

			var jobState, itemState, storedClaimState, storedRequestID string
			var attempt, maxAttempts, itemAttempt, itemSequence, eventCount, continuationCount int
			if err := pool.QueryRow(t.Context(), `SELECT job.state,job.attempt,job.max_attempts,item.state,
				item.attempt,item.sequence,claim.state,claim.provider_request_id,
				(SELECT count(*) FROM dns_reconcile_task_events event
				 WHERE event.tenant_id=job.tenant_id AND event.job_id=job.id),
				(SELECT count(*) FROM dns_reconcile_provider_recovery_continuations continuation
				 WHERE continuation.tenant_id=job.tenant_id AND continuation.job_id=job.id)
				FROM background_jobs job
				JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
				JOIN dns_reconcile_provider_mutation_claims claim
				  ON claim.tenant_id=job.tenant_id AND claim.job_id=job.id
				WHERE job.tenant_id=$1 AND job.id=$2`, fixture.tenantID, fixture.jobID).Scan(
				&jobState, &attempt, &maxAttempts, &itemState, &itemAttempt, &itemSequence,
				&storedClaimState, &storedRequestID, &eventCount, &continuationCount,
			); err != nil {
				t.Fatal(err)
			}
			if jobState != "queued" || itemState != "pending" || itemAttempt != 1 || itemSequence != 1 ||
				maxAttempts != attempt+1 || eventCount != 2 || continuationCount != 1 ||
				storedClaimState != claimState || storedRequestID != fixture.providerRequestID {
				t.Fatalf("terminal recovery job=%s attempt=%d/%d item=%s claim=%s request=%s events=%d",
					jobState, attempt, maxAttempts, itemState, storedClaimState, storedRequestID, eventCount)
			}
			restarted := &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending}
			if candidates, err := restarted.dueUncertainCandidates(t.Context(), fixture.tenantID, 10); err != nil || len(candidates) != 0 {
				t.Fatalf("restart candidates=(%+v,%v), want terminal recovery consumed exactly once", candidates, err)
			}

			continuation, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
				TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind,
				WorkerID: "dns-runtime-terminal-continuation", Limit: 1, LeaseDuration: time.Minute,
			})
			if err != nil || len(continuation) != 1 || continuation[0].Job.Attempt != 2 {
				t.Fatalf("claim continuation=(%+v,%v)", continuation, err)
			}
			if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
				TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: continuation[0].WorkerID,
				LeaseID: continuation[0].LeaseID, Report: jobstate.Report{
					ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
					Code: "provider_recovery_pending", Attempt: 2, Sequence: 2,
				},
			}); err != nil {
				t.Fatal(err)
			}
			result.Status = dnscheck.TaskFailed
			result.ErrorClass = dnscheck.ProviderErrorTransient
			result.ErrorCode = "provider_recovery_pending"
			result.Operations[0].Status = dnscheck.OperationTransientFailed
			result.Operations[0].ErrorClass = dnscheck.ProviderErrorTransient
			result.Operations[0].ErrorCode = "provider_recovery_pending"
			result.Operations[0].ReportSequence = 3
			result.Operations[0].Attempts = 4
			resultJSON, err = json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
				tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
				compensation_plan,error_class,error_code,occurred_at)
				VALUES($1,$2,3,'control','failed',1,$3,'[]'::jsonb,'transient',
				'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
				t.Fatal(err)
			}
			candidates, err = restarted.dueUncertainCandidates(t.Context(), fixture.tenantID, 10)
			if err != nil || len(candidates) != 0 {
				t.Fatalf("exhausted continuation candidates=(%+v,%v), want consumed claim excluded", candidates, err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT max_attempts,
				(SELECT count(*) FROM dns_reconcile_provider_recovery_continuations continuation
				 WHERE continuation.tenant_id=job.tenant_id AND continuation.job_id=job.id)
				FROM background_jobs job WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.jobID).
				Scan(&maxAttempts, &continuationCount); err != nil {
				t.Fatal(err)
			}
			if maxAttempts != 2 || continuationCount != 1 {
				t.Fatalf("repeated continuation max_attempts=%d facts=%d", maxAttempts, continuationCount)
			}
		})
	}
}

func TestDNSReconcileRuntimeBadCandidateDoesNotStarveRecoveryOrPending(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	fixture := seedDNSRuntimeRecovery(t, pool, 1)
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind, WorkerID: "dns-runtime-fairness",
		Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim job=(%+v,%v)", claimed, err)
	}
	if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
		TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claimed[0].WorkerID,
		LeaseID: claimed[0].LeaseID, Report: jobstate.Report{
			ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
			Code: "provider_recovery_pending", Attempt: 1, Sequence: 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	goodOperation := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
	}
	badOperation := dnscheck.ProviderOperation{
		Sequence: 2, Action: dnscheck.ProviderCreate, Name: "bad.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.20", TTL: 300, Reason: "missing_record",
	}
	badSnapshotOperation := badOperation
	badSnapshotOperation.Value = "192.0.2.21"
	badClientRequestID := "aaa-runtime-bad-candidate"
	badOperationJSON, err := json.Marshal(badOperation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_operations(
		tenant_id,job_id,phase,ordinal,source_sequence,action,client_request_id,operation,created_at)
		VALUES($1,$2,'apply',2,2,'create',$3,$4::jsonb,clock_timestamp())`,
		fixture.tenantID, fixture.jobID, badClientRequestID, badOperationJSON); err != nil {
		t.Fatal(err)
	}
	result := dnscheck.ReconcileResult{
		TenantID: fixture.tenantID, SiteID: fixture.siteID, ZoneID: fixture.zoneID,
		Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
		ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
		Operations: []dnscheck.OperationResult{
			{SourceSequence: 1, Operation: goodOperation, ClientRequestID: fixture.clientRequestID,
				ProviderRequestID: fixture.providerRequestID, Status: dnscheck.OperationTransientFailed,
				ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
				ReportSequence: 2, Attempts: 3},
			{SourceSequence: 2, Operation: badSnapshotOperation, ClientRequestID: badClientRequestID,
				ProviderRequestID: dnsproviderremote.ProviderMutationRequestID(badClientRequestID),
				Status:            dnscheck.OperationTransientFailed, ErrorClass: dnscheck.ProviderErrorTransient,
				ErrorCode: "provider_recovery_pending", ReportSequence: 2, Attempts: 3},
		},
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at)
		VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient',
		'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
		t.Fatal(err)
	}
	insertTerminalClaim := func(clientRequestID, state string) {
		t.Helper()
		claimID := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_mutation_claims(
			tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,zone_id,provider_id,
			claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,
			expected_provider_revision,site_config_digest,operation_digest,authority_digest,
			provider_config_digest,credential_digest,provider_request_id,claimed_at)
			SELECT operation.tenant_id,operation.client_request_id,operation.job_id,operation.phase,
			operation.ordinal,task.site_id,task.zone_id,provider.id,$1,statement_timestamp()+interval '2 minutes',
			'claimed',site.revision,zone.revision,provider.revision,
			dns_reconcile_site_config_digest_089(site),dns_reconcile_operation_digest_089(operation.operation),
			dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider),
			dns_reconcile_provider_config_digest_089(zone,provider),
			dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext),
			$4,statement_timestamp()
			FROM dns_reconcile_operations operation
			JOIN dns_reconcile_tasks task ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
			JOIN sites site ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id
			JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
			JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
			WHERE operation.tenant_id=$2 AND operation.client_request_id=$3`, claimID,
			fixture.tenantID, clientRequestID, dnsproviderremote.ProviderMutationRequestID(clientRequestID)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
			SET state=$4,lease_expires_at=clock_timestamp(),final_zone_revision=expected_zone_revision,
			    finalized_at=clock_timestamp()
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
			fixture.tenantID, clientRequestID, claimID, state); err != nil {
			t.Fatal(err)
		}
	}
	insertTerminalClaim(badClientRequestID, string(dnsproviderremote.MutationConflict))
	insertTerminalClaim(fixture.clientRequestID, string(dnsproviderremote.MutationNotApplied))

	pendingSource, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &dnsRecoveryPendingRecorder{}
	runner := &dnsReconcileRecoveryRunner{
		source:  &dnsReconcileRecoveryTenantSource{pool: pool, pending: pendingSource},
		pending: recorder, providers: unusedDNSRecoveryProviderResolver{},
	}
	if _, err := runner.RunOnce(t.Context(), fixture.tenantID, "dns-runtime-pending", 10); err != nil {
		t.Fatalf("run recovery fairness: %v", err)
	}
	var disposition, reason string
	var failureCount, maxAttempts, continuationCount int
	if err := pool.QueryRow(t.Context(), `SELECT failure.disposition,failure.reason_code,failure.failure_count,
		job.max_attempts,(SELECT count(*) FROM dns_reconcile_provider_recovery_continuations continuation
		 WHERE continuation.tenant_id=job.tenant_id AND continuation.job_id=job.id)
		FROM dns_reconcile_provider_recovery_failures failure
		JOIN background_jobs job ON job.tenant_id=failure.tenant_id AND job.id=$3
		WHERE failure.tenant_id=$1 AND failure.client_request_id=$2`,
		fixture.tenantID, badClientRequestID, fixture.jobID).
		Scan(&disposition, &reason, &failureCount, &maxAttempts, &continuationCount); err != nil {
		t.Fatal(err)
	}
	if disposition != "quarantined" || reason != "provider_recovery_candidate_invalid" ||
		failureCount != 1 || maxAttempts != 2 || continuationCount != 1 || recorder.calls != 1 {
		t.Fatalf("fair recovery disposition=%s reason=%s failures=%d max=%d continuations=%d pending=%d",
			disposition, reason, failureCount, maxAttempts, continuationCount, recorder.calls)
	}
	if _, err := runner.RunOnce(t.Context(), fixture.tenantID, "dns-runtime-pending-restart", 10); err != nil {
		t.Fatalf("restart recovery fairness: %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT failure_count FROM dns_reconcile_provider_recovery_failures
		WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, badClientRequestID).
		Scan(&failureCount); err != nil {
		t.Fatal(err)
	}
	if failureCount != 1 || recorder.calls != 2 {
		t.Fatalf("quarantined candidate busy-looped failures=%d pending=%d", failureCount, recorder.calls)
	}
}

func TestDNSReconcileRuntimeLookupFailureAndTenantCapacitySurviveRestart(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	bad := seedDNSRuntimeRecovery(t, pool, 1)
	good := seedDNSRuntimeRecovery(t, pool, 1)
	ordinary := seedDNSRuntimeRecovery(t, pool, 1)
	markDNSRuntimeRecoveryDue(t, pool, bad, string(dnsproviderremote.MutationUncertain))
	markDNSRuntimeRecoveryDue(t, pool, good, string(dnsproviderremote.MutationNotApplied))

	pending, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	source := &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending}
	tenants, err := source.PendingTenants(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !containsDNSRuntimeTenant(tenants, ordinary.tenantID) {
		t.Errorf("recovery tenants exhausted capacity and starved ordinary tenant: %v", tenants)
	}

	provider := &failingDNSRecoveryLookupAdapter{}
	runner := &dnsReconcileRecoveryRunner{
		source: source, pending: &dnsRecoveryPendingRecorder{},
		providers: fixedDNSRecoveryProviderResolver{provider: provider},
	}
	if err := runner.recoverDueUncertain(t.Context(), bad.tenantID, 10); err != nil {
		t.Fatalf("persist bad recovery lookup: %v", err)
	}
	var reason, disposition string
	var failureCount int
	if err := pool.QueryRow(t.Context(), `SELECT reason_code,disposition,failure_count
		FROM dns_reconcile_provider_recovery_failures
		WHERE tenant_id=$1 AND client_request_id=$2`, bad.tenantID, bad.clientRequestID).
		Scan(&reason, &disposition, &failureCount); err != nil {
		t.Errorf("lookup failure was not durable: %v", err)
	} else if reason != "provider_recovery_lookup_failed" || disposition != "backoff" || failureCount != 1 {
		t.Errorf("lookup failure fact=(%s,%s,%d)", reason, disposition, failureCount)
	}
	if provider.calls != 1 {
		t.Errorf("bad recovery provider calls=%d, want 1", provider.calls)
	}

	if err := runner.recoverDueUncertain(t.Context(), good.tenantID, 10); err != nil {
		t.Fatalf("requeue good terminal recovery: %v", err)
	}
	var continuations int
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM dns_reconcile_provider_recovery_continuations
		WHERE tenant_id=$1 AND job_id=$2`, good.tenantID, good.jobID).Scan(&continuations); err != nil {
		t.Fatal(err)
	}
	if continuations != 1 {
		t.Errorf("good recovery continuations=%d, want 1", continuations)
	}

	restartedPending, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	restartedSource := &dnsReconcileRecoveryTenantSource{pool: pool, pending: restartedPending}
	restartedRunner := &dnsReconcileRecoveryRunner{
		source: restartedSource, pending: &dnsRecoveryPendingRecorder{},
		providers: fixedDNSRecoveryProviderResolver{provider: provider},
	}
	if err := restartedRunner.recoverDueUncertain(t.Context(), bad.tenantID, 10); err != nil {
		t.Fatalf("restart recovery scan: %v", err)
	}
	if provider.calls != 1 {
		t.Errorf("restart bypassed durable lookup backoff; provider calls=%d", provider.calls)
	}
	tenants, err = restartedSource.PendingTenants(t.Context(), 2)
	if err != nil || !containsDNSRuntimeTenant(tenants, ordinary.tenantID) {
		t.Fatalf("restart ordinary tenant selection=(%v,%v)", tenants, err)
	}
}

func TestDNSReconcileRuntimeRecoveryLeaseFencesTwoWorkers(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	fixture := seedDNSRuntimeRecovery(t, pool, 1)
	markDNSRuntimeRecoveryDue(t, pool, fixture, string(dnsproviderremote.MutationUncertain))
	pending, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	provider := &blockingDNSRecoveryLookupAdapter{
		pool: pool, fixture: fixture, entered: make(chan struct{}, 2), release: make(chan struct{}),
	}
	newRunner := func() *dnsReconcileRecoveryRunner {
		return &dnsReconcileRecoveryRunner{
			source:    &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending},
			pending:   &dnsRecoveryPendingRecorder{},
			providers: fixedDNSRecoveryProviderResolver{provider: provider},
		}
	}
	runnerA, runnerB := newRunner(), newRunner()
	doneA := make(chan error, 1)
	go func() { doneA <- runnerA.recoverDueUncertain(t.Context(), fixture.tenantID, 10) }()
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		t.Fatal("worker A did not enter provider recovery")
	}
	doneB := make(chan error, 1)
	go func() { doneB <- runnerB.recoverDueUncertain(t.Context(), fixture.tenantID, 10) }()
	secondMutation := false
	select {
	case <-provider.entered:
		secondMutation = true
	case err := <-doneB:
		if err != nil {
			t.Errorf("worker B recovery: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("worker B neither observed the durable recovery lease nor reached the provider")
	}
	provider.releaseOnce.Do(func() { close(provider.release) })
	if err := <-doneA; err != nil {
		t.Errorf("worker A recovery: %v", err)
	}
	if secondMutation {
		if err := <-doneB; err != nil {
			t.Logf("worker B stale recovery returned %v", err)
		}
		t.Errorf("two workers entered provider recovery for one uncertain claim")
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Fatalf("provider recovery calls=%d, want 1", calls)
	}
	var continuations int
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM dns_reconcile_provider_recovery_continuations
		WHERE tenant_id=$1 AND job_id=$2`, fixture.tenantID, fixture.jobID).Scan(&continuations); err != nil {
		t.Fatal(err)
	}
	if continuations != 1 {
		t.Fatalf("recovery continuations=%d, want 1", continuations)
	}
	if err := newRunner().recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
		t.Fatal(err)
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Fatalf("restart repeated provider recovery calls=%d", calls)
	}
}

func TestDNSReconcileRuntimeRecoveryFailurePersistenceIsRetryable(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	bad := seedDNSRuntimeRecovery(t, pool, 1)
	ordinary := seedDNSRuntimeRecovery(t, pool, 1)
	markDNSRuntimeRecoveryDue(t, pool, bad, string(dnsproviderremote.MutationUncertain))
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION dns_round10_fail_recovery_backoff()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'injected DNS recovery backoff persistence failure';
		END;
		$$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TRIGGER dns_round10_fail_recovery_backoff
		BEFORE INSERT OR UPDATE ON dns_reconcile_provider_recovery_failures
		FOR EACH ROW EXECUTE FUNCTION dns_round10_fail_recovery_backoff()`); err != nil {
		t.Fatal(err)
	}
	dropFailureInjection := func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS dns_round10_fail_recovery_backoff
			ON dns_reconcile_provider_recovery_failures`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS dns_round10_fail_recovery_backoff()`)
	}
	t.Cleanup(dropFailureInjection)
	pending, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	provider := &failingDNSRecoveryLookupAdapter{}
	runner := &dnsReconcileRecoveryRunner{
		source:    &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending},
		pending:   &dnsRecoveryPendingRecorder{},
		providers: fixedDNSRecoveryProviderResolver{provider: provider},
	}
	if err := runner.recoverDueUncertain(t.Context(), bad.tenantID, 10); !errors.Is(err, dnsreconcile.ErrUnavailable) {
		t.Fatalf("recovery persistence failure=%v, want retryable unavailable", err)
	}
	dropFailureInjection()
	var leaseState string
	var leaseActive bool
	if err := pool.QueryRow(t.Context(), `SELECT state,lease_expires_at>clock_timestamp()
		FROM dns_reconcile_provider_recovery_leases
		WHERE tenant_id=$1 AND client_request_id=$2
		ORDER BY claimed_at DESC LIMIT 1`, bad.tenantID, bad.clientRequestID).
		Scan(&leaseState, &leaseActive); err != nil {
		t.Fatal(err)
	}
	if leaseState != "active" || !leaseActive {
		t.Fatalf("failed persistence recovery lease=(%s,%t), want active", leaseState, leaseActive)
	}
	restarted := &dnsReconcileRecoveryRunner{
		source:    &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending},
		pending:   &dnsRecoveryPendingRecorder{},
		providers: fixedDNSRecoveryProviderResolver{provider: provider},
	}
	if err := restarted.recoverDueUncertain(t.Context(), bad.tenantID, 10); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("restart bypassed unpersisted-backoff lease; provider calls=%d", provider.calls)
	}
	tenants, err := restarted.source.PendingTenants(t.Context(), 1)
	if err != nil || len(tenants) != 1 || tenants[0] != ordinary.tenantID {
		t.Fatalf("ordinary tenant fairness=(%v,%v), want %s", tenants, err, ordinary.tenantID)
	}
}

func TestDNSReconcileRuntimeRealAdapterRecoveryLeaseSuccessFailureRetry(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	newRunner := func(resolver dnsreconcile.ProviderResolver) *dnsReconcileRecoveryRunner {
		t.Helper()
		pending, err := dnsreconcile.NewPostgresTenantSource(pool)
		if err != nil {
			t.Fatal(err)
		}
		return &dnsReconcileRecoveryRunner{
			source:    &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending},
			pending:   &dnsRecoveryPendingRecorder{},
			providers: resolver,
		}
	}
	t.Run("success", func(t *testing.T) {
		fixture := seedDNSRuntimeRecovery(t, pool, 1)
		remote := &realDNSRecoveryRemote{}
		resolver := newDNSRuntimeRealProviderResolver(t, pool, fixture, remote)
		runner := newRunner(resolver)
		markDNSRuntimeRecoveryDue(t, pool, fixture, string(dnsproviderremote.MutationUncertain))
		oldClaimID := dnsRuntimeClaimID(t, pool, fixture)
		if err := runner.recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
			t.Fatal(err)
		}
		assertDNSRuntimeRealRecovery(t, pool, fixture, oldClaimID, remote, 1)
		if err := newRunner(resolver).recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
			t.Fatal(err)
		}
		if remote.lookups.Load() != 1 || remote.mutations.Load() != 0 {
			t.Fatalf("restart provider calls lookup=%d mutation=%d",
				remote.lookups.Load(), remote.mutations.Load())
		}
	})
	t.Run("failure and retry", func(t *testing.T) {
		fixture := seedDNSRuntimeRecovery(t, pool, 1)
		remote := &realDNSRecoveryRemote{}
		remote.failLookups.Store(1)
		resolver := newDNSRuntimeRealProviderResolver(t, pool, fixture, remote)
		runner := newRunner(resolver)
		markDNSRuntimeRecoveryDue(t, pool, fixture, string(dnsproviderremote.MutationUncertain))
		oldClaimID := dnsRuntimeClaimID(t, pool, fixture)
		if err := runner.recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
			t.Fatalf("persist real adapter lookup failure: %v", err)
		}
		rotatedClaimID := dnsRuntimeClaimID(t, pool, fixture)
		if rotatedClaimID == oldClaimID {
			t.Fatal("real adapter did not rotate the provider claim before lookup")
		}
		var failureLeaseID uuid.UUID
		var leaseState, disposition, reason string
		if err := pool.QueryRow(t.Context(), `SELECT failure.recovery_lease_id,
			lease.state,failure.disposition,failure.reason_code
			FROM dns_reconcile_provider_recovery_failures failure
			JOIN dns_reconcile_provider_recovery_leases lease
			  ON lease.tenant_id=failure.tenant_id
			 AND lease.client_request_id=failure.client_request_id
			 AND lease.recovery_lease_id=failure.recovery_lease_id
			WHERE failure.tenant_id=$1 AND failure.client_request_id=$2`,
			fixture.tenantID, fixture.clientRequestID).
			Scan(&failureLeaseID, &leaseState, &disposition, &reason); err != nil {
			t.Fatal(err)
		}
		if failureLeaseID == uuid.Nil || leaseState != "released" || disposition != "backoff" ||
			reason != "provider_recovery_lookup_failed" {
			t.Fatalf("failure lease=%s/%s disposition=%s reason=%s",
				failureLeaseID, leaseState, disposition, reason)
		}
		if err := newRunner(resolver).recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
			t.Fatal(err)
		}
		if remote.lookups.Load() != 1 {
			t.Fatalf("restart bypassed durable backoff; lookups=%d", remote.lookups.Load())
		}
		forceDNSRuntimeRealRecoveryRetry(t, pool, fixture)
		if err := newRunner(resolver).recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
			t.Fatal(err)
		}
		assertDNSRuntimeRealRecovery(t, pool, fixture, rotatedClaimID, remote, 2)
	})
}

func TestDNSReconcileRuntimeRealAdapterRecoveryLeaseLinearizesWorkers(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	fixture := seedDNSRuntimeRecovery(t, pool, 1)
	remote := &realDNSRecoveryRemote{entered: make(chan struct{}, 2), release: make(chan struct{})}
	resolver := newDNSRuntimeRealProviderResolver(t, pool, fixture, remote)
	markDNSRuntimeRecoveryDue(t, pool, fixture, string(dnsproviderremote.MutationUncertain))
	oldClaimID := dnsRuntimeClaimID(t, pool, fixture)
	newRunner := func() *dnsReconcileRecoveryRunner {
		pending, err := dnsreconcile.NewPostgresTenantSource(pool)
		if err != nil {
			t.Fatal(err)
		}
		return &dnsReconcileRecoveryRunner{
			source:  &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending},
			pending: &dnsRecoveryPendingRecorder{}, providers: resolver,
		}
	}
	doneA := make(chan error, 1)
	go func() { doneA <- newRunner().recoverDueUncertain(t.Context(), fixture.tenantID, 10) }()
	select {
	case <-remote.entered:
	case <-time.After(time.Second):
		t.Fatal("worker A did not enter real adapter lookup")
	}
	if rotated := dnsRuntimeClaimID(t, pool, fixture); rotated == oldClaimID {
		t.Fatal("real adapter lookup started before claim token rotation")
	}
	doneB := make(chan error, 1)
	go func() { doneB <- newRunner().recoverDueUncertain(t.Context(), fixture.tenantID, 10) }()
	secondLookup := false
	select {
	case <-remote.entered:
		secondLookup = true
	case err := <-doneB:
		if err != nil {
			t.Errorf("worker B recovery: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("worker B neither observed the stable recovery lease nor entered lookup")
	}
	close(remote.release)
	if err := <-doneA; err != nil {
		t.Errorf("worker A recovery: %v", err)
	}
	if secondLookup {
		if err := <-doneB; err != nil {
			t.Logf("worker B stale recovery returned %v", err)
		}
		t.Error("two workers entered the real adapter lookup")
	}
	assertDNSRuntimeRealRecovery(t, pool, fixture, oldClaimID, remote, 1)
	if err := newRunner().recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
		t.Fatal(err)
	}
	if remote.lookups.Load() != 1 || remote.mutations.Load() != 0 {
		t.Fatalf("restart provider calls lookup=%d mutation=%d",
			remote.lookups.Load(), remote.mutations.Load())
	}
}

func markDNSRuntimeRecoveryDue(t *testing.T, pool *pgxpool.Pool, fixture dnsRuntimeRecoveryFixture,
	state string,
) {
	t.Helper()
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind,
		WorkerID: "dns-runtime-round9", Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim recovery fixture=(%+v,%v)", claimed, err)
	}
	if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
		TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claimed[0].WorkerID,
		LeaseID: claimed[0].LeaseID, Report: jobstate.Report{
			ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
			Code: "provider_recovery_pending", Attempt: 1, Sequence: 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	operation := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
	}
	resultJSON, err := json.Marshal(dnscheck.ReconcileResult{
		TenantID: fixture.tenantID, SiteID: fixture.siteID, ZoneID: fixture.zoneID,
		Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
		ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1, Operation: operation, ClientRequestID: fixture.clientRequestID,
			ProviderRequestID: fixture.providerRequestID, Status: dnscheck.OperationTransientFailed,
			ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
			ReportSequence: 1, Attempts: 3,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at)
		VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient',
		'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
		t.Fatal(err)
	}
	claimID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_mutation_claims(
		tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,zone_id,provider_id,
		claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,
		expected_provider_revision,site_config_digest,operation_digest,authority_digest,
		provider_config_digest,credential_digest,provider_request_id,claimed_at)
		SELECT operation.tenant_id,operation.client_request_id,operation.job_id,operation.phase,
		operation.ordinal,task.site_id,task.zone_id,provider.id,$1,statement_timestamp()+interval '2 minutes',
		'claimed',site.revision,zone.revision,provider.revision,
		dns_reconcile_site_config_digest_089(site),dns_reconcile_operation_digest_089(operation.operation),
		dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider),
		dns_reconcile_provider_config_digest_089(zone,provider),
		dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext),
		$4,statement_timestamp()
		FROM dns_reconcile_operations operation
		JOIN dns_reconcile_tasks task ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
		JOIN sites site ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id
		JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		WHERE operation.tenant_id=$2 AND operation.client_request_id=$3`, claimID,
		fixture.tenantID, fixture.clientRequestID, fixture.providerRequestID); err != nil {
		t.Fatal(err)
	}
	if state == string(dnsproviderremote.MutationUncertain) {
		if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
			SET state='uncertain',lease_expires_at=clock_timestamp()
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
			fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
			t.Fatal(err)
		}
		connection, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
			connection.Release()
			t.Fatal(err)
		}
		_, updateErr := connection.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
			SET lease_expires_at=GREATEST(claimed_at,clock_timestamp()-interval '1 microsecond'),
			    recovery_not_before=clock_timestamp()-interval '1 microsecond'
			WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, fixture.clientRequestID)
		_, resetErr := connection.Exec(t.Context(), `SET session_replication_role=origin`)
		connection.Release()
		if updateErr != nil || resetErr != nil {
			t.Fatalf("force runtime recovery due=(%v,%v)", updateErr, resetErr)
		}
		return
	}
	if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state=$4,final_zone_revision=expected_zone_revision,finalized_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`, fixture.tenantID,
		fixture.clientRequestID, claimID, state); err != nil {
		t.Fatal(err)
	}
}

func containsDNSRuntimeTenant(tenants []uuid.UUID, target uuid.UUID) bool {
	for _, tenantID := range tenants {
		if tenantID == target {
			return true
		}
	}
	return false
}

type fixedDNSRecoveryProviderResolver struct{ provider dnscheck.ProviderAdapter }

func (resolver fixedDNSRecoveryProviderResolver) ResolveProvider(context.Context, uuid.UUID, uuid.UUID,
	uuid.UUID,
) (dnscheck.ProviderAdapter, error) {
	return resolver.provider, nil
}

type failingDNSRecoveryLookupAdapter struct{ calls int }

func (*failingDNSRecoveryLookupAdapter) CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error) {
	return 1, nil
}

func (adapter *failingDNSRecoveryLookupAdapter) Mutate(context.Context,
	dnscheck.ProviderMutation,
) (dnscheck.ProviderMutationResult, error) {
	adapter.calls++
	return dnscheck.ProviderMutationResult{}, errors.New("injected provider recovery lookup failure")
}

type blockingDNSRecoveryLookupAdapter struct {
	pool        *pgxpool.Pool
	fixture     dnsRuntimeRecoveryFixture
	calls       atomic.Int32
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

type realDNSRecoveryRemote struct {
	lookups     atomic.Int32
	mutations   atomic.Int32
	failLookups atomic.Int32
	entered     chan struct{}
	release     chan struct{}
}

func (remote *realDNSRecoveryRemote) Lookup(ctx context.Context, _ dnsproviderremote.ProviderConfig,
	_ dnscheck.ProviderOperation,
) (dnsproviderremote.ReconcileLookup, error) {
	remote.lookups.Add(1)
	if remote.entered != nil {
		remote.entered <- struct{}{}
		select {
		case <-remote.release:
		case <-ctx.Done():
			return dnsproviderremote.ReconcileLookup{}, ctx.Err()
		}
	}
	for {
		remaining := remote.failLookups.Load()
		if remaining < 1 || remote.failLookups.CompareAndSwap(remaining, remaining-1) {
			if remaining > 0 {
				return dnsproviderremote.ReconcileLookup{}, &dnsproviderremote.Error{
					Code: dnsproviderremote.CodeUnavailable, Temporary: true,
				}
			}
			break
		}
	}
	return dnsproviderremote.ReconcileLookup{TargetComplete: true, RecordID: "real-recovery-record"}, nil
}

func (remote *realDNSRecoveryRemote) Mutate(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation,
) (string, error) {
	remote.mutations.Add(1)
	return "", errors.New("recovery attempted a second provider mutation")
}

func newDNSRuntimeRealProviderResolver(t *testing.T, pool *pgxpool.Pool,
	fixture dnsRuntimeRecoveryFixture, remote dnsproviderremote.ReconcileRemote,
) dnsreconcile.ProviderResolver {
	t.Helper()
	key := make([]byte, 32)
	for index := range key {
		key[index] = 0x5a
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-runtime-real", key)
	if err != nil {
		t.Fatal(err)
	}
	// 读路径（DecryptCredential）只接受绑定租户/作用域/提供商的 v2 信封
	keyID, ciphertext, err := cipher.EncryptCredential(dnsacme.CredentialBinding{
		TenantID: fixture.tenantID, ScopeID: fixture.scopeID, ProviderID: fixture.providerID,
	}, []byte(`{"api_token":"runtime-real-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE dns_providers
		SET credential_key_id=$2,credential_ciphertext=$3
		WHERE id=$1`, fixture.providerID, keyID, ciphertext); err != nil {
		t.Fatal(err)
	}
	resolver, err := dnsproviderremotesource.NewReconcileResolver(
		dnsproviderremotesource.New(pool, cipher), remote,
	)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func dnsRuntimeClaimID(t *testing.T, pool *pgxpool.Pool,
	fixture dnsRuntimeRecoveryFixture,
) uuid.UUID {
	t.Helper()
	var claimID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT claim_id
		FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, fixture.clientRequestID).
		Scan(&claimID); err != nil {
		t.Fatal(err)
	}
	return claimID
}

func assertDNSRuntimeRealRecovery(t *testing.T, pool *pgxpool.Pool,
	fixture dnsRuntimeRecoveryFixture, previousClaimID uuid.UUID, remote *realDNSRecoveryRemote,
	wantLookups int32,
) {
	t.Helper()
	var claimID uuid.UUID
	var claimState, leaseState string
	var continuations int
	if err := pool.QueryRow(t.Context(), `SELECT claim.claim_id,claim.state,lease.state,
		(SELECT count(*) FROM dns_reconcile_provider_recovery_continuations continuation
		 WHERE continuation.tenant_id=claim.tenant_id AND continuation.job_id=claim.job_id)
		FROM dns_reconcile_provider_mutation_claims claim
		JOIN dns_reconcile_provider_recovery_leases lease
		  ON lease.tenant_id=claim.tenant_id AND lease.client_request_id=claim.client_request_id
		WHERE claim.tenant_id=$1 AND claim.client_request_id=$2
		ORDER BY lease.claimed_at DESC LIMIT 1`, fixture.tenantID, fixture.clientRequestID).
		Scan(&claimID, &claimState, &leaseState, &continuations); err != nil {
		t.Fatal(err)
	}
	if claimID == previousClaimID || claimState != string(dnsproviderremote.MutationSucceeded) ||
		leaseState != "released" || continuations != 1 || remote.lookups.Load() != wantLookups ||
		remote.mutations.Load() != 0 {
		t.Fatalf("real recovery claim=%s previous=%s state=%s lease=%s continuations=%d lookup=%d mutation=%d",
			claimID, previousClaimID, claimState, leaseState, continuations,
			remote.lookups.Load(), remote.mutations.Load())
	}
}

func forceDNSRuntimeRealRecoveryRetry(t *testing.T, pool *pgxpool.Pool,
	fixture dnsRuntimeRecoveryFixture,
) {
	t.Helper()
	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	_, claimErr := connection.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET lease_expires_at=GREATEST(claimed_at,clock_timestamp()-interval '1 microsecond'),
		    recovery_not_before=clock_timestamp()-interval '1 microsecond'
		WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, fixture.clientRequestID)
	_, failureErr := connection.Exec(t.Context(), `UPDATE dns_reconcile_provider_recovery_failures
		SET retry_not_before=clock_timestamp()-interval '1 microsecond'
		WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, fixture.clientRequestID)
	_, resetErr := connection.Exec(t.Context(), `SET session_replication_role=origin`)
	if claimErr != nil || failureErr != nil || resetErr != nil {
		t.Fatalf("force real recovery retry=(%v,%v,%v)", claimErr, failureErr, resetErr)
	}
}

func (*blockingDNSRecoveryLookupAdapter) CurrentRevision(context.Context,
	dnscheck.ProviderRevisionRequest,
) (int64, error) {
	return 1, nil
}

func (adapter *blockingDNSRecoveryLookupAdapter) Mutate(ctx context.Context,
	_ dnscheck.ProviderMutation,
) (dnscheck.ProviderMutationResult, error) {
	call := adapter.calls.Add(1)
	adapter.entered <- struct{}{}
	select {
	case <-adapter.release:
	case <-ctx.Done():
		return dnscheck.ProviderMutationResult{}, ctx.Err()
	}
	if call != 1 {
		return dnscheck.ProviderMutationResult{}, errors.New("duplicate provider recovery mutation")
	}
	command, err := adapter.pool.Exec(ctx, `UPDATE dns_reconcile_provider_mutation_claims
		SET state='not_applied',final_zone_revision=expected_zone_revision,
		    finalized_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND state='uncertain'`,
		adapter.fixture.tenantID, adapter.fixture.clientRequestID)
	if err != nil || command.RowsAffected() != 1 {
		return dnscheck.ProviderMutationResult{}, dnsreconcile.ErrUnavailable
	}
	return dnscheck.ProviderMutationResult{ProviderRequestID: adapter.fixture.providerRequestID}, nil
}

type dnsRecoveryPendingRecorder struct{ calls int }

func (recorder *dnsRecoveryPendingRecorder) RunOnce(context.Context, uuid.UUID, string, int) ([]dnsreconcile.Task, error) {
	recorder.calls++
	return nil, nil
}

type unusedDNSRecoveryProviderResolver struct{}

func (unusedDNSRecoveryProviderResolver) ResolveProvider(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dnscheck.ProviderAdapter, error) {
	return nil, dnsreconcile.ErrUnavailable
}

type dnsRuntimeRecoveryFixture struct {
	tenantID, scopeID, userID, siteID, zoneID, providerID, jobID uuid.UUID
	clientRequestID, providerRequestID                           string
}

func seedDNSRuntimeRecovery(t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, maxAttempts int) dnsRuntimeRecoveryFixture {
	t.Helper()
	if maxAttempts < 1 {
		t.Fatalf("invalid max attempts %d", maxAttempts)
	}
	fixture := dnsRuntimeRecoveryFixture{
		tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), siteID: uuid.New(),
		zoneID: uuid.New(), providerID: uuid.New(), jobID: uuid.New(),
		clientRequestID: "runtime-recovery-operation",
	}
	fixture.providerRequestID = dnsproviderremote.ProviderMutationRequestID(fixture.clientRequestID)
	digest := make([]byte, sha256.Size)
	now := time.Now().UTC().Truncate(time.Microsecond)
	operationJSON, err := json.Marshal(dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'DNS runtime recovery')`, []any{fixture.tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, fixture.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'DNS runtime recovery','hash')`, []any{fixture.userID, "dnsruntime" + strings.ReplaceAll(fixture.userID.String(), "-", "")[:20]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
		{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id)
		 VALUES($1,$2,$3,'www.example.test',ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,1)`, []any{fixture.siteID, fixture.scopeID, fixture.userID}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{fixture.siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{fixture.siteID}},
		{`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
		 created_by_user_id,updated_by_user_id) VALUES($1,$2,'runtime-provider','cloudflare','runtime-key',$3,'verified',$4,$4)`, []any{fixture.providerID, fixture.scopeID, append(make([]byte, 29), 1), fixture.userID}},
		// provider_zone_apex（迁移 473）已记：否则认领时向真实 provider 补查托管根域，假 remote 走不到 Lookup
		{`INSERT INTO dns_zones(id,scope_id,provider_id,name,status,created_by_user_id,updated_by_user_id,provider_zone_apex)
		 VALUES($1,$2,$3,'example.test','draft',$4,$4,'example.test')`, []any{fixture.zoneID, fixture.scopeID, fixture.providerID, fixture.userID}},
		{`INSERT INTO background_jobs(id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,
			 state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at)
			 VALUES($1,$2,'dns_reconcile','dns_reconcile/site','runtime-job',$3,'runtime-request','',
			 'queued',0,$5,$4,1,$4,$4)`, []any{fixture.jobID, fixture.tenantID, digest, now, maxAttempts}},
		{`INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state)
		 VALUES($1,$2,1,'reconcile','pending')`, []any{fixture.tenantID, fixture.jobID}},
		{`INSERT INTO dns_reconcile_tasks(tenant_id,tenant_scope_id,job_id,site_id,zone_id,idempotency_key,
		 job_idempotency_key,payload_digest,job_request_digest,canonical_request,plan_digest,deterministic_plan,
		 initial_provider_revision,required_consecutive,created_at)
		 VALUES($1,$2,$3,$4,$5,'runtime-raw','runtime-job',$6,$6,'{}'::jsonb,$6,'{}'::jsonb,1,3,$7)`, []any{fixture.tenantID, fixture.scopeID, fixture.jobID, fixture.siteID, fixture.zoneID, digest, now}},
		{`INSERT INTO dns_reconcile_operations(tenant_id,job_id,phase,ordinal,source_sequence,action,
		 client_request_id,operation,created_at) VALUES($1,$2,'apply',1,1,'create',$3,$4::jsonb,$5)`, []any{fixture.tenantID, fixture.jobID, fixture.clientRequestID, operationJSON, now}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return fixture
}
