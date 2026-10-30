//go:build integration

package jobstate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var postgresTestNow = time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)

func TestBackgroundJobsMigrationRoundTrip(t *testing.T) {
	pool := openJobstateTestDatabase(t, false)
	migrateJobstateThrough27(t, pool)
	assertJobstateMigration(t, pool, 27, true)
	applyJobstateMigration(t, pool, 27, "down")
	assertJobstateMigration(t, pool, 26, false)
	applyJobstateMigration(t, pool, 27, "up")
	assertJobstateMigration(t, pool, 27, true)
	assertJobstateTables(t, pool, true)
}

func TestBackgroundJobsSQLConstraints(t *testing.T) {
	pool := openJobstateTestDatabase(t, true)
	store, err := NewStore(pool, func() time.Time { return postgresTestNow })
	if err != nil {
		t.Fatal(err)
	}
	tenantID := seedJobstateTenant(t, pool, "Constraint Tenant")
	job := createStoredJob(t, store, storedCreateInput(
		tenantID, "sql-constraints", "constraints", "node-success", "node-failure",
	))
	claim := claimOne(t, store, tenantID, "test.constraints", "worker-valid", 30*time.Second)
	ctx := context.Background()

	invalidWrites := []struct {
		name string
		exec func() error
	}{
		{
			name: "succeeded item with error code",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items
					SET state='succeeded', attempt=1, sequence=1,
					    error_code='unexpected_error', completed_at=$2
					WHERE job_id=$1 AND item_id='node-success'`, job.ID, postgresTestNow)
				return err
			},
		},
		{
			name: "failed item without error code",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items
					SET state='failed', attempt=1, sequence=1,
					    error_code=NULL, completed_at=$2
					WHERE job_id=$1 AND item_id='node-failure'`, job.ID, postgresTestNow)
				return err
			},
		},
		{
			name: "succeeded result with error code",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					INSERT INTO background_job_results (
						id, tenant_id, job_id, item_id, attempt, sequence,
						state, error_code, source, reported_at
					) VALUES ($1,$2,$3,'node-success',1,1,'succeeded','unexpected_error','worker',$4)`,
					uuid.New(), tenantID, job.ID, postgresTestNow)
				return err
			},
		},
		{
			name: "failed result without error code",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					INSERT INTO background_job_results (
						id, tenant_id, job_id, item_id, attempt, sequence,
						state, error_code, source, reported_at
					) VALUES ($1,$2,$3,'node-failure',1,1,'failed',NULL,'worker',$4)`,
					uuid.New(), tenantID, job.ID, postgresTestNow)
				return err
			},
		},
	}
	for index, separator := range []string{"\u2028", "\u2029"} {
		separator := separator
		invalidWrites = append(invalidWrites, struct {
			name string
			exec func() error
		}{
			name: fmt.Sprintf("worker ID separator U+202%d", 8+index),
			exec: func() error {
				_, err := pool.Exec(ctx, `
					INSERT INTO background_job_attempts (
						tenant_id, job_id, attempt, lease_id, worker_id, state,
						started_at, last_heartbeat_at, lease_expires_at
					) VALUES ($1,$2,$3,$4,$5,'running',$6,$6,$7)`,
					tenantID, job.ID, 2+index, uuid.New(), "worker"+separator+"id",
					postgresTestNow, postgresTestNow.Add(time.Minute))
				return err
			},
		})
	}
	for _, test := range invalidWrites {
		t.Run(test.name, func(t *testing.T) {
			postgresError := requirePostgresErrorCodeOneOf(t, test.exec(), "23514", "P0001")
			t.Logf("rejected by database guard: %s", postgresError.Message)
		})
	}

	applyStoreReport(t, store, claim, success("node-success", 1, 1))
	finished := applyStoreReport(t, store, claim, failure("node-failure", 1, 1, "node_offline"))
	if finished.State != StatePartialFailed || finished.Progress.Succeeded != 1 || finished.Progress.Failed != 1 ||
		finished.Items[0].ErrorCode != "" || finished.Items[1].ErrorCode != "node_offline" {
		t.Fatalf("valid success/failure regressed: %+v", finished)
	}
}

func TestBackgroundJobsSQLForgeryGuards(t *testing.T) {
	pool := openJobstateTestDatabase(t, true)
	clock := &storeTestClock{value: postgresTestNow}
	store, err := NewStore(pool, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := seedJobstateTenant(t, pool, "Forgery Guard Tenant")
	ctx := context.Background()

	t.Run("terminal job insert cannot manufacture completed history", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO background_jobs (
				id, tenant_id, kind, subject, idempotency_key, request_digest,
				request_id, state, attempt, max_attempts, total_count,
				completed_count, succeeded_count, failed_count, cancelled_count,
				created_at, started_at, updated_at, completed_at
			) VALUES ($1,$2,'test.forged','forged','forged-terminal',decode(repeat('00',32),'hex'),
				'request-forged','succeeded',1,2,1,1,1,0,0,$3,$3,$3,$3)`,
			uuid.New(), tenantID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("queued insert requires zero counters and attempt", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO background_jobs (
				id, tenant_id, kind, subject, idempotency_key, request_digest,
				request_id, state, attempt, max_attempts, claimable_at, total_count,
				completed_count, succeeded_count, failed_count, cancelled_count,
				created_at, updated_at
			) VALUES ($1,$2,'test.forged','forged','forged-counters',decode(repeat('00',32),'hex'),
				'request-forged','queued',1,2,$3,1,1,1,0,0,$3,$3)`,
			uuid.New(), tenantID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("queued insert rejects non-finite creation time", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO background_jobs (
				id, tenant_id, kind, subject, idempotency_key, request_digest,
				request_id, state, attempt, max_attempts, claimable_at, total_count,
				created_at, updated_at
			) VALUES ($1,$2,'test.forged','forged','forged-infinity',decode(repeat('00',32),'hex'),
				'request-forged','queued',0,2,'infinity',1,'infinity','infinity')`,
			uuid.New(), tenantID)
		requirePostgresErrorCode(t, err, "23514")
	})

	t.Run("terminal item insert cannot bypass report", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		jobID := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO background_jobs (
				id, tenant_id, kind, subject, idempotency_key, request_digest,
				request_id, state, attempt, max_attempts, claimable_at, total_count,
				created_at, updated_at
			) VALUES ($1,$2,'test.forged','forged','forged-item-insert',decode(repeat('00',32),'hex'),
				'request-forged','queued',0,2,$3,1,$3,$3)`, jobID, tenantID, postgresTestNow); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO background_job_items (
				tenant_id, job_id, ordinal, item_id, state, attempt, sequence, completed_at
			) VALUES ($1,$2,1,'forged-item','succeeded',1,1,$3)`, tenantID, jobID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	runningJob := createStoredJob(t, store, storedCreateInput(
		tenantID, "forgery-running", "forgery_running", "pending-a", "pending-b",
	))
	runningClaim := claimOne(t, store, tenantID, "test.forgery_running", "worker-forgery", time.Minute)

	t.Run("attempt insert must match current claim", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO background_job_attempts (
				tenant_id, job_id, attempt, lease_id, worker_id, state,
				started_at, last_heartbeat_at, lease_expires_at
			) VALUES ($1,$2,2,$3,'other-worker','running',$4,$4,$5)`,
			tenantID, runningJob.ID, uuid.New(), postgresTestNow, postgresTestNow.Add(time.Minute))
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("terminal attempt cannot be inserted", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO background_job_attempts (
				tenant_id, job_id, attempt, lease_id, worker_id, state,
				started_at, last_heartbeat_at, lease_expires_at, completed_at
			) VALUES ($1,$2,1,$3,'worker-forgery','succeeded',$4,$4,$5,$4)`,
			tenantID, runningJob.ID, uuid.New(), postgresTestNow, postgresTestNow.Add(time.Minute))
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("queued job cannot accept a worker result", func(t *testing.T) {
		queued := createStoredJob(t, store, storedCreateInput(
			tenantID, "forgery-queued-result", "forgery_queued_result", "queued-item",
		))
		_, err := pool.Exec(ctx, `
			INSERT INTO background_job_results (
				id, tenant_id, job_id, item_id, attempt, sequence,
				state, source, reported_at
			) VALUES ($1,$2,$3,'queued-item',1,1,'succeeded','worker',$4)`,
			uuid.New(), tenantID, queued.ID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("cross-attempt result cannot enter current claim", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO background_job_results (
				id, tenant_id, job_id, item_id, attempt, sequence,
				state, source, reported_at
			) VALUES ($1,$2,$3,'pending-a',2,1,'succeeded','worker',$4)`,
			uuid.New(), tenantID, runningJob.ID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("expired lease cannot accept a worker result", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			INSERT INTO background_job_results (
				id, tenant_id, job_id, item_id, attempt, sequence,
				state, source, reported_at
			) VALUES ($1,$2,$3,'pending-a',1,1,'succeeded','worker',$4)`,
			uuid.New(), tenantID, runningJob.ID, runningClaim.LeaseExpiresAt)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("terminal item requires an exact immutable result", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			UPDATE background_job_items
			SET state='succeeded', attempt=1, sequence=1, completed_at=$3
			WHERE tenant_id=$1 AND job_id=$2 AND item_id='pending-a'`,
			tenantID, runningJob.ID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("item cancellation requires parent cancellation", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			UPDATE background_job_items
			SET state='cancelled', attempt=1, sequence=0, error_code='cancelled', completed_at=$3
			WHERE tenant_id=$1 AND job_id=$2 AND item_id='pending-a'`,
			tenantID, runningJob.ID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("result and item timestamps must match exactly", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `
			INSERT INTO background_job_results (
				id, tenant_id, job_id, item_id, attempt, sequence,
				state, source, reported_at
			) VALUES ($1,$2,$3,'pending-a',1,1,'succeeded','worker',$4)`,
			uuid.New(), tenantID, runningJob.ID, postgresTestNow); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `
			UPDATE background_job_items
			SET state='succeeded', attempt=1, sequence=1, completed_at=$3
			WHERE tenant_id=$1 AND job_id=$2 AND item_id='pending-a'`,
			tenantID, runningJob.ID, postgresTestNow.Add(time.Microsecond))
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("unapplied result fails deferred validation", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO background_job_results (
				id, tenant_id, job_id, item_id, attempt, sequence,
				state, source, reported_at
			) VALUES ($1,$2,$3,'pending-a',1,1,'succeeded','worker',$4)`,
			uuid.New(), tenantID, runningJob.ID, postgresTestNow); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		requirePostgresErrorCode(t, tx.Commit(ctx), "P0001")
	})

	t.Run("forged progress and terminal projection are rejected", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			UPDATE background_jobs
			SET completed_count=1, succeeded_count=1, updated_at=updated_at + interval '1 microsecond'
			WHERE tenant_id=$1 AND id=$2`, tenantID, runningJob.ID)
		requirePostgresErrorCode(t, err, "P0001")

		_, err = pool.Exec(ctx, `
			UPDATE background_jobs
			SET state='succeeded', completed_count=total_count, succeeded_count=total_count,
				lease_id=NULL, lease_owner=NULL, lease_expires_at=NULL, claimable_at=NULL,
				completed_at=$3, updated_at=$3
			WHERE tenant_id=$1 AND id=$2`, tenantID, runningJob.ID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("attempt heartbeat and terminal state must match parent", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			UPDATE background_job_attempts
			SET last_heartbeat_at=last_heartbeat_at + interval '1 microsecond',
				lease_expires_at=lease_expires_at + interval '1 microsecond'
			WHERE tenant_id=$1 AND job_id=$2 AND attempt=1`, tenantID, runningJob.ID)
		requirePostgresErrorCode(t, err, "P0001")

		_, err = pool.Exec(ctx, `
			UPDATE background_job_attempts
			SET state='failed', completed_at=$3, error_code='all_items_failed'
			WHERE tenant_id=$1 AND job_id=$2 AND attempt=1`, tenantID, runningJob.ID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("isolated lease expiry cannot contradict running parent", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			UPDATE background_job_attempts
			SET state='lease_expired', completed_at=$3, error_code='lease_expired'
			WHERE tenant_id=$1 AND job_id=$2 AND attempt=1`,
			tenantID, runningJob.ID, runningClaim.LeaseExpiresAt)
		requirePostgresErrorCode(t, err, "P0001")
	})

	t.Run("terminal parent cannot accept historical result", func(t *testing.T) {
		terminal := createStoredJob(t, store, storedCreateInput(
			tenantID, "forgery-terminal-result", "forgery_terminal_result", "terminal-item",
		))
		claim := claimOne(t, store, tenantID, "test.forgery_terminal_result", "worker-terminal", time.Minute)
		applyStoreReport(t, store, claim, success("terminal-item", 1, 1))
		_, err := pool.Exec(ctx, `
			INSERT INTO background_job_results (
				id, tenant_id, job_id, item_id, attempt, sequence,
				state, source, reported_at
			) VALUES ($1,$2,$3,'terminal-item',1,1,'succeeded','worker',$4)`,
			uuid.New(), tenantID, terminal.ID, postgresTestNow)
		requirePostgresErrorCode(t, err, "P0001")
	})
}

func TestBackgroundJobsSQLStateAndHistoryGuards(t *testing.T) {
	pool := openJobstateTestDatabase(t, true)
	clock := &storeTestClock{value: postgresTestNow}
	store, err := NewStore(pool, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := seedJobstateTenant(t, pool, "Guard Tenant")
	partialInput := storedCreateInput(tenantID, "guard-partial", "guard_partial", "node-success", "node-failure")
	partialInput.MaxAttempts = 2
	partialJob := createStoredJob(t, store, partialInput)
	partialClaim := claimOne(t, store, tenantID, "test.guard_partial", "worker-partial", 30*time.Second)
	clock.Advance(time.Second)
	applyStoreReport(t, store, partialClaim, success("node-success", 1, 2))
	partialJob = applyStoreReport(t, store, partialClaim, failure("node-failure", 1, 1, "node_offline"))
	if partialJob.State != StatePartialFailed {
		t.Fatalf("partial job state=%s", partialJob.State)
	}

	runningJob := createStoredJob(t, store, storedCreateInput(tenantID, "guard-running", "guard_running", "node-running"))
	runningClaim := claimOne(t, store, tenantID, "test.guard_running", "worker-running", 30*time.Second)
	ctx := context.Background()

	guardedWrites := []struct {
		name string
		exec func() error
	}{
		{
			name: "job creation facts immutable",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_jobs SET request_id='changed', updated_at=updated_at + interval '1 microsecond'
					WHERE id=$1`, runningJob.ID)
				return err
			},
		},
		{
			name: "job terminal state cannot regress",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_jobs
					SET state='running', lease_id=$2, lease_owner='direct-worker',
					    lease_expires_at=updated_at + interval '1 minute',
					    claimable_at=updated_at + interval '1 minute',
					    completed_at=NULL, updated_at=updated_at + interval '1 microsecond'
					WHERE id=$1`, partialJob.ID, uuid.New())
				return err
			},
		},
		{
			name: "job updated time cannot regress",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_jobs SET updated_at=updated_at - interval '1 microsecond' WHERE id=$1`, runningJob.ID)
				return err
			},
		},
		{
			name: "job started time cannot regress",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_jobs SET started_at=started_at - interval '1 microsecond' WHERE id=$1`, runningJob.ID)
				return err
			},
		},
		{
			name: "job completed time cannot regress",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_jobs
					SET completed_at=completed_at - interval '1 microsecond',
					    updated_at=updated_at + interval '1 microsecond'
					WHERE id=$1`, partialJob.ID)
				return err
			},
		},
		{
			name: "job attempt cannot skip",
			exec: func() error {
				_, err := pool.Exec(ctx, `UPDATE background_jobs SET attempt=attempt + 1 WHERE id=$1`, runningJob.ID)
				return err
			},
		},
		{
			name: "job progress cannot regress",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_jobs
					SET completed_count=completed_count - 1, failed_count=failed_count - 1,
					    updated_at=updated_at + interval '1 microsecond'
					WHERE id=$1`, partialJob.ID)
				return err
			},
		},
		{
			name: "item creation facts immutable",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items SET ordinal=ordinal + 100
					WHERE job_id=$1 AND item_id='node-success'`, partialJob.ID)
				return err
			},
		},
		{
			name: "item attempt cannot skip parent attempt",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items
					SET state='succeeded', attempt=2, sequence=1, completed_at=$2
					WHERE job_id=$1 AND item_id='node-running'`, runningJob.ID, clock.Now())
				return err
			},
		},
		{
			name: "item completed time cannot predate parent",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items
					SET state='succeeded', attempt=1, sequence=1, completed_at=$2
					WHERE job_id=$1 AND item_id='node-running'`, runningJob.ID, postgresTestNow)
				return err
			},
		},
		{
			name: "successful item cannot return to pending",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items
					SET state='pending', attempt=0, sequence=0, error_code=NULL, completed_at=NULL
					WHERE job_id=$1 AND item_id='node-success'`, partialJob.ID)
				return err
			},
		},
		{
			name: "failed item cannot retry before parent queues",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items
					SET state='pending', attempt=0, sequence=0, error_code=NULL, completed_at=NULL
					WHERE job_id=$1 AND item_id='node-failure'`, partialJob.ID)
				return err
			},
		},
		{
			name: "item sequence cannot regress",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items SET sequence=sequence - 1
					WHERE job_id=$1 AND item_id='node-success'`, partialJob.ID)
				return err
			},
		},
		{
			name: "item completed time cannot regress",
			exec: func() error {
				_, err := pool.Exec(ctx, `
					UPDATE background_job_items SET completed_at=completed_at - interval '1 microsecond'
					WHERE job_id=$1 AND item_id='node-success'`, partialJob.ID)
				return err
			},
		},
		{
			name: "job delete blocked",
			exec: func() error {
				_, err := pool.Exec(ctx, `DELETE FROM background_jobs WHERE id=$1`, partialJob.ID)
				return err
			},
		},
		{
			name: "item delete blocked",
			exec: func() error {
				_, err := pool.Exec(ctx, `DELETE FROM background_job_items WHERE job_id=$1`, partialJob.ID)
				return err
			},
		},
		{
			name: "attempt delete blocked",
			exec: func() error {
				_, err := pool.Exec(ctx, `DELETE FROM background_job_attempts WHERE job_id=$1`, partialJob.ID)
				return err
			},
		},
		{
			name: "result delete blocked",
			exec: func() error {
				_, err := pool.Exec(ctx, `DELETE FROM background_job_results WHERE job_id=$1`, partialJob.ID)
				return err
			},
		},
		{name: "job truncate blocked", exec: func() error {
			_, err := pool.Exec(ctx, `TRUNCATE background_jobs CASCADE`)
			return err
		}},
		{name: "item truncate blocked", exec: func() error {
			_, err := pool.Exec(ctx, `TRUNCATE background_job_items CASCADE`)
			return err
		}},
		{name: "attempt truncate blocked", exec: func() error {
			_, err := pool.Exec(ctx, `TRUNCATE background_job_attempts CASCADE`)
			return err
		}},
		{name: "result truncate blocked", exec: func() error {
			_, err := pool.Exec(ctx, `TRUNCATE background_job_results`)
			return err
		}},
	}
	for _, test := range guardedWrites {
		t.Run(test.name, func(t *testing.T) {
			postgresError := requirePostgresErrorCode(t, test.exec(), "P0001")
			t.Log(postgresError.Message)
		})
	}

	if _, err := store.Heartbeat(ctx, HeartbeatInput{
		TenantID: tenantID, JobID: runningJob.ID, WorkerID: runningClaim.WorkerID,
		Attempt: 1, LeaseID: runningClaim.LeaseID, LeaseDuration: time.Minute,
	}); err != nil {
		t.Fatalf("valid heartbeat: %v", err)
	}
	cancelled, err := store.Cancel(ctx, tenantID, runningJob.ID)
	if err != nil || cancelled.State != StateCancelled {
		t.Fatalf("valid cancellation: job=%+v err=%v", cancelled, err)
	}
	queuedCancellation := createStoredJob(t, store, storedCreateInput(
		tenantID, "guard-queued-cancel", "guard_queued_cancel", "node-queued",
	))
	cancelled, err = store.Cancel(ctx, tenantID, queuedCancellation.ID)
	if err != nil || cancelled.State != StateCancelled || cancelled.Attempt != 0 || cancelled.Progress.Cancelled != 1 {
		t.Fatalf("valid queued cancellation: job=%+v err=%v", cancelled, err)
	}
	queued, err := store.Retry(ctx, tenantID, partialJob.ID)
	if err != nil || queued.State != StateQueued || queued.Progress.Pending != 1 || queued.Progress.Succeeded != 1 {
		t.Fatalf("valid retry: job=%+v err=%v", queued, err)
	}
	_, err = pool.Exec(ctx, `
		UPDATE background_jobs SET attempt=attempt - 1, updated_at=updated_at + interval '1 microsecond'
		WHERE id=$1`, partialJob.ID)
	requirePostgresErrorCode(t, err, "P0001")
	clock.Advance(5 * time.Second)
	retryClaim := claimOne(t, store, tenantID, "test.guard_partial", "worker-retry", time.Minute)
	finished := applyStoreReport(t, store, retryClaim, success("node-failure", 2, 1))
	if finished.State != StateSucceeded || finished.Progress.Succeeded != 2 {
		t.Fatalf("valid retry report: %+v", finished)
	}
}

func TestPostgresStoreLifecycleIsolationAndRecovery(t *testing.T) {
	pool := openJobstateTestDatabase(t, true)
	installSettlementDLQOverlay(t, pool)
	clock := &storeTestClock{value: postgresTestNow}
	store, err := NewStore(pool, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	tenantA := seedJobstateTenant(t, pool, "Tenant A")
	tenantB := seedJobstateTenant(t, pool, "Tenant B")

	t.Run("tenant idempotency and conflict", func(t *testing.T) {
		input := storedCreateInput(tenantA, "idempotent-key", "idempotency", "节点-上海")
		nodeID := uuid.New()
		input.Items[0].NodeID = &nodeID
		first, err := store.Create(context.Background(), input)
		if err != nil || first.Replayed {
			t.Fatalf("first create: result=%+v err=%v", first, err)
		}
		if first.Job.Items[0].NodeID == nil || *first.Job.Items[0].NodeID != nodeID {
			t.Fatalf("node result identity was not persisted: %+v", first.Job.Items[0])
		}
		second, err := store.Create(context.Background(), input)
		if err != nil || !second.Replayed || second.Job.ID != first.Job.ID {
			t.Fatalf("idempotent replay: result=%+v err=%v", second, err)
		}
		input.Payload = []byte("different")
		if _, err := store.Create(context.Background(), input); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("same key with different payload: %v", err)
		}
		input.TenantID = tenantB
		otherTenant, err := store.Create(context.Background(), input)
		if err != nil || otherTenant.Job.ID == first.Job.ID {
			t.Fatalf("tenant-scoped idempotency: result=%+v err=%v", otherTenant, err)
		}
		if _, err := store.Get(context.Background(), tenantB, first.Job.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant read: %v", err)
		}
	})

	t.Run("concurrent single claim and tenant isolation", func(t *testing.T) {
		created := createStoredJob(t, store, storedCreateInput(tenantA, "single-claim", "claim", "node-a"))
		createStoredJob(t, store, storedCreateInput(tenantB, "tenant-b-claim", "claim", "node-b"))
		start := make(chan struct{})
		claims := make(chan []Claim, 2)
		errorsChannel := make(chan error, 2)
		var workers sync.WaitGroup
		for _, workerID := range []string{"worker-a", "worker-b"} {
			workerID := workerID
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				claimed, err := store.Claim(context.Background(), ClaimInput{
					TenantID: tenantA, Kind: "test.claim", WorkerID: workerID,
					Limit: 1, LeaseDuration: 30 * time.Second,
				})
				claims <- claimed
				errorsChannel <- err
			}()
		}
		close(start)
		workers.Wait()
		close(claims)
		close(errorsChannel)
		for err := range errorsChannel {
			if err != nil {
				t.Fatal(err)
			}
		}
		claimedCount := 0
		for batch := range claims {
			claimedCount += len(batch)
			for _, claim := range batch {
				if claim.Job.ID != created.ID || claim.Job.TenantID != tenantA {
					t.Fatalf("wrong job claimed: %+v", claim.Job)
				}
			}
		}
		if claimedCount != 1 {
			t.Fatalf("concurrent claim count=%d, want 1", claimedCount)
		}
		otherClaims, err := store.Claim(context.Background(), ClaimInput{
			TenantID: tenantB, Kind: "test.claim", WorkerID: "worker-c",
			Limit: 1, LeaseDuration: 30 * time.Second,
		})
		if err != nil || len(otherClaims) != 1 || otherClaims[0].Job.TenantID != tenantB {
			t.Fatalf("tenant B claim: claims=%+v err=%v", otherClaims, err)
		}
	})

	t.Run("worker crash lease recovery", func(t *testing.T) {
		clock.Set(postgresTestNow.Add(time.Hour))
		job := createStoredJob(t, store, storedCreateInput(tenantA, "lease-recovery", "recovery", "node-a"))
		first := claimOne(t, store, tenantA, "test.recovery", "worker-crashed", 2*time.Second)
		if first.Job.ID != job.ID || first.Job.Attempt != 1 {
			t.Fatalf("first claim: %+v", first)
		}
		clock.Advance(time.Second)
		extended, err := store.Heartbeat(context.Background(), HeartbeatInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-crashed", Attempt: 1,
			LeaseID: first.LeaseID, LeaseDuration: 2 * time.Second,
		})
		if err != nil || !extended.After(first.LeaseExpiresAt) {
			t.Fatalf("extend heartbeat: expires=%s err=%v", extended, err)
		}
		clock.Advance(3 * time.Second)
		early, err := store.Claim(context.Background(), ClaimInput{
			TenantID: tenantA, Kind: "test.recovery", WorkerID: "worker-too-early",
			Limit: 1, LeaseDuration: 30 * time.Second,
		})
		if err != nil || len(early) != 0 {
			t.Fatalf("expired lease ignored backoff: claims=%+v err=%v", early, err)
		}
		clock.Advance(5 * time.Second)
		second := claimOne(t, store, tenantA, "test.recovery", "worker-recovery", 30*time.Second)
		if second.Job.ID != job.ID || second.Job.Attempt != 2 || second.LeaseID == first.LeaseID {
			t.Fatalf("recovered claim: %+v", second)
		}
		if _, err := store.Heartbeat(context.Background(), HeartbeatInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-crashed", Attempt: 1,
			LeaseID: first.LeaseID, LeaseDuration: 30 * time.Second,
		}); !errors.Is(err, ErrClaimLost) {
			t.Fatalf("expired worker heartbeat: %v", err)
		}
		result, err := store.Report(context.Background(), ReportInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-crashed", LeaseID: first.LeaseID,
			Report: success("node-a", 1, 1),
		})
		if err != nil || result.Applied || result.Job.Attempt != 2 {
			t.Fatalf("stale worker report: result=%+v err=%v", result, err)
		}
		result, err = store.Report(context.Background(), ReportInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-recovery", LeaseID: second.LeaseID,
			Report: success("node-a", 2, 1),
		})
		if err != nil || !result.Applied || result.Job.State != StateSucceeded {
			t.Fatalf("recovered result: result=%+v err=%v", result, err)
		}
		assertAttemptState(t, pool, job.ID, 1, "lease_expired")
	})

	t.Run("partial failure retry and immutable result audit", func(t *testing.T) {
		clock.Set(postgresTestNow.Add(2 * time.Hour))
		input := storedCreateInput(tenantA, "partial-retry", "partial", "node-a", "node-b")
		input.MaxAttempts = 2
		job := createStoredJob(t, store, input)
		claim := claimOne(t, store, tenantA, "test.partial", "worker-partial", 30*time.Second)
		applyStoreReport(t, store, claim, success("node-a", 1, 2))
		duplicate, err := store.Report(context.Background(), ReportInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-partial", LeaseID: claim.LeaseID,
			Report: success("node-a", 1, 2),
		})
		if err != nil || duplicate.Applied {
			t.Fatalf("duplicate result: result=%+v err=%v", duplicate, err)
		}
		outOfOrder, err := store.Report(context.Background(), ReportInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-partial", LeaseID: claim.LeaseID,
			Report: failure("node-a", 1, 1, "timeout"),
		})
		if err != nil || outOfOrder.Applied {
			t.Fatalf("out-of-order result: result=%+v err=%v", outOfOrder, err)
		}
		if _, err := store.Report(context.Background(), ReportInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-partial", LeaseID: claim.LeaseID,
			Report: failure("node-a", 1, 2, "timeout"),
		}); !errors.Is(err, ErrReportConflict) {
			t.Fatalf("same-sequence result conflict: %v", err)
		}
		partial := applyStoreReport(t, store, claim, failure("node-b", 1, 1, "node_offline"))
		if partial.State != StatePartialFailed || partial.Progress.Succeeded != 1 || partial.Progress.Failed != 1 {
			t.Fatalf("partial result: %+v", partial)
		}
		queued, err := store.Retry(context.Background(), tenantA, job.ID)
		if err != nil || queued.State != StateQueued || queued.Progress.Succeeded != 1 || queued.Progress.Pending != 1 {
			t.Fatalf("retry partial job: job=%+v err=%v", queued, err)
		}
		clock.Advance(5 * time.Second)
		second := claimOne(t, store, tenantA, "test.partial", "worker-retry", 30*time.Second)
		finished := applyStoreReport(t, store, second, success("node-b", 2, 1))
		if finished.State != StateSucceeded || finished.Attempt != 2 {
			t.Fatalf("retried result: %+v", finished)
		}
		assertHistoryCounts(t, pool, job.ID, 2, 3)
		if _, err := pool.Exec(context.Background(), `UPDATE background_job_results SET error_code='changed' WHERE job_id=$1`, job.ID); err == nil {
			t.Fatal("result audit accepted mutation")
		}
		if _, err := pool.Exec(context.Background(), `UPDATE background_job_attempts SET error_code='changed' WHERE job_id=$1 AND attempt=1`, job.ID); err == nil {
			t.Fatal("completed attempt audit accepted mutation")
		}
	})

	t.Run("terminal report wins before cancellation", func(t *testing.T) {
		clock.Set(postgresTestNow.Add(3500 * time.Second))
		job := createStoredJob(t, store, storedCreateInput(tenantA, "report-before-cancel", "report_before_cancel", "node-a"))
		claim := claimOne(t, store, tenantA, "test.report_before_cancel", "worker-report", 30*time.Second)
		finished := applyStoreReport(t, store, claim, success("node-a", 1, 1))
		if finished.State != StateSucceeded {
			t.Fatalf("terminal report result: %+v", finished)
		}
		if _, err := store.Cancel(context.Background(), tenantA, job.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("cancellation after terminal report error=%v", err)
		}
	})

	t.Run("cancellation gates late reports", func(t *testing.T) {
		clock.Set(postgresTestNow.Add(3 * time.Hour))
		job := createStoredJob(t, store, storedCreateInput(tenantA, "cancel-running", "cancel", "node-a"))
		claim := claimOne(t, store, tenantA, "test.cancel", "worker-cancel", 30*time.Second)
		cancelled, err := store.Cancel(context.Background(), tenantA, job.ID)
		if err != nil || cancelled.State != StateCancelled || cancelled.CancelRequestedAt.IsZero() || cancelled.Progress.Cancelled != 1 {
			t.Fatalf("cancel running job: job=%+v err=%v", cancelled, err)
		}
		late, err := store.Report(context.Background(), ReportInput{
			TenantID: tenantA, JobID: job.ID, WorkerID: "worker-cancel", LeaseID: claim.LeaseID,
			Report: success("node-a", 1, 1),
		})
		if err != nil || late.Applied || late.Job.State != StateCancelled {
			t.Fatalf("late cancelled report: result=%+v err=%v", late, err)
		}
	})

	t.Run("retry exhaustion", func(t *testing.T) {
		clock.Set(postgresTestNow.Add(4 * time.Hour))
		input := storedCreateInput(tenantA, "retry-exhausted", "exhausted", "node-a")
		input.MaxAttempts = 1
		job := createStoredJob(t, store, input)
		claim := claimOne(t, store, tenantA, "test.exhausted", "worker-exhausted", 30*time.Second)
		failed := applyStoreReport(t, store, claim, failure("node-a", 1, 1, "permanent_failure"))
		if failed.State != StateFailed {
			t.Fatalf("failed job: %+v", failed)
		}
		if _, err := store.Retry(context.Background(), tenantA, job.ID); !errors.Is(err, ErrRetriesExhausted) {
			t.Fatalf("retry exhausted job: %v", err)
		}
	})

	t.Run("expired final lease is failed transactionally", func(t *testing.T) {
		clock.Set(postgresTestNow.Add(5 * time.Hour))
		input := storedCreateInput(tenantA, "lease-exhausted", "lease_exhausted", "node-a")
		input.MaxAttempts = 1
		job := createStoredJob(t, store, input)
		claimOne(t, store, tenantA, "test.lease_exhausted", "worker-last", time.Second)
		clock.Advance(2 * time.Second)
		claims, err := store.Claim(context.Background(), ClaimInput{
			TenantID: tenantA, Kind: "test.lease_exhausted", WorkerID: "worker-after",
			Limit: 1, LeaseDuration: 30 * time.Second,
		})
		if err != nil || len(claims) != 0 {
			t.Fatalf("claim after exhausted lease: claims=%+v err=%v", claims, err)
		}
		failed, err := store.Get(context.Background(), tenantA, job.ID)
		if err != nil || failed.State != StateFailed || failed.LastErrorCode != CodeRetriesExhausted ||
			failed.Progress.Failed != 1 || failed.Items[0].Sequence != 0 {
			t.Fatalf("exhausted lease result: job=%+v err=%v", failed, err)
		}
		assertHistoryCounts(t, pool, job.ID, 1, 1)
	})
}

func installSettlementDLQOverlay(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `CREATE TABLE background_job_dead_letters (
		tenant_id uuid NOT NULL,
		job_id uuid NOT NULL,
		attempt integer NOT NULL,
		reason_code text NOT NULL,
		failed_item_count integer NOT NULL,
		source text NOT NULL,
		job_transition_xact_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
		created_at timestamptz NOT NULL,
		PRIMARY KEY(job_id,attempt)
	)`); err != nil {
		t.Fatal(err)
	}
	migration, err := controlmigrations.FS.ReadFile("104_background_job_settlement_dlq.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	const projectionStart = "CREATE OR REPLACE FUNCTION validate_background_job_projection("
	start := strings.Index(string(migration), projectionStart)
	if start < 0 {
		t.Fatal("migration 104 projection function is missing")
	}
	end := strings.Index(string(migration[start:]), "\n$$;")
	if end < 0 {
		t.Fatal("migration 104 projection function is incomplete")
	}
	projection := migration[start : start+end+len("\n$$;")]
	if _, err := pool.Exec(context.Background(), string(projection)); err != nil {
		t.Fatal(err)
	}
}

type storeTestClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *storeTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}

func (clock *storeTestClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.value = value
	clock.mu.Unlock()
}

func (clock *storeTestClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.value = clock.value.Add(duration)
	clock.mu.Unlock()
}

func storedCreateInput(tenantID uuid.UUID, key, suffix string, itemIDs ...string) CreateInput {
	items := make([]CreateItem, len(itemIDs))
	for index, itemID := range itemIDs {
		items[index] = CreateItem{ItemID: itemID}
	}
	return CreateInput{
		TenantID: tenantID, Kind: "test." + suffix, Subject: "任务/" + suffix,
		IdempotencyKey: key, Payload: []byte("payload/" + suffix), Items: items,
		MaxAttempts: 2, RequestID: "request-" + suffix, TraceID: "trace-" + suffix,
	}
}

func createStoredJob(t *testing.T, store *Store, input CreateInput) StoredJob {
	t.Helper()
	result, err := store.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed {
		t.Fatal("new job was replayed")
	}
	return result.Job
}

func claimOne(t *testing.T, store *Store, tenantID uuid.UUID, kind, workerID string, duration time.Duration) Claim {
	t.Helper()
	claims, err := store.Claim(context.Background(), ClaimInput{
		TenantID: tenantID, Kind: kind, WorkerID: workerID, Limit: 1, LeaseDuration: duration,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 {
		t.Fatalf("claim count=%d, want 1", len(claims))
	}
	return claims[0]
}

func applyStoreReport(t *testing.T, store *Store, claim Claim, report Report) StoredJob {
	t.Helper()
	result, err := store.Report(context.Background(), ReportInput{
		TenantID: claim.Job.TenantID, JobID: claim.Job.ID,
		WorkerID: claim.WorkerID, LeaseID: claim.LeaseID, Report: report,
	})
	if err != nil || !result.Applied {
		t.Fatalf("apply result: result=%+v err=%v", result, err)
	}
	return result.Job
}

func seedJobstateTenant(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants (id, display_name) VALUES ($1,$2)`, id, name); err != nil {
		t.Fatal(err)
	}
	return id
}

func assertAttemptState(t *testing.T, pool *pgxpool.Pool, jobID uuid.UUID, attempt int, want string) {
	t.Helper()
	var state string
	if err := pool.QueryRow(context.Background(), `
		SELECT state FROM background_job_attempts WHERE job_id=$1 AND attempt=$2`, jobID, attempt).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != want {
		t.Fatalf("attempt state=%q, want %q", state, want)
	}
}

func assertHistoryCounts(t *testing.T, pool *pgxpool.Pool, jobID uuid.UUID, attempts, results int) {
	t.Helper()
	var actualAttempts, actualResults int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM background_job_attempts WHERE job_id=$1`, jobID).Scan(&actualAttempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM background_job_results WHERE job_id=$1`, jobID).Scan(&actualResults); err != nil {
		t.Fatal(err)
	}
	if actualAttempts != attempts || actualResults != results {
		t.Fatalf("history=(%d,%d), want=(%d,%d)", actualAttempts, actualResults, attempts, results)
	}
}

func requirePostgresErrorCode(t *testing.T, err error, code string) *pgconn.PgError {
	t.Helper()
	if err == nil {
		t.Fatalf("database accepted direct write; want SQLSTATE %s", code)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("direct write error=%v, want SQLSTATE %s", err, code)
	}
	return postgresError
}

func requirePostgresErrorCodeOneOf(t *testing.T, err error, codes ...string) *pgconn.PgError {
	t.Helper()
	if err == nil {
		t.Fatalf("database accepted direct write; want SQLSTATE in %v", codes)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		t.Fatalf("direct write error=%v, want PostgreSQL error", err)
	}
	for _, code := range codes {
		if postgresError.Code == code {
			return postgresError
		}
	}
	t.Fatalf("direct write SQLSTATE=%s, want one of %v", postgresError.Code, codes)
	return nil
}

func openJobstateTestDatabase(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "jobstate_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^jobstate_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop jobstate schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		migrateJobstateThrough27(t, pool)
	}
	return pool
}

func assertJobstateMigration(t *testing.T, pool *pgxpool.Pool, version int64, exists bool) {
	t.Helper()
	actualVersion := jobstateMigrationVersion(t, pool)
	if actualVersion != version {
		t.Fatalf("migration version=%d, want %d", actualVersion, version)
	}
	assertJobstateTables(t, pool, exists)
}

func assertJobstateTables(t *testing.T, pool *pgxpool.Pool, exists bool) {
	t.Helper()
	for _, table := range []string{"background_jobs", "background_job_items", "background_job_attempts", "background_job_results"} {
		var actual bool
		if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != exists {
			t.Fatalf("table %s exists=%t, want %t", table, actual, exists)
		}
	}
}

func jobstateMigrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func migrateJobstateThrough27(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatal(err)
	}
	for version := int64(1); version <= 27; version++ {
		var applied bool
		if err := pool.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if !applied {
			applyJobstateMigration(t, pool, version, "up")
		}
	}
}

func applyJobstateMigration(t *testing.T, pool *pgxpool.Pool, version int64, direction string) {
	t.Helper()
	if direction != "up" && direction != "down" {
		t.Fatalf("invalid migration direction %q", direction)
	}
	matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.*.sql", version))
	if err != nil {
		t.Fatal(err)
	}
	var name string
	for _, match := range matches {
		if strings.HasSuffix(match, "."+direction+".sql") {
			if name != "" {
				t.Fatalf("multiple migration %03d %s files", version, direction)
			}
			name = match
		}
	}
	if name == "" {
		t.Fatalf("missing migration %03d %s file", version, direction)
	}
	script, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), string(script)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(context.Background(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		} else {
			_, err = tx.Exec(context.Background(), `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	}); err != nil {
		t.Fatalf("apply migration %03d %s: %v", version, direction, err)
	}
}
