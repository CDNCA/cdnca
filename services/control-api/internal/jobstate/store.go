package jobstate

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
	now  Clock
}

func NewStore(pool *pgxpool.Pool, clock Clock) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: PostgreSQL pool", ErrInvalidRequest)
	}
	if clock == nil {
		clock = time.Now
	}
	return &Store{pool: pool, now: clock}, nil
}

func (store *Store) Create(ctx context.Context, input CreateInput) (CreateResult, error) {
	if ctx == nil || validateCreate(input) != nil {
		return CreateResult{}, ErrInvalidRequest
	}
	now := store.timestamp()
	var result CreateResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var err error
		result, err = CreateTx(ctx, tx, input, now)
		return err
	})
	if err != nil {
		return CreateResult{}, fmt.Errorf("persist background job: %w", err)
	}
	return result, nil
}

func (store *Store) Get(ctx context.Context, tenantID, jobID uuid.UUID) (StoredJob, error) {
	if ctx == nil || tenantID == uuid.Nil || jobID == uuid.Nil {
		return StoredJob{}, ErrInvalidRequest
	}
	var job StoredJob
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		var err error
		job, err = loadStoredJob(ctx, tx, tenantID, jobID, false)
		return err
	})
	return job, err
}

type claimCandidate struct {
	id      uuid.UUID
	state   State
	attempt uint32
}

func (store *Store) Claim(ctx context.Context, input ClaimInput) ([]Claim, error) {
	if ctx == nil || validateClaim(input) != nil {
		return nil, ErrInvalidRequest
	}
	now := store.timestamp()
	leaseExpiresAt := now.Add(input.LeaseDuration)
	claims := make([]Claim, 0, input.Limit)
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.finalizeExhausted(ctx, tx, input, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT id, state, attempt
			FROM background_jobs
			WHERE tenant_id=$1 AND kind=$2
			  AND state IN ('queued','running') AND claimable_at <= $3
			  AND attempt < max_attempts
			ORDER BY claimable_at, created_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT $4`, input.TenantID, input.Kind, now, input.Limit)
		if err != nil {
			return fmt.Errorf("select claimable background jobs: %w", err)
		}
		candidates := make([]claimCandidate, 0, input.Limit)
		for rows.Next() {
			var candidate claimCandidate
			var state string
			var attempt int
			if err := rows.Scan(&candidate.id, &state, &attempt); err != nil {
				rows.Close()
				return fmt.Errorf("scan claimable background job: %w", err)
			}
			candidate.state = State(state)
			candidate.attempt = uint32(attempt)
			candidates = append(candidates, candidate)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate claimable background jobs: %w", err)
		}
		rows.Close()

		for _, candidate := range candidates {
			if candidate.state == StateRunning {
				if err := expireAttempt(ctx, tx, input.TenantID, candidate.id, candidate.attempt, now); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `
					WITH counts AS (
						SELECT count(*) FILTER (WHERE state = 'succeeded')::integer AS succeeded,
						       count(*) FILTER (WHERE state = 'cancelled')::integer AS cancelled
						FROM background_job_items WHERE tenant_id=$1 AND job_id=$2
					)
					UPDATE background_jobs job
					SET state='queued', completed_count=counts.succeeded+counts.cancelled,
					    succeeded_count=counts.succeeded, failed_count=0, cancelled_count=counts.cancelled,
					    lease_id=NULL, lease_owner=NULL, lease_expires_at=NULL, claimable_at=$3,
					    last_error_code=NULL, completed_at=NULL, updated_at=$4
					FROM counts WHERE job.tenant_id=$1 AND job.id=$2`, input.TenantID, candidate.id,
					now.Add(retryDelay(candidate.attempt)), now); err != nil {
					return fmt.Errorf("queue expired background job: %w", err)
				}
				if _, err := tx.Exec(ctx, `
					UPDATE background_job_items
					SET state='pending', attempt=0, sequence=0, error_code=NULL, completed_at=NULL
					WHERE tenant_id=$1 AND job_id=$2 AND state='failed'`, input.TenantID, candidate.id); err != nil {
					return fmt.Errorf("reset expired background job items: %w", err)
				}
				continue
			}
			leaseID := uuid.New()
			nextAttempt := candidate.attempt + 1
			if _, err := tx.Exec(ctx, `
				WITH counts AS (
					SELECT count(*) FILTER (WHERE state <> 'pending')::integer AS completed,
					       count(*) FILTER (WHERE state = 'succeeded')::integer AS succeeded,
					       count(*) FILTER (WHERE state = 'failed')::integer AS failed,
					       count(*) FILTER (WHERE state = 'cancelled')::integer AS cancelled
					FROM background_job_items WHERE tenant_id=$1 AND job_id=$2
				)
				UPDATE background_jobs job
				SET state='running', attempt=$3, started_at=COALESCE(job.started_at,$4),
				    updated_at=$4, completed_at=NULL, last_error_code=NULL,
				    lease_id=$5, lease_owner=$6, lease_expires_at=$7, claimable_at=$7,
				    completed_count=counts.completed, succeeded_count=counts.succeeded,
				    failed_count=counts.failed, cancelled_count=counts.cancelled
				FROM counts WHERE job.tenant_id=$1 AND job.id=$2`, input.TenantID, candidate.id,
				nextAttempt, now, leaseID, input.WorkerID, leaseExpiresAt); err != nil {
				return fmt.Errorf("claim background job: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO background_job_attempts (
					tenant_id, job_id, attempt, lease_id, worker_id, state,
					started_at, last_heartbeat_at, lease_expires_at
				) VALUES ($1,$2,$3,$4,$5,'running',$6,$6,$7)`, input.TenantID, candidate.id,
				nextAttempt, leaseID, input.WorkerID, now, leaseExpiresAt); err != nil {
				return fmt.Errorf("record background job attempt: %w", err)
			}
			job, err := loadStoredJob(ctx, tx, input.TenantID, candidate.id, false)
			if err != nil {
				return err
			}
			claims = append(claims, Claim{
				Job: job, LeaseID: leaseID, WorkerID: input.WorkerID, LeaseExpiresAt: leaseExpiresAt,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("claim background jobs: %w", err)
	}
	return claims, nil
}

func expireAttempt(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, attempt uint32, now time.Time) error {
	command, err := tx.Exec(ctx, `
		UPDATE background_job_attempts
		SET state='lease_expired', completed_at=$4, error_code=$5
		WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND state='running'`,
		tenantID, jobID, attempt, now, CodeLeaseExpired)
	if err != nil {
		return fmt.Errorf("expire background job attempt: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

func (store *Store) timestamp() time.Time {
	return store.now().UTC().Truncate(time.Microsecond)
}
