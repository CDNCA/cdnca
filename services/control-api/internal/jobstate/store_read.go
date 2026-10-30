package jobstate

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadStoredJob(ctx context.Context, database queryer, tenantID, jobID uuid.UUID, lock bool) (StoredJob, error) {
	query := `
		SELECT id, tenant_id, kind, subject, idempotency_key, request_digest,
		       request_id, trace_id, state, attempt, max_attempts,
		       cancel_requested_at, total_count, completed_count, succeeded_count,
		       failed_count, cancelled_count, last_error_code,
		       created_at, started_at, updated_at, completed_at
		FROM background_jobs WHERE tenant_id=$1 AND id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var job StoredJob
	var digest []byte
	var state string
	var attempt, maximum int
	var cancelRequestedAt, startedAt, completedAt *time.Time
	var lastErrorCode *string
	err := database.QueryRow(ctx, query, tenantID, jobID).Scan(
		&job.ID, &job.TenantID, &job.Kind, &job.Subject, &job.IdempotencyKey, &digest,
		&job.RequestID, &job.TraceID, &state, &attempt, &maximum,
		&cancelRequestedAt, &job.Progress.Total, &job.Progress.Completed, &job.Progress.Succeeded,
		&job.Progress.Failed, &job.Progress.Cancelled, &lastErrorCode,
		&job.CreatedAt, &startedAt, &job.UpdatedAt, &completedAt,
	)
	if err == pgx.ErrNoRows {
		return StoredJob{}, ErrNotFound
	}
	if err != nil {
		return StoredJob{}, fmt.Errorf("read background job: %w", err)
	}
	copy(job.RequestDigest[:], digest)
	job.State = State(state)
	job.Attempt = uint32(attempt)
	job.MaxAttempts = uint32(maximum)
	job.Progress.Pending = job.Progress.Total - job.Progress.Completed
	job.CancelRequestedAt = timeValue(cancelRequestedAt)
	job.StartedAt = timeValue(startedAt)
	job.CompletedAt = timeValue(completedAt)
	job.LastErrorCode = stringValue(lastErrorCode)

	rows, err := database.Query(ctx, `
		SELECT item_id, node_id, state, attempt, sequence, error_code, completed_at
		FROM background_job_items
		WHERE tenant_id=$1 AND job_id=$2 ORDER BY ordinal`, tenantID, jobID)
	if err != nil {
		return StoredJob{}, fmt.Errorf("read background job items: %w", err)
	}
	defer rows.Close()
	job.Items = make([]StoredItem, 0, job.Progress.Total)
	for rows.Next() {
		var item StoredItem
		var nodeID *uuid.UUID
		var itemState string
		var itemAttempt int
		var sequence int64
		var errorCode *string
		var itemCompletedAt *time.Time
		if err := rows.Scan(&item.ItemID, &nodeID, &itemState, &itemAttempt, &sequence, &errorCode, &itemCompletedAt); err != nil {
			return StoredJob{}, fmt.Errorf("scan background job item: %w", err)
		}
		item.NodeID = cloneUUID(nodeID)
		item.State = ItemState(itemState)
		item.Attempt = uint32(itemAttempt)
		item.Sequence = uint64(sequence)
		item.ErrorCode = stringValue(errorCode)
		item.CompletedAt = timeValue(itemCompletedAt)
		job.Items = append(job.Items, item)
	}
	if err := rows.Err(); err != nil {
		return StoredJob{}, fmt.Errorf("iterate background job items: %w", err)
	}
	return job, nil
}

func cloneUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func timeValue(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
