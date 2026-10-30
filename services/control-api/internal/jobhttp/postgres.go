package jobhttp

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const jobProjectionSQL = `
	SELECT job.id,job.tenant_id,job.kind,job.subject,job.request_id,job.trace_id,
	       job.state,job.attempt,job.max_attempts,job.total_count,job.completed_count,
	       job.succeeded_count,job.failed_count,job.cancelled_count,job.last_error_code,
	       job.created_at,job.started_at,job.updated_at,job.completed_at`

// resourceItemMatchSQL reports whether a resource filter matched through an
// item's node instead of the job subject; the service validates it per row.
const resourceItemMatchSQL = `EXISTS (
	    SELECT 1 FROM background_job_items resource_item
	    WHERE resource_item.tenant_id=job.tenant_id AND resource_item.job_id=job.id
	      AND resource_item.node_id IS NOT NULL AND resource_item.node_id::text=lower($5))`

const jobListProjectionSQL = jobProjectionSQL + `,
	       ($5::text IS NOT NULL AND ` + resourceItemMatchSQL + `)`

const platformJobFilterSQL = `
	FROM background_jobs job
	WHERE ($1::uuid IS NULL OR job.tenant_id=$1)
	  AND ($2::uuid IS NULL OR job.id=$2)
	  AND ($3::text[] IS NULL OR job.state=ANY($3))
	  AND ($4::text IS NULL OR job.kind=$4)
	  AND ($5::text IS NULL OR job.subject=$5 OR ` + resourceItemMatchSQL + `)
	  AND job.created_at >= $6 AND job.created_at < $7`

const platformListSQL = jobListProjectionSQL + platformJobFilterSQL + `
	  AND ($8::timestamptz IS NULL OR (job.created_at,job.id) < ($8,$9::uuid))
	ORDER BY job.created_at DESC,job.id DESC
	LIMIT $10`

const tenantJobFilterSQL = `
	FROM background_jobs job
	JOIN access_scopes scope ON scope.id=$1 AND scope.kind='tenant' AND scope.tenant_id=job.tenant_id
	WHERE ($2::text[] IS NULL OR job.state=ANY($2))
	  AND ($3::uuid IS NULL OR job.id=$3)
	  AND ($4::text IS NULL OR job.kind=$4)
	  AND ($5::text IS NULL OR job.subject=$5 OR ` + resourceItemMatchSQL + `)
	  AND job.created_at >= $6 AND job.created_at < $7`

const tenantListSQL = jobListProjectionSQL + tenantJobFilterSQL + `
	  AND ($8::timestamptz IS NULL OR (job.created_at,job.id) < ($8,$9::uuid))
	ORDER BY job.created_at DESC,job.id DESC
	LIMIT $10`

const platformGetSQL = `
	SELECT job.id,job.tenant_id,job.kind,job.subject,job.request_id,job.trace_id,
	       job.state,job.attempt,job.max_attempts,job.total_count,job.completed_count,
	       job.succeeded_count,job.failed_count,job.cancelled_count,job.last_error_code,
	       job.created_at,job.started_at,job.updated_at,job.completed_at
	FROM background_jobs job WHERE job.id=$1`

const tenantGetSQL = `
	SELECT job.id,job.tenant_id,job.kind,job.subject,job.request_id,job.trace_id,
	       job.state,job.attempt,job.max_attempts,job.total_count,job.completed_count,
	       job.succeeded_count,job.failed_count,job.cancelled_count,job.last_error_code,
	       job.created_at,job.started_at,job.updated_at,job.completed_at
	FROM background_jobs job
	JOIN access_scopes scope ON scope.id=$1 AND scope.kind='tenant' AND scope.tenant_id=job.tenant_id
	WHERE job.id=$2`

const platformAttemptsSQL = `
	SELECT attempt.state,attempt.attempt,attempt.started_at,attempt.last_heartbeat_at,
	       attempt.lease_expires_at,attempt.completed_at,attempt.error_code
	FROM background_job_attempts attempt
	WHERE attempt.job_id=$1 AND ($2::integer IS NULL OR attempt.attempt < $2)
	ORDER BY attempt.attempt DESC LIMIT $3`

const tenantAttemptsSQL = `
	SELECT attempt.state,attempt.attempt,attempt.started_at,attempt.last_heartbeat_at,
	       attempt.lease_expires_at,attempt.completed_at,attempt.error_code
	FROM background_job_attempts attempt
	JOIN background_jobs job ON job.tenant_id=attempt.tenant_id AND job.id=attempt.job_id
	JOIN access_scopes scope ON scope.id=$1 AND scope.kind='tenant' AND scope.tenant_id=job.tenant_id
	WHERE attempt.job_id=$2 AND ($3::integer IS NULL OR attempt.attempt < $3)
	ORDER BY attempt.attempt DESC LIMIT $4`

const platformResultsSQL = `
	SELECT item.ordinal,item.item_id,item.node_id,item.state,item.attempt,item.sequence,
	       item.error_code,item.completed_at,
	       CASE WHEN item.state<>'pending' AND item_attempt.started_at<=item.completed_at THEN item_attempt.started_at END,
	       (SELECT count(*) FROM background_job_results failure
	        WHERE failure.tenant_id=item.tenant_id AND failure.job_id=item.job_id
	          AND failure.item_id=item.item_id AND failure.state='failed')
	FROM background_job_items item
	LEFT JOIN background_job_attempts item_attempt
	  ON item_attempt.job_id=item.job_id AND item_attempt.attempt=item.attempt
	WHERE item.job_id=$1 AND ($2::integer IS NULL OR item.ordinal > $2)
	ORDER BY item.ordinal LIMIT $3`

const tenantResultsSQL = `
	SELECT item.ordinal,item.item_id,item.node_id,item.state,item.attempt,item.sequence,
	       item.error_code,item.completed_at,
	       CASE WHEN item.state<>'pending' AND item_attempt.started_at<=item.completed_at THEN item_attempt.started_at END,
	       (SELECT count(*) FROM background_job_results failure
	        WHERE failure.tenant_id=item.tenant_id AND failure.job_id=item.job_id
	          AND failure.item_id=item.item_id AND failure.state='failed')
	FROM background_job_items item
	LEFT JOIN background_job_attempts item_attempt
	  ON item_attempt.job_id=item.job_id AND item_attempt.attempt=item.attempt
	JOIN background_jobs job ON job.tenant_id=item.tenant_id AND job.id=item.job_id
	JOIN access_scopes scope ON scope.id=$1 AND scope.kind='tenant' AND scope.tenant_id=job.tenant_id
	WHERE item.job_id=$2 AND ($3::integer IS NULL OR item.ordinal > $3)
	ORDER BY item.ordinal LIMIT $4`

const platformReceiptsSQL = `
	SELECT item.ordinal,result.item_id,item.node_id,result.state,result.attempt,result.sequence,
	       result.error_code,result.source,result.reported_at
	FROM background_job_results result
	JOIN background_job_items item
	  ON item.tenant_id=result.tenant_id AND item.job_id=result.job_id AND item.item_id=result.item_id
	WHERE result.job_id=$1 AND ($2::integer IS NULL OR result.attempt < $2 OR
	      (result.attempt=$2 AND item.ordinal > $3::integer))
	ORDER BY result.attempt DESC,item.ordinal ASC LIMIT $4`

const tenantReceiptsSQL = `
	SELECT item.ordinal,result.item_id,item.node_id,result.state,result.attempt,result.sequence,
	       result.error_code,result.source,result.reported_at
	FROM background_job_results result
	JOIN background_job_items item
	  ON item.tenant_id=result.tenant_id AND item.job_id=result.job_id AND item.item_id=result.item_id
	JOIN background_jobs job ON job.tenant_id=result.tenant_id AND job.id=result.job_id
	JOIN access_scopes scope ON scope.id=$1 AND scope.kind='tenant' AND scope.tenant_id=job.tenant_id
	WHERE result.job_id=$2 AND ($3::integer IS NULL OR result.attempt < $3 OR
	      (result.attempt=$3 AND item.ordinal > $4::integer))
	ORDER BY result.attempt DESC,item.ordinal ASC LIMIT $5`

const platformDeadLettersSQL = `
	SELECT attempt,reason_code,failed_item_count,source,created_at
	FROM background_job_dead_letters
	WHERE job_id=$1 AND ($2::integer IS NULL OR attempt < $2)
	ORDER BY attempt DESC LIMIT $3`

const tenantDeadLettersSQL = `
	SELECT letter.attempt,letter.reason_code,letter.failed_item_count,letter.source,letter.created_at
	FROM background_job_dead_letters letter
	JOIN background_jobs job ON job.tenant_id=letter.tenant_id AND job.id=letter.job_id
	JOIN access_scopes scope ON scope.id=$1 AND scope.kind='tenant' AND scope.tenant_id=job.tenant_id
	WHERE letter.job_id=$2 AND ($3::integer IS NULL OR letter.attempt < $3)
	ORDER BY letter.attempt DESC LIMIT $4`

type PostgresReader struct {
	pool    *pgxpool.Pool
	auditor commandAuditAppender
	now     func() time.Time
	// apiKeys 在命令事务内复核 API 密钥；未配置时 API 密钥命令一律 503（失败即关）。
	apiKeys commandAPIKeyAuthorizer
}

// UseIAM 配置命令事务内的 API 密钥复核（API-JOBS-02）。
func (reader *PostgresReader) UseIAM(iam *iamlock.Authorizer) error {
	if reader == nil || iam == nil || !iam.Configured() {
		return ErrInvalidRequest
	}
	reader.apiKeys = iamCommandAPIKeyAuthorizer{iam: iam}
	return nil
}

func NewPostgresReader(pool *pgxpool.Pool) (*PostgresReader, error) {
	if pool == nil {
		return nil, ErrInvalidRequest
	}
	clock := time.Now
	return &PostgresReader{pool: pool, auditor: newCommandAuditor(pool, clock), now: clock}, nil
}

func (reader *PostgresReader) List(ctx context.Context, scope ReadScope, query ListQuery) ([]Job, error) {
	if ctx == nil || !validReadScope(scope) {
		return nil, ErrInvalidRequest
	}
	states := stateStrings(query.States)
	var rows pgx.Rows
	var err error
	switch scope.Kind {
	case ScopePlatform:
		rows, err = reader.pool.Query(ctx, platformListSQL,
			query.TenantID, query.TaskID, nullableSlice(states), nullableString(query.Kind), nullableString(query.Resource),
			query.From, query.To, query.AfterCreated, query.AfterTaskID, query.Limit)
	case ScopeTenant:
		rows, err = reader.pool.Query(ctx, tenantListSQL,
			scope.ID, nullableSlice(states), query.TaskID, nullableString(query.Kind), nullableString(query.Resource),
			query.From, query.To, query.AfterCreated, query.AfterTaskID, query.Limit)
	}
	if err != nil {
		return nil, postgresError(ctx, "list jobs")
	}
	defer rows.Close()
	jobs := make([]Job, 0, query.Limit)
	for rows.Next() {
		job, err := scanListJob(rows)
		if err != nil {
			return nil, postgresError(ctx, "scan jobs")
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, postgresError(ctx, "iterate jobs")
	}
	return jobs, nil
}

func (reader *PostgresReader) Get(ctx context.Context, scope ReadScope, taskID uuid.UUID) (Job, error) {
	if ctx == nil || !validReadScope(scope) || taskID == uuid.Nil {
		return Job{}, ErrInvalidRequest
	}
	var row pgx.Row
	switch scope.Kind {
	case ScopePlatform:
		row = reader.pool.QueryRow(ctx, platformGetSQL, taskID)
	case ScopeTenant:
		row = reader.pool.QueryRow(ctx, tenantGetSQL, scope.ID, taskID)
	}
	job, err := scanJob(row)
	if err == pgx.ErrNoRows {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, postgresError(ctx, "get job")
	}
	return job, nil
}

func (reader *PostgresReader) Attempts(
	ctx context.Context,
	scope ReadScope,
	taskID uuid.UUID,
	query AttemptQuery,
) ([]Attempt, error) {
	if ctx == nil || !validReadScope(scope) || taskID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	var rows pgx.Rows
	var err error
	switch scope.Kind {
	case ScopePlatform:
		rows, err = reader.pool.Query(ctx, platformAttemptsSQL, taskID, query.AfterAttempt, query.Limit)
	case ScopeTenant:
		rows, err = reader.pool.Query(ctx, tenantAttemptsSQL, scope.ID, taskID, query.AfterAttempt, query.Limit)
	}
	if err != nil {
		return nil, postgresError(ctx, "list job attempts")
	}
	defer rows.Close()
	result := make([]Attempt, 0, query.Limit)
	for rows.Next() {
		var attempt Attempt
		var state string
		var number int
		var completedAt *time.Time
		var failureCode *string
		if err := rows.Scan(&state, &number, &attempt.StartedAt, &attempt.LastHeartbeatAt,
			&attempt.LeaseExpiresAt, &completedAt, &failureCode); err != nil {
			return nil, postgresError(ctx, "scan job attempts")
		}
		attempt.Status = AttemptState(state)
		attempt.Number = uint32(number)
		attempt.StartedAt = attempt.StartedAt.UTC()
		attempt.LastHeartbeatAt = attempt.LastHeartbeatAt.UTC()
		attempt.LeaseExpiresAt = attempt.LeaseExpiresAt.UTC()
		attempt.CompletedAt = utcTimePointer(completedAt)
		attempt.FailureCode = pointerString(failureCode)
		result = append(result, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, postgresError(ctx, "iterate job attempts")
	}
	return result, nil
}

func (reader *PostgresReader) Results(
	ctx context.Context,
	scope ReadScope,
	taskID uuid.UUID,
	query ResultQuery,
) ([]ItemResult, error) {
	if ctx == nil || !validReadScope(scope) || taskID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	var rows pgx.Rows
	var err error
	switch scope.Kind {
	case ScopePlatform:
		rows, err = reader.pool.Query(ctx, platformResultsSQL, taskID, query.AfterOrdinal, query.Limit)
	case ScopeTenant:
		rows, err = reader.pool.Query(ctx, tenantResultsSQL, scope.ID, taskID, query.AfterOrdinal, query.Limit)
	}
	if err != nil {
		return nil, postgresError(ctx, "list job results")
	}
	defer rows.Close()
	result := make([]ItemResult, 0, query.Limit)
	for rows.Next() {
		var item ItemResult
		var state string
		var attempt int
		var sequence int64
		var failureCode *string
		var completedAt, startedAt *time.Time
		var failureCount int64
		if err := rows.Scan(&item.Ordinal, &item.ItemID, &item.NodeID, &state, &attempt,
			&sequence, &failureCode, &completedAt, &startedAt, &failureCount); err != nil {
			return nil, postgresError(ctx, "scan job results")
		}
		item.Status = ResultState(state)
		item.Attempt = uint32(attempt)
		item.Sequence = uint64(sequence)
		item.FailureCode = pointerString(failureCode)
		item.CompletedAt = utcTimePointer(completedAt)
		item.StartedAt = utcTimePointer(startedAt)
		item.FailureCount = int(failureCount)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, postgresError(ctx, "iterate job results")
	}
	return result, nil
}

func (reader *PostgresReader) Receipts(
	ctx context.Context,
	scope ReadScope,
	taskID uuid.UUID,
	query ReceiptQuery,
) ([]SettlementReceipt, error) {
	if ctx == nil || !validReadScope(scope) || taskID == uuid.Nil ||
		(query.AfterAttempt == nil) != (query.AfterOrdinal == nil) {
		return nil, ErrInvalidRequest
	}
	var rows pgx.Rows
	var err error
	switch scope.Kind {
	case ScopePlatform:
		rows, err = reader.pool.Query(ctx, platformReceiptsSQL, taskID, query.AfterAttempt, query.AfterOrdinal, query.Limit)
	case ScopeTenant:
		rows, err = reader.pool.Query(ctx, tenantReceiptsSQL, scope.ID, taskID, query.AfterAttempt, query.AfterOrdinal, query.Limit)
	}
	if err != nil {
		return nil, postgresError(ctx, "list job settlement receipts")
	}
	defer rows.Close()
	result := make([]SettlementReceipt, 0, query.Limit)
	for rows.Next() {
		var receipt SettlementReceipt
		var state string
		var attempt int
		var sequence int64
		var failureCode *string
		if err := rows.Scan(&receipt.Ordinal, &receipt.ItemID, &receipt.NodeID, &state, &attempt,
			&sequence, &failureCode, &receipt.Source, &receipt.ReportedAt); err != nil {
			return nil, postgresError(ctx, "scan job settlement receipts")
		}
		receipt.Status = ResultState(state)
		receipt.Attempt = uint32(attempt)
		receipt.Sequence = uint64(sequence)
		receipt.FailureCode = pointerString(failureCode)
		receipt.ReportedAt = receipt.ReportedAt.UTC()
		result = append(result, receipt)
	}
	if err := rows.Err(); err != nil {
		return nil, postgresError(ctx, "iterate job settlement receipts")
	}
	return result, nil
}

func (reader *PostgresReader) DeadLetters(
	ctx context.Context,
	scope ReadScope,
	taskID uuid.UUID,
	query DeadLetterQuery,
) ([]DeadLetter, error) {
	if ctx == nil || !validReadScope(scope) || taskID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	var rows pgx.Rows
	var err error
	switch scope.Kind {
	case ScopePlatform:
		rows, err = reader.pool.Query(ctx, platformDeadLettersSQL, taskID, query.AfterAttempt, query.Limit)
	case ScopeTenant:
		rows, err = reader.pool.Query(ctx, tenantDeadLettersSQL, scope.ID, taskID, query.AfterAttempt, query.Limit)
	}
	if err != nil {
		return nil, postgresError(ctx, "list job dead letters")
	}
	defer rows.Close()
	result := make([]DeadLetter, 0, query.Limit)
	for rows.Next() {
		var letter DeadLetter
		var attempt int
		if err := rows.Scan(&attempt, &letter.ReasonCode, &letter.FailedItemCount,
			&letter.Source, &letter.CreatedAt); err != nil {
			return nil, postgresError(ctx, "scan job dead letters")
		}
		letter.Attempt = uint32(attempt)
		letter.CreatedAt = letter.CreatedAt.UTC()
		result = append(result, letter)
	}
	if err := rows.Err(); err != nil {
		return nil, postgresError(ctx, "iterate job dead letters")
	}
	return result, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanJob(scanner rowScanner) (Job, error) {
	return scanJobColumns(scanner)
}

// scanListJob reads a list row whose projection ends with the item-node match flag.
func scanListJob(scanner rowScanner) (Job, error) {
	var matched bool
	job, err := scanJobColumns(scanner, &matched)
	job.resourceMatchedByNode = matched
	return job, err
}

func scanJobColumns(scanner rowScanner, extra ...any) (Job, error) {
	var job Job
	var state string
	var attempt, maxAttempts int
	var failureCode *string
	var startedAt, completedAt *time.Time
	if err := scanner.Scan(append([]any{
		&job.TaskID, &job.TenantID, &job.Kind, &job.RelatedResource.Reference,
		&job.RequestID, &job.TraceID, &state, &attempt, &maxAttempts,
		&job.Progress.Total, &job.Progress.Completed, &job.Progress.Succeeded,
		&job.Progress.Failed, &job.Progress.Cancelled, &failureCode,
		&job.CreatedAt, &startedAt, &job.UpdatedAt, &completedAt,
	}, extra...)...); err != nil {
		return Job{}, err
	}
	job.Status = State(state)
	job.Attempt = uint32(attempt)
	job.MaxAttempts = uint32(maxAttempts)
	job.Progress.Pending = job.Progress.Total - job.Progress.Completed
	job.FailureCode = pointerString(failureCode)
	job.CreatedAt = job.CreatedAt.UTC()
	job.StartedAt = utcTimePointer(startedAt)
	job.UpdatedAt = job.UpdatedAt.UTC()
	job.CompletedAt = utcTimePointer(completedAt)
	job.Revision = revisionForJob(job)
	return job, nil
}

func validReadScope(scope ReadScope) bool {
	return scope.ID != uuid.Nil && (scope.Kind == ScopePlatform || scope.Kind == ScopeTenant)
}

func stateStrings(states []State) []string {
	if len(states) == 0 {
		return nil
	}
	result := make([]string, len(states))
	for index, state := range states {
		result[index] = string(state)
	}
	return result
}

func nullableSlice(value []string) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func postgresError(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, operation)
}
