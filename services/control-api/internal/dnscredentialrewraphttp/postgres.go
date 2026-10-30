package dnscredentialrewraphttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	batchOperationPrefix = "dns.provider.credential_rewrap.batch:"
	itemOperationPrefix  = "dns.provider.credential_rewrap.item:"
	itemWriteOperation   = "dns.provider.credential_rewrap"
)

type postgresRepository struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

type intentRecord struct {
	ordinal   int
	item      BatchItem
	progress  ItemProgress
	updatedAt time.Time
	complete  bool
}

func newPostgresRepository(pool *pgxpool.Pool, now func() time.Time) *postgresRepository {
	return &postgresRepository{pool: pool, now: now}
}

func (repository *postgresRepository) Claim(ctx context.Context, request ClaimRequest) (Claim, error) {
	if repository == nil || repository.pool == nil || repository.now == nil || ctx == nil ||
		!request.Owner.valid() || !metadataPattern.MatchString(request.IdempotencyKey) || len(request.Items) == 0 ||
		len(request.Items) > MaxBatchItems {
		return Claim{}, ErrInvalidRequest
	}
	jobID, err := uuid.NewV7()
	if err != nil {
		return Claim{}, unavailable(err)
	}
	var claim Claim
	err = pgx.BeginFunc(ctx, repository.pool, func(tx pgx.Tx) error {
		command, insertErr := tx.Exec(ctx, `
			INSERT INTO dns_acme_write_requests(
				id,actor_user_id,target_scope_id,operation,idempotency_key,request_digest
			) VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT(actor_user_id,operation,idempotency_key) DO NOTHING`,
			jobID, request.Owner.UserID, request.Owner.ScopeID, batchOperation(request.Owner.SessionID),
			request.IdempotencyKey, request.Digest[:])
		if insertErr != nil {
			return unavailable(insertErr)
		}
		if command.RowsAffected() == 1 {
			for ordinal, item := range request.Items {
				intentID, idErr := uuid.NewV7()
				if idErr != nil {
					return unavailable(idErr)
				}
				digest := intentDigest(request.Owner, jobID, ordinal, item)
				if _, insertErr = tx.Exec(ctx, `
					INSERT INTO dns_acme_write_requests(
						id,actor_user_id,target_scope_id,operation,idempotency_key,request_digest
					) VALUES($1,$2,$3,$4,$5,$6)`, intentID, request.Owner.UserID, request.Owner.ScopeID,
					itemOperation(request.Owner.SessionID, jobID, ordinal, item), request.IdempotencyKey, digest[:]); insertErr != nil {
					return unavailable(insertErr)
				}
			}
			var createdAt time.Time
			if queryErr := tx.QueryRow(ctx, `SELECT created_at FROM dns_acme_write_requests WHERE id=$1`, jobID).Scan(&createdAt); queryErr != nil {
				return unavailable(queryErr)
			}
			claim = Claim{
				ID: jobID, CreatedAt: createdAt.UTC(), UpdatedAt: createdAt.UTC(),
				Items: append([]BatchItem(nil), request.Items...),
			}
			return nil
		}

		var storedDigest, response []byte
		var completedAt *time.Time
		var createdAt time.Time
		if queryErr := tx.QueryRow(ctx, `
			SELECT id,request_digest,response_body::text::bytea,created_at,completed_at
			FROM dns_acme_write_requests
			WHERE actor_user_id=$1 AND target_scope_id=$2 AND operation=$3 AND idempotency_key=$4
			FOR UPDATE`, request.Owner.UserID, request.Owner.ScopeID, batchOperation(request.Owner.SessionID),
			request.IdempotencyKey).Scan(&jobID, &storedDigest, &response, &createdAt, &completedAt); queryErr != nil {
			return unavailable(queryErr)
		}
		if len(storedDigest) != sha256.Size || !bytes.Equal(storedDigest, request.Digest[:]) {
			return ErrIdempotencyConflict
		}
		claim = Claim{ID: jobID, CreatedAt: createdAt.UTC(), UpdatedAt: createdAt.UTC()}
		if completedAt != nil {
			if len(response) == 0 || json.Unmarshal(response, &claim.Job) != nil {
				return unavailable(errors.New("invalid completed batch receipt"))
			}
			claim.Complete = true
			return nil
		}
		intents, loadErr := loadIntents(ctx, tx, request.Owner, jobID, true)
		if loadErr != nil {
			return loadErr
		}
		claim.Items = intentItems(intents)
		for _, intent := range intents {
			if intent.updatedAt.After(claim.UpdatedAt) {
				claim.UpdatedAt = intent.updatedAt
			}
		}
		if !sameBatchItems(claim.Items, request.Items) {
			return ErrIdempotencyConflict
		}
		return nil
	})
	if err != nil {
		return Claim{}, err
	}
	return claim, nil
}

func (repository *postgresRepository) ItemCompleted(ctx context.Context, owner Owner, key string) (bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil || !owner.valid() || !metadataPattern.MatchString(key) {
		return false, ErrInvalidRequest
	}
	var completed bool
	err := repository.pool.QueryRow(ctx, `
		SELECT completed_at IS NOT NULL
		FROM dns_acme_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		owner.UserID, itemWriteOperation, key).Scan(&completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, unavailable(err)
	}
	return completed, nil
}

func (repository *postgresRepository) Item(
	ctx context.Context,
	owner Owner,
	jobID uuid.UUID,
	ordinal int,
) (ItemProgress, bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil || !owner.valid() || jobID == uuid.Nil ||
		ordinal < 0 || ordinal >= MaxBatchItems {
		return ItemProgress{}, false, ErrInvalidRequest
	}
	rows, err := repository.pool.Query(ctx, `
		SELECT operation,response_body::text::bytea,completed_at IS NOT NULL
		FROM dns_acme_write_requests
		WHERE actor_user_id=$1 AND target_scope_id=$2 AND operation LIKE $3
		ORDER BY operation`, owner.UserID, owner.ScopeID,
		itemOperationJobPrefix(owner.SessionID, jobID)+fmt.Sprintf("%03d:", ordinal)+"%")
	if err != nil {
		return ItemProgress{}, false, unavailable(err)
	}
	defer rows.Close()
	var operation string
	var response []byte
	var complete bool
	if !rows.Next() {
		return ItemProgress{}, false, ErrJobNotFound
	}
	if err := rows.Scan(&operation, &response, &complete); err != nil {
		return ItemProgress{}, false, unavailable(err)
	}
	if rows.Next() {
		return ItemProgress{}, false, unavailable(errors.New("duplicate item intent"))
	}
	record, parseErr := parseIntentOperation(operation, owner, jobID)
	if parseErr != nil || record.ordinal != ordinal {
		return ItemProgress{}, false, unavailable(errors.New("invalid item intent"))
	}
	if !complete {
		return ItemProgress{
			ProviderID: record.item.ProviderID, ExpectedRevision: record.item.ExpectedRevision, Status: ItemPending,
		}, false, nil
	}
	if len(response) == 0 || json.Unmarshal(response, &record.progress) != nil ||
		!validTerminalItem(record.progress, record.item) {
		return ItemProgress{}, false, unavailable(errors.New("invalid item receipt"))
	}
	return record.progress, true, nil
}

func (repository *postgresRepository) CompleteItem(
	ctx context.Context,
	request CompleteItemRequest,
) (ItemProgress, error) {
	item := BatchItem{ProviderID: request.Item.ProviderID, ExpectedRevision: request.Item.ExpectedRevision}
	if repository == nil || repository.pool == nil || repository.now == nil || ctx == nil || !request.Owner.valid() ||
		request.JobID == uuid.Nil || request.Ordinal < 0 || request.Ordinal >= MaxBatchItems ||
		!validTerminalItem(request.Item, item) {
		return ItemProgress{}, ErrInvalidRequest
	}
	encoded, err := json.Marshal(request.Item)
	if err != nil {
		return ItemProgress{}, unavailable(err)
	}
	digest := intentDigest(request.Owner, request.JobID, request.Ordinal, item)
	command, err := repository.pool.Exec(ctx, `
		UPDATE dns_acme_write_requests
		SET resource_id=$5,response_body=$6,completed_at=$7
		WHERE actor_user_id=$1 AND target_scope_id=$2 AND operation=$3 AND request_digest=$4
		  AND idempotency_key<>'' AND completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL`,
		request.Owner.UserID, request.Owner.ScopeID,
		itemOperation(request.Owner.SessionID, request.JobID, request.Ordinal, item), digest[:],
		item.ProviderID, encoded, repository.now().UTC())
	if err != nil {
		return ItemProgress{}, unavailable(err)
	}
	if command.RowsAffected() == 1 {
		return request.Item, nil
	}
	stored, complete, readErr := repository.Item(ctx, request.Owner, request.JobID, request.Ordinal)
	if readErr != nil {
		return ItemProgress{}, readErr
	}
	if !complete {
		return ItemProgress{}, ErrIdempotencyConflict
	}
	return stored, nil
}

func (repository *postgresRepository) Complete(ctx context.Context, request CompleteRequest) (Job, error) {
	if repository == nil || repository.pool == nil || repository.now == nil || ctx == nil ||
		!request.Owner.valid() || !validJob(request.Job) || request.Job.State == JobProcessing {
		return Job{}, ErrInvalidRequest
	}
	request.Job.CompletedAt = repository.now().UTC()
	request.Job.UpdatedAt = request.Job.CompletedAt
	encoded, err := json.Marshal(request.Job)
	if err != nil {
		return Job{}, unavailable(err)
	}
	command, err := repository.pool.Exec(ctx, `
		UPDATE dns_acme_write_requests
		SET resource_id=$5,response_body=$6,completed_at=$7
		WHERE id=$1 AND actor_user_id=$2 AND target_scope_id=$3 AND operation=$4
		  AND completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL`,
		request.Job.ID, request.Owner.UserID, request.Owner.ScopeID, batchOperation(request.Owner.SessionID),
		request.Job.ID, encoded, request.Job.CompletedAt)
	if err != nil {
		return Job{}, unavailable(err)
	}
	if command.RowsAffected() == 1 {
		return request.Job, nil
	}
	return repository.Get(ctx, GetRequest{Owner: request.Owner, JobID: request.Job.ID})
}

func (repository *postgresRepository) Get(ctx context.Context, request GetRequest) (Job, error) {
	if repository == nil || repository.pool == nil || ctx == nil || !request.Owner.valid() || request.JobID == uuid.Nil {
		return Job{}, ErrInvalidRequest
	}
	var response []byte
	var createdAt time.Time
	var completedAt *time.Time
	err := repository.pool.QueryRow(ctx, `
		SELECT response_body::text::bytea,created_at,completed_at
		FROM dns_acme_write_requests
		WHERE id=$1 AND actor_user_id=$2 AND target_scope_id=$3 AND operation=$4`,
		request.JobID, request.Owner.UserID, request.Owner.ScopeID,
		batchOperation(request.Owner.SessionID)).Scan(&response, &createdAt, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrJobNotFound
	}
	if err != nil {
		return Job{}, unavailable(err)
	}
	if completedAt != nil {
		var job Job
		if len(response) == 0 || json.Unmarshal(response, &job) != nil {
			return Job{}, unavailable(errors.New("invalid completed batch receipt"))
		}
		return job, nil
	}
	intents, err := loadIntents(ctx, repository.pool, request.Owner, request.JobID, false)
	if err != nil {
		return Job{}, err
	}
	job := Job{
		ID: request.JobID, State: JobProcessing, Requested: len(intents),
		Items: make([]ItemProgress, len(intents)), CreatedAt: createdAt.UTC(), UpdatedAt: createdAt.UTC(),
	}
	for index, intent := range intents {
		if intent.updatedAt.After(job.UpdatedAt) {
			job.UpdatedAt = intent.updatedAt
		}
		if intent.complete {
			job.Items[index] = intent.progress
			job.Completed++
			switch intent.progress.Status {
			case ItemCompleted:
				job.Succeeded++
			case ItemReplayed:
				job.Succeeded++
				job.Replayed++
			case ItemConflict:
				job.Conflicted++
			case ItemFailed:
				job.Failed++
			}
			continue
		}
		job.Items[index] = ItemProgress{
			ProviderID: intent.item.ProviderID, ExpectedRevision: intent.item.ExpectedRevision, Status: ItemPending,
		}
	}
	return job, nil
}

func (repository *postgresRepository) WithJobLock(
	ctx context.Context,
	jobID uuid.UUID,
	run func(context.Context) error,
) (bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil || jobID == uuid.Nil || run == nil {
		return false, ErrInvalidRequest
	}
	connection, err := repository.pool.Acquire(ctx)
	if err != nil {
		return false, unavailable(err)
	}
	left, right := advisoryLockKeys()
	var acquired bool
	if err := connection.QueryRow(ctx, `SELECT pg_try_advisory_lock($1::integer,$2::integer)`, left, right).Scan(&acquired); err != nil {
		// The lock state is unknown: never hand this session back to the pool.
		_ = connection.Hijack().Close(context.Background())
		return false, unavailable(err)
	}
	if !acquired {
		connection.Release()
		return false, nil
	}
	defer func() {
		unlockContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var unlocked bool
		err := connection.QueryRow(unlockContext, `SELECT pg_advisory_unlock($1::integer,$2::integer)`, left, right).Scan(&unlocked)
		if err != nil || !unlocked {
			// notif-sub: a pooled connection still holding a session advisory
			// lock makes every IAM-locked transaction on it fail (P6902).
			_ = connection.Hijack().Close(unlockContext)
			return
		}
		connection.Release()
	}()
	return true, run(ctx)
}

type rowsQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadIntents(
	ctx context.Context,
	querier rowsQuerier,
	owner Owner,
	jobID uuid.UUID,
	lock bool,
) ([]intentRecord, error) {
	query := `SELECT operation,response_body::text::bytea,completed_at
		FROM dns_acme_write_requests
		WHERE actor_user_id=$1 AND target_scope_id=$2 AND operation LIKE $3
		ORDER BY operation`
	if lock {
		query += " FOR UPDATE"
	}
	rows, err := querier.Query(ctx, query, owner.UserID, owner.ScopeID, itemOperationJobPrefix(owner.SessionID, jobID)+"%")
	if err != nil {
		return nil, unavailable(err)
	}
	defer rows.Close()
	intents := make([]intentRecord, 0)
	for rows.Next() {
		var operation string
		var response []byte
		var completedAt *time.Time
		if err := rows.Scan(&operation, &response, &completedAt); err != nil {
			return nil, unavailable(err)
		}
		record, err := parseIntentOperation(operation, owner, jobID)
		if err != nil || record.ordinal != len(intents) {
			return nil, unavailable(errors.New("invalid item intent sequence"))
		}
		record.complete = completedAt != nil
		if completedAt != nil {
			record.updatedAt = completedAt.UTC()
			if len(response) == 0 || json.Unmarshal(response, &record.progress) != nil ||
				!validTerminalItem(record.progress, record.item) {
				return nil, unavailable(errors.New("invalid item receipt"))
			}
		}
		intents = append(intents, record)
	}
	if rows.Err() != nil {
		return nil, unavailable(rows.Err())
	}
	if len(intents) == 0 || len(intents) > MaxBatchItems {
		return nil, unavailable(errors.New("missing item intents"))
	}
	return intents, nil
}

func intentItems(intents []intentRecord) []BatchItem {
	items := make([]BatchItem, len(intents))
	for index, intent := range intents {
		items[index] = intent.item
	}
	return items
}

func batchOperation(sessionID uuid.UUID) string {
	return batchOperationPrefix + sessionID.String()
}

func itemOperationJobPrefix(sessionID, jobID uuid.UUID) string {
	return itemOperationPrefix + sessionID.String() + ":" + jobID.String() + ":"
}

func itemOperation(sessionID, jobID uuid.UUID, ordinal int, item BatchItem) string {
	return itemOperationJobPrefix(sessionID, jobID) + fmt.Sprintf("%03d:%s:%d", ordinal, item.ProviderID, item.ExpectedRevision)
}

func parseIntentOperation(operation string, owner Owner, jobID uuid.UUID) (intentRecord, error) {
	prefix := itemOperationJobPrefix(owner.SessionID, jobID)
	if !strings.HasPrefix(operation, prefix) {
		return intentRecord{}, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(operation, prefix), ":")
	if len(parts) != 3 {
		return intentRecord{}, ErrUnavailable
	}
	ordinal, ordinalErr := strconv.Atoi(parts[0])
	providerID, providerErr := uuid.Parse(parts[1])
	revision, revisionErr := strconv.ParseInt(parts[2], 10, 64)
	if ordinalErr != nil || ordinal < 0 || ordinal >= MaxBatchItems || fmt.Sprintf("%03d", ordinal) != parts[0] ||
		providerErr != nil || providerID == uuid.Nil || providerID.String() != parts[1] || revisionErr != nil || revision < 1 {
		return intentRecord{}, ErrUnavailable
	}
	return intentRecord{ordinal: ordinal, item: BatchItem{ProviderID: providerID, ExpectedRevision: revision}}, nil
}

func advisoryLockKeys() (int32, int32) {
	digest := sha256.Sum256([]byte("dns-credential-rewrap-global-job-lock/v1"))
	return int32(binary.BigEndian.Uint32(digest[0:4])), int32(binary.BigEndian.Uint32(digest[4:8]))
}

func unavailable(err error) error {
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

var _ Repository = (*postgresRepository)(nil)
