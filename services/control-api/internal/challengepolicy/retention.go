package challengepolicy

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

const maxIdempotencyPruneBatch = 1000

const pruneCompletedIdempotencySQL = `
	WITH expired AS (
		SELECT id
		FROM challenge_policy_write_requests
		WHERE completed_at IS NOT NULL
		  AND retention_expires_at <= LEAST($1, transaction_timestamp())
		ORDER BY retention_expires_at, id
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	)
	DELETE FROM challenge_policy_write_requests request
	USING expired
	WHERE request.id = expired.id`

// PruneCompletedIdempotency removes at most limit completed receipts whose fixed retention has expired.
func (store *Store) PruneCompletedIdempotency(ctx context.Context, now time.Time, limit int) (int64, error) {
	if store == nil || store.pool == nil || now.IsZero() || limit < 1 || limit > maxIdempotencyPruneBatch {
		return 0, ErrInvalidInput
	}
	var pruned int64
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, pruneCompletedIdempotencySQL, now.UTC().Truncate(time.Microsecond), limit)
		if err != nil {
			return err
		}
		pruned = command.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, normalizeStoreError(err)
	}
	return pruned, nil
}
