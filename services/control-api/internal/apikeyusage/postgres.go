package apikeyusage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresStore struct {
	pool             *pgxpool.Pool
	operationTimeout time.Duration
}

func newPostgresStore(pool *pgxpool.Pool, operationTimeout time.Duration) *postgresStore {
	return &postgresStore{pool: pool, operationTimeout: operationTimeout}
}

func (s *postgresStore) update(
	ctx context.Context,
	observations map[uuid.UUID]time.Time,
) (int, int, error) {
	if len(observations) == 0 {
		return 0, 0, nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	timeout := fmt.Sprintf("%dms", max(int64(1), s.operationTimeout.Milliseconds()))
	if _, err := tx.Exec(ctx, `
		SELECT set_config('lock_timeout', $1, true),
		       set_config('statement_timeout', $1, true)`, timeout); err != nil {
		return 0, 0, err
	}

	ids := make([]uuid.UUID, 0, len(observations))
	for id := range observations {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	times := make([]time.Time, len(ids))
	for index, id := range ids {
		times[index] = observations[id]
	}

	var updated int
	if err := tx.QueryRow(ctx, `
		WITH observations(key_id, observed_at) AS (
			SELECT * FROM unnest($1::uuid[], $2::timestamptz[])
		), candidates AS (
			SELECT key_id, MAX(observed_at) AS observed_at
			FROM observations
			GROUP BY key_id
		), changed AS (
			UPDATE api_keys AS key
			SET last_used_at = candidate.observed_at
			FROM candidates AS candidate
			WHERE key.id = candidate.key_id
			  AND key.status = 'active'
			  AND key.activated_at IS NOT NULL
			  AND transaction_timestamp() < COALESCE(key.expires_at, 'infinity'::timestamptz)
			  AND candidate.observed_at <= transaction_timestamp()
			  AND candidate.observed_at >= key.activated_at
			  AND candidate.observed_at < COALESCE(key.expires_at, 'infinity'::timestamptz)
			  AND (
				key.last_used_at IS NULL OR
				candidate.observed_at >= key.last_used_at + $3::bigint * interval '1 microsecond'
			  )
			RETURNING key.id
		)
		SELECT count(*) FROM changed`, ids, times, mergeWindow.Microseconds()).Scan(&updated); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return updated, len(observations) - updated, nil
}
