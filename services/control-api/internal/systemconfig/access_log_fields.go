package systemconfig

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func cloneAccessLogFields(input *edgeconfig.AccessLogFields) *edgeconfig.AccessLogFields {
	if input == nil {
		return nil
	}
	return &edgeconfig.AccessLogFields{Fields: slices.Clone(input.Fields)}
}

// AccessLogFieldReader answers the active access_log_fields for the
// analytics ingest, re-read at most every refreshEvery. A read failure keeps
// the last value (the default before the first success) and is logged, so
// ingest never stops on it.
type AccessLogFieldReader struct {
	pool         *pgxpool.Pool
	logger       *slog.Logger
	refreshEvery time.Duration
	now          func() time.Time

	mu       sync.Mutex
	value    edgeconfig.AccessLogFields
	loadedAt time.Time
}

func NewAccessLogFieldReader(pool *pgxpool.Pool, logger *slog.Logger) *AccessLogFieldReader {
	if logger == nil {
		logger = slog.Default()
	}
	return &AccessLogFieldReader{pool: pool, logger: logger, refreshEvery: 30 * time.Second, now: time.Now,
		value: edgeconfig.EffectiveAccessLogFields(nil)}
}

func (reader *AccessLogFieldReader) AccessLogFields(ctx context.Context) edgeconfig.AccessLogFields {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !reader.loadedAt.IsZero() && reader.now().Sub(reader.loadedAt) < reader.refreshEvery {
		return reader.value
	}
	var value edgeconfig.AccessLogFields
	err := pgx.BeginTxFunc(ctx, reader.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		active, found, err := LoadActiveEdgeNginx(ctx, tx)
		if err != nil {
			return err
		}
		value = active.AccessLogFields
		if !found {
			value = edgeconfig.EffectiveAccessLogFields(nil)
		}
		return nil
	})
	if err != nil {
		reader.logger.Warn("access log fields unavailable; keeping the last value", "error", err)
		return reader.value
	}
	reader.value, reader.loadedAt = value, reader.now()
	return reader.value
}
