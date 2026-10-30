package analytics

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Defaults of the cleanup settings page (systemcleanup.DefaultSettings),
// used when no settings row exists; the ClickHouse TTL sync uses the same.
const (
	defaultAccessLogDays = 7
	defaultHistoryDays   = 90
)

// PostgresRetentionReader reads access_logs_days and bandwidth_history_days
// from platform_system_cleanup_settings (what retentioncleanup applies to the
// ClickHouse TTLs), cached for a minute.
type PostgresRetentionReader struct {
	pool *pgxpool.Pool

	mu       sync.Mutex
	cached   Retention
	cachedAt time.Time
}

func NewPostgresRetentionReader(pool *pgxpool.Pool) *PostgresRetentionReader {
	return &PostgresRetentionReader{pool: pool}
}

func (reader *PostgresRetentionReader) AnalyticsRetention(ctx context.Context) (Retention, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !reader.cachedAt.IsZero() && time.Since(reader.cachedAt) < time.Minute {
		return reader.cached, nil
	}
	retention := Retention{AccessLogDays: defaultAccessLogDays, HistoryDays: defaultHistoryDays}
	var accessLogDays, historyDays *int
	if err := reader.pool.QueryRow(ctx, `SELECT max((settings->>'access_logs_days')::integer),
		max((settings->>'bandwidth_history_days')::integer) FROM platform_system_cleanup_settings`).Scan(&accessLogDays, &historyDays); err != nil {
		return Retention{}, err
	}
	if accessLogDays != nil && *accessLogDays >= 0 {
		retention.AccessLogDays = *accessLogDays
	}
	if historyDays != nil && *historyDays >= 0 {
		retention.HistoryDays = *historyDays
	}
	reader.cached, reader.cachedAt = retention, time.Now()
	return retention, nil
}
