package nodemetrics

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresReaderHistoryReturnsNewestLimitInChronologicalOrder(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	adminPool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "nodemetrics_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(t.Context(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		_, _ = adminPool.Exec(t.Context(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		// t.Context() is already cancelled when cleanup runs.
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
	})
	_, err = pool.Exec(t.Context(), `
		CREATE TABLE nodes (
			id uuid PRIMARY KEY,
			scope_id uuid NOT NULL,
			name text NOT NULL
		);
		CREATE TABLE node_metric_samples (
			node_id uuid NOT NULL,
			publication_sequence bigint NOT NULL,
			observed_at timestamptz NOT NULL,
			record_kind text NOT NULL,
			metrics_known boolean NOT NULL,
			cpu_percent double precision,
			memory_used_bytes bigint,
			memory_total_bytes bigint,
			active_connections bigint,
			rx_bandwidth_bps bigint,
			tx_bandwidth_bps bigint,
			telemetry_json jsonb,
			total_rx_bytes bigint,
			total_tx_bytes bigint
		)`)
	if err != nil {
		t.Fatal(err)
	}
	scopeID, nodeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes (id, scope_id, name) VALUES ($1, $2, 'edge-1')`,
		nodeID, scopeID); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	for sequence := int64(1); sequence <= 4; sequence++ {
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO node_metric_samples (
				node_id, publication_sequence, observed_at, record_kind, metrics_known,
				cpu_percent, memory_used_bytes, memory_total_bytes, active_connections,
				rx_bandwidth_bps, tx_bandwidth_bps
			) VALUES ($1, $2, $3, 'metric', true, $4, 1, 2, 3, 4, 5)`,
			nodeID, sequence, start.Add(time.Duration(sequence)*time.Minute), float64(sequence)); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	history, err := reader.History(t.Context(), scopeID, nodeID, start, start.Add(5*time.Minute), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].PublicationSequence != 3 || history[1].PublicationSequence != 4 ||
		!history[0].ObservedAt.Before(history[1].ObservedAt) {
		t.Fatalf("history = %#v, want newest sequences [3, 4] in ascending time order", history)
	}
}
