package analytics

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The reader follows the cleanup settings the ClickHouse TTL sync applies,
// with the page defaults when no settings row exists.
func TestPostgresRetentionReaderIntegration(t *testing.T) {
	base := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgx.Connect(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	name := "retention_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := admin.Exec(t.Context(), "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(t.Context(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(t.Context())
	})
	config, err := pgxpool.ParseConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Shape of migration 193 (only the settings document matters here).
	if _, err := pool.Exec(t.Context(), `CREATE TABLE platform_system_cleanup_settings (
		platform_scope_id uuid PRIMARY KEY, settings jsonb NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	reader := NewPostgresRetentionReader(pool)
	retention, err := reader.AnalyticsRetention(t.Context())
	if err != nil || retention != (Retention{AccessLogDays: 7, HistoryDays: 90}) {
		t.Fatalf("defaults = %#v, %v", retention, err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO platform_system_cleanup_settings VALUES
		(gen_random_uuid(), '{"access_logs_days": 3, "bandwidth_history_days": 400}')`); err != nil {
		t.Fatal(err)
	}
	reader = NewPostgresRetentionReader(pool)
	retention, err = reader.AnalyticsRetention(t.Context())
	if err != nil || retention != (Retention{AccessLogDays: 3, HistoryDays: 400}) {
		t.Fatalf("settings = %#v, %v", retention, err)
	}
}
