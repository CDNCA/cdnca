package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This test writes only a task-owned schema; published configuration inputs
// are read-only. Missing observations must not disappear from global coverage.
func TestRealtimeRosterIndependentDatabaseCoverage(t *testing.T) {
	dsn := os.Getenv("REALTIME_ROSTER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("REALTIME_ROSTER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "realtime_roster_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := databasetest.CleanupContext()
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
	}()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	config.ConnConfig.RuntimeParams["timezone"] = "UTC"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(ctx, `CREATE TABLE schema_migrations AS SELECT * FROM public.schema_migrations WHERE version<=246`); err != nil {
		t.Fatal(err)
	}
	up, err := migrations.FS.ReadFile("247_realtime_source_roster.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(up)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO schema_migrations SELECT * FROM public.schema_migrations WHERE version BETWEEN 247 AND 277`); err != nil {
		t.Fatal(err)
	}
	emptyRoster, err := migrations.FS.ReadFile("278_realtime_empty_source_roster.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(emptyRoster)); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"analytics_realtime_source_windows_184", "analytics_realtime_expected_counts_131",
		"analytics_access_source_window_contributions_208"} {
		if _, err = pool.Exec(ctx, "CREATE TABLE "+pgx.Identifier{table}.Sanitize()+" AS SELECT * FROM public."+pgx.Identifier{table}.Sanitize()+" WITH NO DATA"); err != nil {
			t.Fatal(err)
		}
	}
	store, _ := NewPostgresRealtimeCoverageStore(pool)
	reader, _ := NewPostgresRealtimeExpectedCountReader(pool)
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.Add(-2 * time.Hour)
	reader.now = func() time.Time { return end.Add(defaultRealtimeCoverageGrace) }
	emptyTopology := false
	for hour := start; hour.Before(end); hour = hour.Add(time.Hour) {
		if err = store.captureRealtimeRoster(ctx, hour); err != nil {
			t.Fatalf("roster capture: %v", err)
		}
		if err = store.captureRealtimeRoster(ctx, hour); err != nil {
			t.Fatalf("idempotent capture: %v", err)
		}
		var raw []byte
		if err = pool.QueryRow(ctx, `SELECT sources FROM analytics_realtime_source_rosters_247 WHERE window_start=$1`, hour).Scan(&raw); err != nil {
			t.Fatal("no published roster available for integration")
		}
		var sources []realtimeRosterSource
		if err = json.Unmarshal(raw, &sources); err != nil {
			t.Fatal(err)
		}
		if len(sources) == 0 {
			if string(raw) != "[]" {
				t.Fatalf("empty roster encoded as %s", raw)
			}
			emptyTopology = true
			continue
		}
		if emptyTopology {
			t.Fatal("topology changed during the test window")
		}
		counts := map[string]int{}
		for _, s := range sources {
			counts[s.ScopeID+"/"+s.SiteID+"/"+s.Host]++
		}
		for _, s := range sources {
			if !s.Stable {
				t.Fatal("integration requires configuration stable before the test window")
			}
			_, err = pool.Exec(ctx, `INSERT INTO analytics_realtime_source_windows_184
                (scope_id,tenant_id,site_id,host,listen_port,window_start,window_end,access_sources_expected,access_sources_finalized,
                 connection_sources_expected,connection_sources_finalized,access_source_watermark,access_finalized_through,
                 connection_source_watermark,connection_finalized_through,evidence_sha256,recorded_at)
                SELECT $1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$8,$8,$8,$7,$7,$7,$7,decode(repeat('ab',32),'hex'),$7
                WHERE NOT EXISTS(SELECT 1 FROM analytics_realtime_source_windows_184 WHERE scope_id=$1::uuid AND site_id=$3::uuid AND host=$4 AND listen_port=$5 AND window_start=$6)`,
				s.ScopeID, s.TenantID, s.SiteID, s.Host, s.ListenPort, hour, hour.Add(time.Hour), counts[s.ScopeID+"/"+s.SiteID+"/"+s.Host])
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	filter := RealtimeFilter{From: start, To: end}
	if emptyTopology {
		assertRealtimeEmptyRosterEvidence(ctx, t, pool, reader, filter)
		return
	}
	evidence, err := reader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter)
	if err != nil || evidence.CoveredWindows != 2 || evidence.ExpectedEvents != 0 || !evidence.FinalizedThrough.Equal(end) {
		var diagnostic []byte
		queryErr := pool.QueryRow(ctx, "SELECT row_to_json(result) FROM ("+realtimeExpectedEvidenceSQL+") result", nilUUIDValue, start, end, "", "", 0, false).Scan(&diagnostic)
		t.Logf("coverage aggregate=%s query_error=%v", diagnostic, queryErr)
		t.Fatalf("complete two-hour evidence failed: %v", err)
	}
	if _, err = pool.Exec(ctx, `DELETE FROM analytics_realtime_source_windows_184 WHERE ctid=(SELECT ctid FROM analytics_realtime_source_windows_184 LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	if partial, err := reader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter); !realtimeEvidenceHasGap(partial, err) {
		t.Fatalf("missing source became complete: %+v %v", partial, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE analytics_realtime_source_rosters_247 SET captured_at=clock_timestamp()`); err == nil {
		t.Fatal("roster mutation allowed")
	}
}

func assertRealtimeEmptyRosterEvidence(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	reader *PostgresRealtimeExpectedCountReader, filter RealtimeFilter) {
	t.Helper()
	evidence, err := reader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter)
	if err != nil || evidence.CoveredWindows != 2 || evidence.ExpectedEvents != 0 || evidence.AccessSourcesExpected != 0 ||
		evidence.ConnectionSourcesExpected != 0 || !evidence.FinalizedThrough.Equal(filter.To) ||
		!evidence.SourceWatermark.Equal(filter.To) || !validRealtimeExpectedEvidence(evidence, AdminScope(), filter) {
		t.Fatalf("empty roster did not prove zero evidence: %#v %v", evidence, err)
	}
	unfinished := *reader
	unfinished.now = func() time.Time { return filter.To.Add(defaultRealtimeCoverageGrace - time.Second) }
	if partial, err := unfinished.ExpectedRealtimeEvidence(ctx, AdminScope(), filter); !realtimeEvidenceHasGap(partial, err) {
		t.Fatalf("hour inside coverage grace became zero: %+v %v", partial, err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO analytics_access_source_window_contributions_208
		(scope_id,tenant_id,site_id,host,listen_port,window_start,window_end)
		VALUES($1::uuid,$2::uuid,$3::uuid,'late.example.test',443,$4,$5)`,
		uuid.NewString(), uuid.NewString(), uuid.NewString(), filter.From, filter.From.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if partial, err := reader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter); !realtimeEvidenceHasGap(partial, err) {
		t.Fatalf("reported activity without roster became zero: %+v %v", partial, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE analytics_realtime_source_rosters_247 SET captured_at=clock_timestamp()`); err == nil {
		t.Fatal("roster mutation allowed")
	}
}

// An unsettled hour is either rejected or reported as a gap; it never counts
// as covered evidence.
func realtimeEvidenceHasGap(evidence RealtimeExpectedEvidence, err error) bool {
	if err != nil {
		return errors.Is(err, ErrRealtimeEvidenceUnavailable)
	}
	return len(evidence.MissingWindows) > 0 && evidence.CoveredWindows < evidence.RequestedWindows
}
