package analytics

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRealtimeMinutePostgresBoundingCoverage(t *testing.T) {
	dsn := os.Getenv("REALTIME_MINUTE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("REALTIME_MINUTE_TEST_DATABASE_URL is not set; requires an isolated PostgreSQL instance")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "realtime_minute_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := databasetest.CleanupContext()
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `
CREATE TABLE access_scopes(id uuid PRIMARY KEY,tenant_id uuid,kind text);
CREATE TABLE analytics_realtime_source_rosters_247(window_start timestamptz PRIMARY KEY,sources jsonb,evidence_sha256 bytea);
CREATE TABLE analytics_realtime_source_windows_184(
  scope_id uuid,tenant_id uuid,site_id uuid,host text,listen_port integer,window_start timestamptz,
  access_sources_expected bigint,access_sources_finalized bigint,connection_sources_expected bigint,connection_sources_finalized bigint,
  access_finalized_through timestamptz,connection_finalized_through timestamptz,access_source_watermark timestamptz,connection_source_watermark timestamptz);
CREATE TABLE analytics_realtime_expected_counts_131(scope_id uuid,tenant_id uuid,site_id uuid,host text,listen_port integer,hour timestamptz,expected_events bigint);
CREATE TABLE analytics_access_source_window_contributions_208(scope_id uuid,tenant_id uuid,site_id uuid,host text,listen_port integer,window_start timestamptz);
`)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 8, 1, 10, 17, 0, 0, time.UTC)
	filter := RealtimeFilter{From: from, To: from.Add(31 * 24 * time.Hour)}
	coverage := realtimeCoverageFilter(filter)
	_, err = pool.Exec(ctx, `INSERT INTO access_scopes VALUES($1,$1,'tenant'),($2,$2,'tenant')`, rankTenantA, rankTenantB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO analytics_realtime_source_rosters_247
SELECT hour,sources,sha256(convert_to(sources::text,'UTF8')) FROM
(SELECT hour,jsonb_agg(jsonb_build_object('scope_id',id,'tenant_id',tenant_id,'site_id',$3::text,
  'host','cdn.example.test','listen_port',443,'node_id',id,'stable',true)) sources
 FROM generate_series($1::timestamptz,$2::timestamptz-interval '1 hour',interval '1 hour') hour
 CROSS JOIN access_scopes GROUP BY hour) fixtures`, coverage.From, coverage.To, rankSiteA1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO analytics_realtime_source_windows_184
SELECT id,tenant_id,$3::uuid,'cdn.example.test',443,hour,1,1,1,1,
  hour+interval '1 hour',hour+interval '1 hour',hour+interval '1 hour',hour+interval '1 hour'
FROM generate_series($1::timestamptz,$2::timestamptz-interval '1 hour',interval '1 hour') hour CROSS JOIN access_scopes`, coverage.From, coverage.To, rankSiteA1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO analytics_realtime_expected_counts_131
SELECT id,tenant_id,$3::uuid,'cdn.example.test',443,hour,CASE WHEN id=$4::uuid THEN 2 ELSE 3 END
FROM generate_series($1::timestamptz,$2::timestamptz-interval '1 hour',interval '1 hour') hour CROSS JOIN access_scopes`, coverage.From, coverage.To, rankSiteA1, rankTenantA)
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := NewPostgresRealtimeExpectedCountReader(pool)
	for _, scope := range []Scope{AdminScope(), {kind: scopeTenant, tenantID: rankTenantA}} {
		evidence, err := reader.ExpectedRealtimeEvidence(ctx, scope, filter)
		want := uint64(745 * 5)
		if scope.kind == scopeTenant {
			want = 745 * 2
		}
		if err != nil || evidence.ExpectedEvents != want || evidence.RequestedWindows != 745 ||
			!evidence.From.Equal(coverage.From) || !evidence.To.Equal(coverage.To) || !validRealtimeExpectedEvidence(evidence, scope, filter) {
			t.Fatalf("31-day minute offset coverage: %+v %v", evidence, err)
		}
	}
	filter.SiteID, filter.Host, filter.ListenPort = rankSiteA1, "cdn.example.test unused.example.test", 443
	if _, err := reader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter); err != nil {
		t.Fatalf("site/multi-host/port scope: %v", err)
	}
	for _, mutation := range []string{
		`DELETE FROM analytics_realtime_source_rosters_247 WHERE window_start=$1`,
		`UPDATE analytics_realtime_source_windows_184 SET access_sources_finalized=0 WHERE window_start=$1`,
		`UPDATE analytics_realtime_source_windows_184 SET connection_sources_finalized=0 WHERE window_start=$1`,
		`UPDATE analytics_realtime_source_windows_184 SET access_source_watermark=window_start WHERE window_start=$1`,
		`UPDATE analytics_realtime_source_rosters_247 SET evidence_sha256=decode('00','hex') WHERE window_start=$1`,
	} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, mutation, coverage.From); err != nil {
			t.Fatal(err)
		}
		// The unsettled hour is reported as a gap and excluded from the settled
		// aggregate; strict validation never treats it as complete evidence.
		txReader := &PostgresRealtimeExpectedCountReader{queryer: tx}
		partial, err := txReader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter)
		if err != nil || len(partial.MissingWindows) != 1 || !partial.MissingWindows[0].Equal(coverage.From) ||
			partial.CoveredWindows != 744 || !validRealtimeExpectedEvidence(partial, AdminScope(), filter) {
			t.Errorf("partial source gap (%s): %+v %v", mutation, partial, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A rostered hour without a listener for the host is proven empty only
	// when nothing reported activity for that host and the hour has closed.
	filter.Host = "missing.example.test"
	evidence, err := reader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter)
	if err != nil || evidence.ExpectedEvents != 0 || evidence.AccessSourcesExpected != 0 || evidence.ConnectionSourcesExpected != 0 ||
		evidence.CoveredWindows != 745 || !validRealtimeExpectedEvidence(evidence, AdminScope(), filter) {
		t.Fatalf("proven empty host evidence: %+v %v", evidence, err)
	}
	unfinished := &PostgresRealtimeExpectedCountReader{queryer: pool, now: func() time.Time { return coverage.To }}
	if partial, err := unfinished.ExpectedRealtimeEvidence(ctx, AdminScope(), filter); err != nil || len(partial.MissingWindows) != 1 ||
		!partial.MissingWindows[0].Equal(coverage.To.Add(-time.Hour)) {
		t.Fatalf("unfinished empty hour not reported as gap: %+v %v", partial, err)
	}
	for _, activity := range []string{
		`INSERT INTO analytics_access_source_window_contributions_208 VALUES($1,$1,$2::uuid,'missing.example.test',443,$3)`,
		`INSERT INTO analytics_realtime_expected_counts_131 VALUES($1,$1,$2::uuid,'missing.example.test',443,$3,1)`,
	} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, activity, rankTenantA, rankSiteA1, coverage.From.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		txReader := &PostgresRealtimeExpectedCountReader{queryer: tx}
		if partial, err := txReader.ExpectedRealtimeEvidence(ctx, AdminScope(), filter); err != nil || len(partial.MissingWindows) != 1 ||
			!partial.MissingWindows[0].Equal(coverage.From.Add(time.Hour)) {
			t.Errorf("reported activity without listener not a gap (%s): %+v %v", activity, partial, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
