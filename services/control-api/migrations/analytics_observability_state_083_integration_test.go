//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const analyticsObservability083Installation = "installation-analytics-083"

var analyticsObservability083Now = time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)

type analyticsHistorySeed083 struct {
	installationID     string
	natsDomain         string
	streamName         string
	durableName        string
	streamCreated      string
	consumerCreated    string
	historyEpoch       uuid.UUID
	historyStart       string
	legacyBaselineKind string
	legacyBaselineAt   *time.Time
	legacyBaselineSHA  []byte
	brokerConsumer     string
	brokerStream       string
	preparedStream     string
	revision           string
	at                 time.Time
}

func TestAnalyticsObservabilityState083RoundTripAndContracts(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 82)
	seedAnalyticsObservability083Installation(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 83); err != nil {
		t.Fatalf("apply 083: %v", err)
	}
	assertAnalyticsObservability083Head(t, pool, 83)
	assertAnalyticsObservability083Tables(t, pool, true)
	assertPackageCommerceRBAC079Ledger(t, pool, 83)
	assertAnalyticsObservability083ColumnContracts(t, pool)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 83); err != nil {
		t.Fatalf("empty 083 down: %v", err)
	}
	assertAnalyticsObservability083Head(t, pool, 82)
	assertAnalyticsObservability083Tables(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 83); err != nil {
		t.Fatalf("reapply 083: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 83)

	first := validAnalyticsHistorySeed083("ANALYTICS_INGEST_V1", "control_api_analytics_ingest_v1")
	if err := execAnalyticsHistorySeed083(t, pool, first); err != nil {
		t.Fatalf("insert first history generation: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE analytics_history_streams
		SET broker_consumer_ack_floor=2,broker_stream_ack_floor=5,prepared_stream_floor=3,
			revision=2,last_reconciled_at=$2,updated_at=$2
		WHERE history_epoch=$1`, first.historyEpoch, first.at.Add(time.Minute)); err != nil {
		t.Fatalf("advance history generation: %v", err)
	}
	assertAnalyticsHistoryFloors083(t, pool, first.historyEpoch, "2", "5", "3", "3", "2")

	immutableMutations := []string{
		`UPDATE analytics_history_streams SET installation_id='other',revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET nats_domain='other',revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET stream_created_unix_nano=stream_created_unix_nano+1,revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET consumer_created_unix_nano=consumer_created_unix_nano+1,revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET history_start_sequence=2,revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET history_start_at=history_start_at+interval '1 second',revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET legacy_baseline_kind='current_visible_state',legacy_baseline_at=history_start_at,legacy_baseline_sha256=decode(repeat('ab',32),'hex'),revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET created_at=created_at+interval '1 second',revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
	}
	for _, statement := range immutableMutations {
		_, err := pool.Exec(t.Context(), statement, first.historyEpoch)
		assertAnalyticsObservability083Code(t, err, "P8301")
	}
	_, err := pool.Exec(t.Context(), `DELETE FROM analytics_history_streams WHERE history_epoch=$1`, first.historyEpoch)
	assertAnalyticsObservability083Code(t, err, "P8302")
	_, err = pool.Exec(t.Context(), `TRUNCATE analytics_history_streams`)
	assertAnalyticsObservability083Code(t, err, "P8302")

	overlap := validAnalyticsHistorySeed083(first.streamName, first.durableName)
	overlap.streamCreated = "1785283200000000100"
	overlap.consumerCreated = "1785283200000000200"
	assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool, overlap), "P8301")

	retiredAt := first.at.Add(2 * time.Minute)
	if _, err := pool.Exec(t.Context(), `UPDATE analytics_history_streams
		SET retired_at=$2,revision=3,last_reconciled_at=$2,updated_at=$2
		WHERE history_epoch=$1`, first.historyEpoch, retiredAt); err != nil {
		t.Fatalf("retire first generation: %v", err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE analytics_history_streams
		SET revision=4,updated_at=$2 WHERE history_epoch=$1`, first.historyEpoch, retiredAt.Add(time.Minute))
	assertAnalyticsObservability083Code(t, err, "P8301")

	sameGeneration := overlap
	sameGeneration.historyEpoch = uuid.New()
	sameGeneration.streamCreated = first.streamCreated
	sameGeneration.consumerCreated = first.consumerCreated
	assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool, sameGeneration), "P8301")
	reusedEpoch := overlap
	reusedEpoch.historyEpoch = first.historyEpoch
	reusedEpoch.at = retiredAt.Add(time.Minute)
	assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool, reusedEpoch), "23505")

	recreated := overlap
	recreated.at = retiredAt.Add(time.Minute)
	recreated.historyStart = "4"
	recreated.brokerStream = "3"
	recreated.preparedStream = "3"
	recreated.legacyBaselineKind = "current_visible_state"
	baselineAt := recreated.at.Add(-time.Minute)
	recreated.legacyBaselineAt = &baselineAt
	recreated.legacyBaselineSHA = make([]byte, 32)
	if err := execAnalyticsHistorySeed083(t, pool, recreated); err != nil {
		t.Fatalf("insert recreated consumer generation: %v", err)
	}
	assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool,
		validAnalyticsHistorySeed083(first.streamName, first.durableName)), "P8301")

	assertAnalyticsObservability083Code(t, migrateVersionIsolated(t.Context(), pool, "down", 83), "P8309")
	assertAnalyticsObservability083Head(t, pool, 83)
	assertAnalyticsObservability083Tables(t, pool, true)
	var facts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM analytics_history_streams`).Scan(&facts); err != nil || facts != 2 {
		t.Fatalf("facts after failed down = %d, want 2, err=%v", facts, err)
	}
}

func TestAnalyticsObservabilityState083ConcurrentMonotonicFloors(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 82)
	seedAnalyticsObservability083Installation(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 83); err != nil {
		t.Fatal(err)
	}
	seed := validAnalyticsHistorySeed083("ANALYTICS_INGEST_V1", "control_api_analytics_ingest_v1")
	if err := execAnalyticsHistorySeed083(t, pool, seed); err != nil {
		t.Fatal(err)
	}

	tx1, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback(t.Context())
	tx2, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback(t.Context())
	var tx1PID, tx2PID int32
	if err := tx1.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&tx1PID); err != nil {
		t.Fatal(err)
	}
	if err := tx2.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&tx2PID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx1.Exec(t.Context(), `UPDATE analytics_history_streams
		SET broker_consumer_ack_floor=7,broker_stream_ack_floor=10,prepared_stream_floor=8,
			revision=2,last_reconciled_at=$2,updated_at=$2 WHERE history_epoch=$1`,
		seed.historyEpoch, seed.at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	secondResult := make(chan error, 1)
	secondEntered := make(chan struct{})
	go func() {
		close(secondEntered)
		_, updateErr := tx2.Exec(t.Context(), `UPDATE analytics_history_streams
			SET broker_consumer_ack_floor=8,broker_stream_ack_floor=12,prepared_stream_floor=9,
				revision=2,last_reconciled_at=$2,updated_at=$2 WHERE history_epoch=$1`,
			seed.historyEpoch, seed.at.Add(2*time.Minute))
		secondResult <- updateErr
	}()
	<-secondEntered
	waitForAnalyticsObservability083Blocker(t, pool, tx2PID, tx1PID)
	if err := tx1.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	resultContext, cancelResult := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelResult()
	select {
	case err := <-secondResult:
		assertAnalyticsObservability083Code(t, err, "P8301")
	case <-resultContext.Done():
		t.Fatal("second writer remained blocked after first commit")
	}
	_ = tx2.Rollback(t.Context())
	assertAnalyticsHistoryFloors083(t, pool, seed.historyEpoch, "7", "10", "8", "8", "2")

	invalidUpdates := []string{
		`UPDATE analytics_history_streams SET revision=1,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET revision=2,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET revision=4,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET broker_stream_ack_floor=9,revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET prepared_stream_floor=7,revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET broker_consumer_ack_floor=6,revision=3,updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
		`UPDATE analytics_history_streams SET revision=3,last_reconciled_at=last_reconciled_at-interval '1 second',updated_at=updated_at+interval '1 minute' WHERE history_epoch=$1`,
	}
	for _, statement := range invalidUpdates {
		_, err := pool.Exec(t.Context(), statement, seed.historyEpoch)
		assertAnalyticsObservability083Code(t, err, "P8301")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE analytics_history_streams
		SET broker_consumer_ack_floor=8,broker_stream_ack_floor=15,prepared_stream_floor=11,
			revision=3,last_reconciled_at=$2,updated_at=$2 WHERE history_epoch=$1`,
		seed.historyEpoch, seed.at.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertAnalyticsHistoryFloors083(t, pool, seed.historyEpoch, "8", "15", "11", "11", "3")
}

func TestAnalyticsObservabilityState083IdentifiersBaselinesAndUInt64(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 82)
	seedAnalyticsObservability083Installation(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 83); err != nil {
		t.Fatal(err)
	}

	validProduction := validAnalyticsHistorySeed083("ANALYTICS_INGEST_V1", "control_api_analytics_ingest_v1")
	if err := execAnalyticsHistorySeed083(t, pool, validProduction); err != nil {
		t.Fatalf("production NATS names rejected: %v", err)
	}
	validAlternate := validAnalyticsHistorySeed083("OBS-ANALYTICS_01", "obs_analytics-01")
	validAlternate.natsDomain = "PROD_EU-1"
	validAlternate.streamCreated = "1785283200000000100"
	validAlternate.consumerCreated = "1785283200000000200"
	if err := execAnalyticsHistorySeed083(t, pool, validAlternate); err != nil {
		t.Fatalf("valid NATS names rejected: %v", err)
	}
	equalCreation := validAnalyticsHistorySeed083("CREATION_EQUAL", "durable")
	equalCreation.streamCreated = "1785283200000000300"
	equalCreation.consumerCreated = equalCreation.streamCreated
	if err := execAnalyticsHistorySeed083(t, pool, equalCreation); err != nil {
		t.Fatalf("equal stream and consumer creation identity rejected: %v", err)
	}
	greaterCreation := validAnalyticsHistorySeed083("CREATION_GREATER", "durable")
	greaterCreation.streamCreated = "1785283200000000400"
	greaterCreation.consumerCreated = "1785283200000000401"
	if err := execAnalyticsHistorySeed083(t, pool, greaterCreation); err != nil {
		t.Fatalf("valid greater consumer creation identity rejected: %v", err)
	}
	lessCreation := validAnalyticsHistorySeed083("CREATION_LESS", "durable")
	lessCreation.streamCreated = "1785283200000000500"
	lessCreation.consumerCreated = "1785283200000000499"
	assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool, lessCreation), "23514")

	invalidNames := []struct {
		domain  string
		stream  string
		durable string
	}{
		{"", "", "durable"},
		{"", "ANALYTICS.INGEST", "durable"},
		{"", "ANALYTICS*", "durable"},
		{"", "ANALYTICS>", "durable"},
		{"", "ANALYTICS/INGEST", "durable"},
		{"", "ANALYTICS\\INGEST", "durable"},
		{"", " ANALYTICS", "durable"},
		{"", "ANALYTICS\nINGEST", "durable"},
		{"", "valid_stream", ""},
		{"", "valid_stream", "bad/durable"},
		{"prod.us", "valid_stream", "durable"},
		{"prod*", "valid_stream", "durable"},
	}
	for _, testCase := range invalidNames {
		seed := validAnalyticsHistorySeed083(testCase.stream, testCase.durable)
		seed.natsDomain = testCase.domain
		assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool, seed), "23514")
	}

	missingInstallation := validAnalyticsHistorySeed083("MISSING_INSTALLATION", "durable")
	missingInstallation.installationID = "missing-installation"
	assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool, missingInstallation), "23503")

	baselineCases := []analyticsHistorySeed083{
		func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("BASELINE_NONE_SKIP", "durable")
			seed.historyStart, seed.brokerStream, seed.preparedStream = "2", "1", "1"
			return seed
		}(),
		func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("BASELINE_MISSING_DIGEST", "durable")
			seed.legacyBaselineKind = "current_visible_state"
			at := seed.at.Add(-time.Minute)
			seed.legacyBaselineAt = &at
			return seed
		}(),
		func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("BASELINE_SHORT_DIGEST", "durable")
			seed.legacyBaselineKind = "current_visible_state"
			at := seed.at.Add(-time.Minute)
			seed.legacyBaselineAt, seed.legacyBaselineSHA = &at, make([]byte, 31)
			return seed
		}(),
		func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("BASELINE_AFTER_START", "durable")
			seed.legacyBaselineKind = "current_visible_state"
			at := seed.at.Add(time.Minute)
			seed.legacyBaselineAt, seed.legacyBaselineSHA = &at, make([]byte, 32)
			return seed
		}(),
	}
	for _, seed := range baselineCases {
		assertAnalyticsObservability083Code(t, execAnalyticsHistorySeed083(t, pool, seed), "23514")
	}

	maximum := validAnalyticsHistorySeed083("UINT64_MAX", "durable")
	maximum.historyStart = "18446744073709551615"
	maximum.brokerConsumer = "18446744073709551614"
	maximum.brokerStream = "18446744073709551614"
	maximum.preparedStream = "18446744073709551614"
	maximum.legacyBaselineKind = "current_visible_state"
	baselineAt := maximum.at.Add(-time.Minute)
	maximum.legacyBaselineAt, maximum.legacyBaselineSHA = &baselineAt, make([]byte, 32)
	if err := execAnalyticsHistorySeed083(t, pool, maximum); err != nil {
		t.Fatalf("insert UInt64 maximum boundary: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE analytics_history_streams SET
		broker_consumer_ack_floor=18446744073709551615,
		broker_stream_ack_floor=18446744073709551615,
		prepared_stream_floor=18446744073709551615,
		revision=2,last_reconciled_at=$2,updated_at=$2 WHERE history_epoch=$1`,
		maximum.historyEpoch, maximum.at.Add(time.Minute)); err != nil {
		t.Fatalf("advance UInt64 maximum boundary: %v", err)
	}
	assertAnalyticsHistoryFloors083(t, pool, maximum.historyEpoch,
		"18446744073709551615", "18446744073709551615", "18446744073709551615",
		"18446744073709551615", "2")

	invalidNumbers := []struct {
		seed analyticsHistorySeed083
		code string
	}{
		{func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("UINT64_ZERO_START", "durable")
			seed.historyStart = "0"
			return seed
		}(), "P8301"},
		{func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("UINT64_OVERFLOW_START", "durable")
			seed.historyStart = "18446744073709551616"
			return seed
		}(), "P8301"},
		{func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("UINT64_NEGATIVE", "durable")
			seed.brokerConsumer = "-1"
			return seed
		}(), "23514"},
		{func() analyticsHistorySeed083 {
			seed := validAnalyticsHistorySeed083("UINT64_OVERFLOW_FLOOR", "durable")
			seed.brokerConsumer = "18446744073709551616"
			return seed
		}(), "23514"},
	}
	for _, testCase := range invalidNumbers {
		assertAnalyticsObservability083Code(t,
			execAnalyticsHistorySeed083(t, pool, testCase.seed), testCase.code)
	}
}

func TestAnalyticsObservabilityState083LedgerHeadFailClosed(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 82)
	if _, err := pool.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=42`); err != nil {
		t.Fatal(err)
	}
	script, err := controlmigrations.FS.ReadFile("083_analytics_observability_state.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), string(script), pgx.QueryExecModeSimpleProtocol)
	assertAnalyticsObservability083Code(t, err, "P8300")
	assertAnalyticsObservability083Tables(t, pool, false)
}

func validAnalyticsHistorySeed083(streamName, durableName string) analyticsHistorySeed083 {
	return analyticsHistorySeed083{
		installationID:     analyticsObservability083Installation,
		streamName:         streamName,
		durableName:        durableName,
		streamCreated:      "1785283200000000000",
		consumerCreated:    "1785283200000000001",
		historyEpoch:       uuid.New(),
		historyStart:       "1",
		legacyBaselineKind: "none",
		brokerConsumer:     "0",
		brokerStream:       "0",
		preparedStream:     "0",
		revision:           "1",
		at:                 analyticsObservability083Now,
	}
}

func execAnalyticsHistorySeed083(t *testing.T, pool *pgxpool.Pool, seed analyticsHistorySeed083) error {
	t.Helper()
	_, err := pool.Exec(t.Context(), `INSERT INTO analytics_history_streams(
		installation_id,nats_domain,stream_name,durable_name,
		stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
		history_start_sequence,history_start_at,
		legacy_baseline_kind,legacy_baseline_at,legacy_baseline_sha256,
		broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,
		revision,last_reconciled_at,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$9,$9,$9)`,
		seed.installationID, seed.natsDomain, seed.streamName, seed.durableName,
		seed.streamCreated, seed.consumerCreated, seed.historyEpoch, seed.historyStart, seed.at,
		seed.legacyBaselineKind, seed.legacyBaselineAt, seed.legacyBaselineSHA,
		seed.brokerConsumer, seed.brokerStream, seed.preparedStream, seed.revision)
	return err
}

func seedAnalyticsObservability083Installation(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_installation_entitlement(
		singleton,installation_id,last_status,created_at,updated_at
	) VALUES(true,$1,'uninstalled',$2,$2)`, analyticsObservability083Installation, analyticsObservability083Now); err != nil {
		t.Fatal(err)
	}
}

func assertAnalyticsHistoryFloors083(t *testing.T, pool *pgxpool.Pool, epoch uuid.UUID,
	brokerConsumer, brokerStream, prepared, committed, revision string,
) {
	t.Helper()
	var gotConsumer, gotBroker, gotPrepared, gotCommitted, gotRevision string
	if err := pool.QueryRow(t.Context(), `SELECT broker_consumer_ack_floor::text,
		broker_stream_ack_floor::text,prepared_stream_floor::text,
		committed_stream_ack_floor::text,revision::text
		FROM analytics_history_streams WHERE history_epoch=$1`, epoch).Scan(
		&gotConsumer, &gotBroker, &gotPrepared, &gotCommitted, &gotRevision,
	); err != nil {
		t.Fatal(err)
	}
	if gotConsumer != brokerConsumer || gotBroker != brokerStream || gotPrepared != prepared ||
		gotCommitted != committed || gotRevision != revision {
		t.Fatalf("history floors/revision = %s/%s/%s/%s/%s, want %s/%s/%s/%s/%s",
			gotConsumer, gotBroker, gotPrepared, gotCommitted, gotRevision,
			brokerConsumer, brokerStream, prepared, committed, revision)
	}
}

func assertAnalyticsObservability083Tables(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var streamTable, exportTable bool
	if err := pool.QueryRow(t.Context(), `SELECT
		to_regclass('analytics_history_streams') IS NOT NULL,
		to_regclass('analytics_log_export_artifacts') IS NOT NULL`).Scan(&streamTable, &exportTable); err != nil {
		t.Fatal(err)
	}
	if streamTable != want || exportTable {
		t.Fatalf("analytics tables stream/export=%t/%t, want %t/false", streamTable, exportTable, want)
	}
}

func waitForAnalyticsObservability083Blocker(t *testing.T, pool *pgxpool.Pool, blockedPID, blockingPID int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT $2 = ANY(pg_blocking_pids($1))`, blockedPID, blockingPID).Scan(&blocked); err != nil {
			t.Fatalf("observe concurrent analytics writer lock: %v", err)
		}
		if blocked {
			return
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("second analytics writer never blocked on the first: %v", err)
		}
	}
}

func assertAnalyticsObservability083ColumnContracts(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var numericColumns int
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='analytics_history_streams'
		  AND data_type='numeric' AND numeric_precision=20 AND numeric_scale=0`).Scan(&numericColumns); err != nil {
		t.Fatal(err)
	}
	if numericColumns != 8 {
		t.Fatalf("UInt64/exact identity NUMERIC(20,0) columns = %d, want 8", numericColumns)
	}
	var generated, expression string
	if err := pool.QueryRow(t.Context(), `SELECT is_generated,generation_expression
		FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='analytics_history_streams'
		  AND column_name='committed_stream_ack_floor'`).Scan(&generated, &expression); err != nil {
		t.Fatal(err)
	}
	if generated != "ALWAYS" || expression == "" {
		t.Fatalf("committed floor generated=%q expression=%q", generated, expression)
	}
	var installationFK, activeIdentityIndex, forbiddenColumns int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM information_schema.referential_constraints
		 WHERE constraint_schema=current_schema()
		   AND constraint_name='analytics_history_streams_installation_id_fkey'),
		(SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema()
		   AND indexname='analytics_history_streams_one_active_identity_idx'),
		(SELECT count(*) FROM information_schema.columns
		 WHERE table_schema=current_schema() AND table_name='analytics_history_streams'
		   AND column_name IN ('event_id','message_id','payload','request_headers','response_headers',
			'request_body','response_body','stream_sequence','event_ordinal'))`).Scan(
		&installationFK, &activeIdentityIndex, &forbiddenColumns); err != nil {
		t.Fatal(err)
	}
	if installationFK != 1 || activeIdentityIndex != 1 || forbiddenColumns != 0 {
		t.Fatalf("installation FK/active index/forbidden columns=%d/%d/%d, want 1/1/0",
			installationFK, activeIdentityIndex, forbiddenColumns)
	}
}

func assertAnalyticsObservability083Head(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration head = %d, want %d", got, want)
	}
}

func assertAnalyticsObservability083Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error = %v, want code %s", err, want)
	}
}
