//go:build integration

package migrations_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAnalyticsIngestHistoryAuthority098Contract(t *testing.T) {
	up := mustReadAnalyticsIngestHistoryAuthority098(t,
		"098_analytics_ingest_history_authority.up.sql")
	down := mustReadAnalyticsIngestHistoryAuthority098(t,
		"098_analytics_ingest_history_authority.down.sql")
	for _, fragment := range []string{
		"migration 098 requires the exact verified 097 release head",
		"38e154e329fb72b2664c84b777fbe63b9ba299e1a73397e7f7fddbc9a7bddd11",
		"2a741f9196025c13982a0cba09091e6dc70f2903d374caae3593e178c14b6552",
		"ERRCODE = 'P9800'",
		"CREATE TABLE analytics_ingest_receipts",
		"CREATE TABLE analytics_history_recoveries",
		"FOREIGN KEY (history_epoch)",
		"REFERENCES analytics_history_streams(history_epoch) ON DELETE RESTRICT",
		"PRIMARY KEY (history_epoch,stream_sequence)",
		"UNIQUE (clickhouse_token)",
		"CREATE UNIQUE INDEX analytics_history_recoveries_one_active_098_idx",
		"WHERE completed_at IS NULL",
		"state IN ('received','prepared','broker_ack_observed')",
		"analytics-history-v1-",
		"CREATE FUNCTION analytics_ingest_mark_prepared_098",
		"CREATE FUNCTION analytics_ingest_mark_broker_ack_observed_098",
		"CREATE FUNCTION analytics_history_schedule_recovery_098",
		"CREATE FUNCTION analytics_history_claim_recovery_098",
		"CREATE FUNCTION analytics_history_reconcile_recovery_098",
		"CREATE FUNCTION analytics_history_complete_recovery_098",
		"BEFORE DELETE ON analytics_ingest_receipts",
		"BEFORE DELETE ON analytics_history_recoveries",
		"BEFORE TRUNCATE ON analytics_ingest_receipts",
		"BEFORE TRUNCATE ON analytics_history_recoveries",
		"ERRCODE = 'P9802'",
		"ERRCODE = 'P9803'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("098 up missing %q", fragment)
		}
	}
	upDigest := sha256.Sum256([]byte(up))
	for _, fragment := range []string{
		"migration 098 rollback requires the exact verified 098 head",
		hex.EncodeToString(upDigest[:]),
		"38e154e329fb72b2664c84b777fbe63b9ba299e1a73397e7f7fddbc9a7bddd11",
		"2a741f9196025c13982a0cba09091e6dc70f2903d374caae3593e178c14b6552",
		"migration 098 rollback would discard analytics ingest history facts",
		"ERRCODE = 'P9801'",
		"DROP TABLE analytics_history_recoveries",
		"DROP TABLE analytics_ingest_receipts",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("098 down missing %q", fragment)
		}
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("098 down must not delete its own schema_migrations row")
	}
}

func TestAnalyticsIngestHistoryAuthority098FreshRoundTripAndHeadGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 97)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 98); err != nil {
		t.Fatalf("fresh 1..98: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 98)
	assertAnalyticsIngestHistoryAuthority098Schema(t, pool, true)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 98); err != nil {
		t.Fatalf("empty 098 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 97)
	assertAnalyticsIngestHistoryAuthority098Schema(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 98); err != nil {
		t.Fatalf("97 -> 98 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 98)

	t.Run("missing historical migration", func(t *testing.T) {
		candidate := packageCommerceRBAC079Pool(t, 97)
		if _, err := candidate.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=42`); err != nil {
			t.Fatal(err)
		}
		_, err := candidate.Exec(t.Context(), mustReadAnalyticsIngestHistoryAuthority098(t,
			"098_analytics_ingest_history_authority.up.sql"))
		assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9800")
	})
	t.Run("tampered 097 parent", func(t *testing.T) {
		candidate := packageCommerceRBAC079Pool(t, 97)
		if _, err := candidate.Exec(t.Context(), `UPDATE schema_migrations
			SET checksum_sha256=repeat('a',64) WHERE version=97`); err != nil {
			t.Fatal(err)
		}
		_, err := candidate.Exec(t.Context(), mustReadAnalyticsIngestHistoryAuthority098(t,
			"098_analytics_ingest_history_authority.up.sql"))
		assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9800")
	})
	t.Run("tampered 098 rollback head", func(t *testing.T) {
		candidate := packageCommerceRBAC079Pool(t, 98)
		if _, err := candidate.Exec(t.Context(), `UPDATE schema_migrations
			SET down_checksum_sha256=repeat('b',64) WHERE version=98`); err != nil {
			t.Fatal(err)
		}
		err := migrateVersionIsolated(t.Context(), candidate, "down", 98)
		if err == nil || !strings.Contains(err.Error(), "migration 98 down checksum mismatch") {
			t.Fatalf("down with tampered 098 checksum error = %v, want checksum mismatch", err)
		}
	})
}

func TestAnalyticsIngestHistoryAuthority098ReceiptProgressAndAtomicPreparation(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	generation := seedAnalyticsIngestHistoryGeneration098(t, pool)
	belowStart := insertAnalyticsIngestReceipt098Value098(generation.historyEpoch, 40, 40)
	err := execAnalyticsIngestReceipt098(t, pool, belowStart, 40)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")
	receipt := insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 41, 1)

	_, err = pool.Exec(t.Context(), `SELECT analytics_ingest_mark_prepared_098($1,$2,$3,$4)`,
		receipt.epoch, receipt.sequence, digest098(99), generation.at.Add(time.Minute))
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")
	assertAnalyticsIngestReceiptAndFloor098(t, pool, receipt, "received", "40", "1")

	_, err = pool.Exec(t.Context(), `SELECT analytics_ingest_mark_prepared_098($1,$2,$3,$4)`,
		receipt.epoch, 42, receipt.identity, generation.at.Add(time.Minute))
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")
	assertAnalyticsIngestReceiptAndFloor098(t, pool, receipt, "received", "40", "1")

	if _, err := pool.Exec(t.Context(), `SELECT analytics_ingest_mark_prepared_098($1,$2,$3,$4)`,
		receipt.epoch, receipt.sequence, receipt.identity, generation.at.Add(time.Minute)); err != nil {
		t.Fatalf("mark prepared: %v", err)
	}
	assertAnalyticsIngestReceiptAndFloor098(t, pool, receipt, "prepared", "41", "2")
	if _, err := pool.Exec(t.Context(), `SELECT analytics_ingest_mark_prepared_098($1,$2,$3,$4)`,
		receipt.epoch, receipt.sequence, receipt.identity, generation.at.Add(time.Minute)); err != nil {
		t.Fatalf("idempotent mark prepared: %v", err)
	}
	assertAnalyticsIngestReceiptAndFloor098(t, pool, receipt, "prepared", "41", "2")

	gap := insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 43, 3)
	_, err = pool.Exec(t.Context(), `SELECT analytics_ingest_mark_prepared_098($1,$2,$3,$4)`,
		gap.epoch, gap.sequence, gap.identity, generation.at.Add(2*time.Minute))
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")
	assertAnalyticsIngestReceiptAndFloor098(t, pool, gap, "received", "41", "2")

	if _, err := pool.Exec(t.Context(), `SELECT analytics_ingest_mark_broker_ack_observed_098($1,$2,$3,$4)`,
		receipt.epoch, receipt.sequence, receipt.identity, generation.at.Add(2*time.Minute)); err != nil {
		t.Fatalf("mark broker ACK observed: %v", err)
	}
	assertAnalyticsIngestReceiptAndFloor098(t, pool, receipt, "broker_ack_observed", "41", "2")

	for name, statement := range map[string]string{
		"identity digest": `UPDATE analytics_ingest_receipts SET receipt_identity_sha256=$3
			WHERE history_epoch=$1 AND stream_sequence=$2`,
		"generation digest": `UPDATE analytics_ingest_receipts SET generation_sha256=$3
			WHERE history_epoch=$1 AND stream_sequence=$2`,
		"ClickHouse token": `UPDATE analytics_ingest_receipts SET clickhouse_token=clickhouse_token||'0'
			WHERE history_epoch=$1 AND stream_sequence=$2`,
		"state regression": `UPDATE analytics_ingest_receipts SET state='received',prepared_at=NULL,
			broker_ack_observed_at=NULL,updated_at=updated_at+interval '1 second'
			WHERE history_epoch=$1 AND stream_sequence=$2`,
	} {
		t.Run(name, func(t *testing.T) {
			args := []any{receipt.epoch, receipt.sequence}
			if strings.Contains(statement, "$3") {
				args = append(args, digest098(88))
			}
			_, mutationErr := pool.Exec(t.Context(), statement, args...)
			assertAnalyticsIngestHistoryAuthority098Code(t, mutationErr, "P9802")
		})
	}
	_, err = pool.Exec(t.Context(), `DELETE FROM analytics_ingest_receipts
		WHERE history_epoch=$1 AND stream_sequence=$2`, receipt.epoch, receipt.sequence)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9802")
	// Later migrations (131, 208) reference receipts by foreign key; without CASCADE the FK
	// check rejects TRUNCATE (0A000) before the 098 truncate guard runs.
	_, err = pool.Exec(t.Context(), `TRUNCATE analytics_ingest_receipts CASCADE`)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9802")

	duplicateToken := analyticsIngestReceipt098{
		epoch: generation.historyEpoch, sequence: 42, identity: digest098(42), token: receipt.token,
	}
	err = execAnalyticsIngestReceipt098(t, pool, duplicateToken, 42)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "23505")

	missingGeneration := insertAnalyticsIngestReceipt098Value098(uuid.New(), 41, 41)
	err = execAnalyticsIngestReceipt098(t, pool, missingGeneration, 41)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "23503")
}

func TestAnalyticsIngestHistoryAuthority098RecoveryClaimTakeoverAndCompletionFence(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	generation := seedAnalyticsIngestHistoryGeneration098(t, pool)
	receipt := insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 41, 1)
	now := generation.at.Add(time.Minute)
	if _, err := pool.Exec(t.Context(), `SELECT analytics_ingest_mark_prepared_098($1,$2,$3,$4)`,
		receipt.epoch, receipt.sequence, receipt.identity, now); err != nil {
		t.Fatal(err)
	}

	firstRecovery := scheduleAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch, now)
	replayedRecovery := scheduleAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch, now)
	if replayedRecovery != firstRecovery {
		t.Fatalf("scheduled recovery replay = %s, want %s", replayedRecovery, firstRecovery)
	}
	assertAnalyticsHistoryRecoveryCount098(t, pool, generation.historyEpoch, 1, 1)
	_, err := pool.Exec(t.Context(), `SELECT analytics_history_claim_recovery_098($1,$2,$3,$4,$5)`,
		generation.historyEpoch, "worker-invalid-token", uuid.Nil, now, now.Add(time.Minute))
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")
	_, err = pool.Exec(t.Context(), `SELECT analytics_history_claim_recovery_098($1,$2,$3,$4,$5)`,
		generation.historyEpoch, "worker-invalid-lease", uuid.New(), now, now)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")

	firstToken := uuid.New()
	claimed, ok := claimAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch,
		"worker-first", firstToken, now, now.Add(time.Minute))
	if !ok || claimed != firstRecovery {
		t.Fatalf("first claim = (%s,%t), want (%s,true)", claimed, ok, firstRecovery)
	}
	_, err = pool.Exec(t.Context(), `SELECT analytics_history_complete_recovery_098($1,$2,$3)`,
		firstRecovery, firstToken, now.Add(10*time.Second))
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")

	if competing, competingOK := claimAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch,
		"worker-live-competitor", uuid.New(), now.Add(30*time.Second), now.Add(90*time.Second)); competingOK {
		t.Fatalf("live lease competitor claimed recovery %s", competing)
	}
	_, err = pool.Exec(t.Context(),
		`SELECT analytics_history_reconcile_recovery_098($1,$2,$3,$4,$5)`,
		firstRecovery, firstToken, 1, 41, now.Add(time.Minute))
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")
	assertAnalyticsHistoryBrokerFloor098(t, pool, generation.historyEpoch, "0", "40", "41", "2")

	secondToken := uuid.New()
	takeoverAt := now.Add(2 * time.Minute)
	takenOver, ok := claimAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch,
		"worker-takeover", secondToken, takeoverAt, takeoverAt.Add(time.Minute))
	if !ok || takenOver != firstRecovery {
		t.Fatalf("expired lease takeover = (%s,%t), want (%s,true)", takenOver, ok, firstRecovery)
	}
	for name, claim := range map[string]struct {
		id    uuid.UUID
		token uuid.UUID
	}{
		"old token":         {id: firstRecovery, token: firstToken},
		"wrong recovery ID": {id: uuid.New(), token: secondToken},
	} {
		t.Run(name, func(t *testing.T) {
			_, reconcileErr := pool.Exec(t.Context(),
				`SELECT analytics_history_reconcile_recovery_098($1,$2,$3,$4,$5)`,
				claim.id, claim.token, 1, 41, takeoverAt.Add(10*time.Second))
			assertAnalyticsIngestHistoryAuthority098Code(t, reconcileErr, "P9803")
		})
	}
	assertAnalyticsHistoryBrokerFloor098(t, pool, generation.historyEpoch, "0", "40", "41", "2")

	if _, err := pool.Exec(t.Context(),
		`SELECT analytics_history_reconcile_recovery_098($1,$2,$3,$4,$5)`,
		firstRecovery, secondToken, 1, 41, takeoverAt.Add(10*time.Second)); err != nil {
		t.Fatalf("reconcile recovery: %v", err)
	}
	assertAnalyticsHistoryBrokerFloor098(t, pool, generation.historyEpoch, "1", "41", "41", "3")
	_, err = pool.Exec(t.Context(), `SELECT analytics_history_complete_recovery_098($1,$2,$3)`,
		firstRecovery, firstToken, takeoverAt.Add(20*time.Second))
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9803")
	if _, err := pool.Exec(t.Context(), `SELECT analytics_history_complete_recovery_098($1,$2,$3)`,
		firstRecovery, secondToken, takeoverAt.Add(20*time.Second)); err != nil {
		t.Fatalf("complete recovered generation: %v", err)
	}
	assertAnalyticsHistoryRecoveryCount098(t, pool, generation.historyEpoch, 1, 0)

	secondRecovery := scheduleAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch,
		takeoverAt.Add(30*time.Second))
	if secondRecovery == firstRecovery {
		t.Fatalf("new schedule reused completed recovery %s", firstRecovery)
	}
	assertAnalyticsHistoryRecoveryCount098(t, pool, generation.historyEpoch, 2, 1)
	_, err = pool.Exec(t.Context(), `UPDATE analytics_history_recoveries
		SET reason='forged_reason' WHERE recovery_id=$1`, firstRecovery)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9802")
	_, err = pool.Exec(t.Context(), `DELETE FROM analytics_history_recoveries WHERE recovery_id=$1`, firstRecovery)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9802")
	_, err = pool.Exec(t.Context(), `TRUNCATE analytics_history_recoveries`)
	assertAnalyticsIngestHistoryAuthority098Code(t, err, "P9802")
}

func TestAnalyticsIngestHistoryAuthority098ConcurrentRecoveryClaimHasOneWinner(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	generation := seedAnalyticsIngestHistoryGeneration098(t, pool)
	now := generation.at.Add(time.Minute)
	recoveryID := scheduleAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch, now)

	type result struct {
		id uuid.UUID
		ok bool
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for index := range 2 {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			id, ok := claimAnalyticsHistoryRecovery098(t, pool, generation.historyEpoch,
				"concurrent-worker-"+string(rune('a'+index)), uuid.New(), now, now.Add(time.Minute))
			results <- result{id: id, ok: ok}
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	winners := 0
	for claim := range results {
		if claim.ok {
			winners++
			if claim.id != recoveryID {
				t.Fatalf("claimed recovery = %s, want %s", claim.id, recoveryID)
			}
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent recovery claim winners = %d, want 1", winners)
	}
}

type analyticsIngestReceipt098 struct {
	epoch    uuid.UUID
	sequence uint64
	identity []byte
	token    string
}

func seedAnalyticsIngestHistoryGeneration098(t *testing.T, pool *pgxpool.Pool) analyticsHistorySeed083 {
	t.Helper()
	seedAnalyticsObservability083Installation(t, pool)
	generation := validAnalyticsHistorySeed083("ANALYTICS_INGEST_V1", "control_api_analytics_ingest_v1")
	generation.historyStart = "41"
	generation.brokerConsumer = "0"
	generation.brokerStream = "40"
	generation.preparedStream = "40"
	// 083 only allows history_start_sequence > 1 with a current_visible_state baseline.
	generation.legacyBaselineKind = "current_visible_state"
	baselineAt := generation.at.Add(-time.Minute)
	generation.legacyBaselineAt, generation.legacyBaselineSHA = &baselineAt, make([]byte, 32)
	if err := execAnalyticsHistorySeed083(t, pool, generation); err != nil {
		t.Fatalf("seed analytics history generation: %v", err)
	}
	return generation
}

func insertAnalyticsIngestReceipt098(
	t *testing.T,
	pool *pgxpool.Pool,
	epoch uuid.UUID,
	sequence uint64,
	marker byte,
) analyticsIngestReceipt098 {
	t.Helper()
	receipt := insertAnalyticsIngestReceipt098Value098(epoch, sequence, marker)
	if err := execAnalyticsIngestReceipt098(t, pool, receipt, marker); err != nil {
		t.Fatalf("insert receipt %d: %v", sequence, err)
	}
	return receipt
}

func insertAnalyticsIngestReceipt098Value098(
	epoch uuid.UUID,
	sequence uint64,
	marker byte,
) analyticsIngestReceipt098 {
	return analyticsIngestReceipt098{
		epoch: epoch, sequence: sequence, identity: digest098(marker),
		token: "analytics-history-v1-" + hex.EncodeToString(digest098(marker+10)),
	}
}

func execAnalyticsIngestReceipt098(
	t *testing.T,
	pool *pgxpool.Pool,
	receipt analyticsIngestReceipt098,
	marker byte,
) error {
	t.Helper()
	at := analyticsObservability083Now.Add(time.Duration(receipt.sequence) * time.Second)
	_, err := pool.Exec(t.Context(), `INSERT INTO analytics_ingest_receipts(
		history_epoch,stream_sequence,receipt_identity_sha256,generation_sha256,message_id,
		payload_sha256,canonical_event_sha256,clickhouse_token,state,received_at,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'received',$9,$9,$9)`,
		receipt.epoch, receipt.sequence, receipt.identity, digest098(marker+1),
		"analytics-message-"+hex.EncodeToString([]byte{marker}), digest098(marker+2),
		digest098(marker+3), receipt.token, at)
	return err
}

func scheduleAnalyticsHistoryRecovery098(
	t *testing.T,
	pool *pgxpool.Pool,
	epoch uuid.UUID,
	at time.Time,
) uuid.UUID {
	t.Helper()
	var recoveryID uuid.UUID
	if err := pool.QueryRow(t.Context(),
		`SELECT analytics_history_schedule_recovery_098($1,'broker_reconcile_required',$2)`,
		epoch, at).Scan(&recoveryID); err != nil {
		t.Fatalf("schedule recovery: %v", err)
	}
	return recoveryID
}

func claimAnalyticsHistoryRecovery098(
	t *testing.T,
	pool *pgxpool.Pool,
	epoch uuid.UUID,
	worker string,
	token uuid.UUID,
	now time.Time,
	leaseExpires time.Time,
) (uuid.UUID, bool) {
	t.Helper()
	var claimed pgtype.UUID
	if err := pool.QueryRow(t.Context(),
		`SELECT analytics_history_claim_recovery_098($1,$2,$3,$4,$5)`,
		epoch, worker, token, now, leaseExpires).Scan(&claimed); err != nil {
		t.Fatalf("claim recovery: %v", err)
	}
	if !claimed.Valid {
		return uuid.Nil, false
	}
	return uuid.UUID(claimed.Bytes), true
}

func assertAnalyticsIngestReceiptAndFloor098(
	t *testing.T,
	pool *pgxpool.Pool,
	receipt analyticsIngestReceipt098,
	wantState string,
	wantFloor string,
	wantRevision string,
) {
	t.Helper()
	var state, floor, revision string
	if err := pool.QueryRow(t.Context(), `SELECT receipt.state,
		history.prepared_stream_floor::text,history.revision::text
		FROM analytics_ingest_receipts receipt
		JOIN analytics_history_streams history USING(history_epoch)
		WHERE receipt.history_epoch=$1 AND receipt.stream_sequence=$2`,
		receipt.epoch, receipt.sequence).Scan(&state, &floor, &revision); err != nil {
		t.Fatal(err)
	}
	if state != wantState || floor != wantFloor || revision != wantRevision {
		t.Fatalf("receipt state/floor/revision = %s/%s/%s, want %s/%s/%s",
			state, floor, revision, wantState, wantFloor, wantRevision)
	}
}

func assertAnalyticsHistoryBrokerFloor098(
	t *testing.T,
	pool *pgxpool.Pool,
	epoch uuid.UUID,
	wantConsumer string,
	wantStream string,
	wantPrepared string,
	wantRevision string,
) {
	t.Helper()
	var consumer, stream, prepared, revision string
	if err := pool.QueryRow(t.Context(), `SELECT broker_consumer_ack_floor::text,
		broker_stream_ack_floor::text,prepared_stream_floor::text,revision::text
		FROM analytics_history_streams WHERE history_epoch=$1`, epoch).
		Scan(&consumer, &stream, &prepared, &revision); err != nil {
		t.Fatal(err)
	}
	if consumer != wantConsumer || stream != wantStream || prepared != wantPrepared || revision != wantRevision {
		t.Fatalf("history consumer/stream/prepared/revision = %s/%s/%s/%s, want %s/%s/%s/%s",
			consumer, stream, prepared, revision,
			wantConsumer, wantStream, wantPrepared, wantRevision)
	}
}

func assertAnalyticsHistoryRecoveryCount098(
	t *testing.T,
	pool *pgxpool.Pool,
	epoch uuid.UUID,
	wantTotal int,
	wantActive int,
) {
	t.Helper()
	var total, active int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER (WHERE completed_at IS NULL)
		FROM analytics_history_recoveries WHERE history_epoch=$1`, epoch).Scan(&total, &active); err != nil {
		t.Fatal(err)
	}
	if total != wantTotal || active != wantActive {
		t.Fatalf("recovery total/active = %d/%d, want %d/%d", total, active, wantTotal, wantActive)
	}
}

func assertAnalyticsIngestHistoryAuthority098Schema(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	for _, relation := range []string{"analytics_ingest_receipts", "analytics_history_recoveries"} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != want {
			t.Fatalf("relation %s exists=%t, want %t", relation, exists, want)
		}
	}
	if !want {
		return
	}
	for _, function := range []string{
		"analytics_ingest_mark_prepared_098(uuid,numeric,bytea,timestamp with time zone)",
		"analytics_ingest_mark_broker_ack_observed_098(uuid,numeric,bytea,timestamp with time zone)",
		"analytics_history_schedule_recovery_098(uuid,text,timestamp with time zone)",
		"analytics_history_claim_recovery_098(uuid,text,uuid,timestamp with time zone,timestamp with time zone)",
		"analytics_history_reconcile_recovery_098(uuid,uuid,numeric,numeric,timestamp with time zone)",
		"analytics_history_complete_recovery_098(uuid,uuid,timestamp with time zone)",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regprocedure($1) IS NOT NULL`, function).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("function %s is missing", function)
		}
	}
}

func digest098(marker byte) []byte {
	return bytes.Repeat([]byte{marker}, sha256.Size)
}

func assertAnalyticsIngestHistoryAuthority098Code(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func mustReadAnalyticsIngestHistoryAuthority098(t *testing.T, name string) string {
	t.Helper()
	encoded, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
