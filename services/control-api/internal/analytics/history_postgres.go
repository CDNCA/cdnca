package analytics

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresIngestHistoryConfig struct {
	InstallationID string
	NATSDomain     string
	StreamName     string
	DurableName    string
	ClaimedBy      string
	RecoveryLease  time.Duration
	Now            func() time.Time
}

type postgresIngestHistoryV1 struct {
	pool       *pgxpool.Pool
	config     PostgresIngestHistoryConfig
	generation IngestHistoryGenerationV1
}

func OpenPostgresIngestHistoryV1(
	ctx context.Context,
	pool *pgxpool.Pool,
	config PostgresIngestHistoryConfig,
) (IngestHistoryAuthorityV1, IngestHistoryGenerationV1, error) {
	if ctx == nil || pool == nil || !validBatchID(config.InstallationID) ||
		(config.NATSDomain != "" && !validNATSName(config.NATSDomain)) ||
		!validNATSName(config.StreamName) || !validNATSName(config.DurableName) ||
		!validBatchID(config.ClaimedBy) {
		return nil, IngestHistoryGenerationV1{}, ErrInvalidConfiguration
	}
	if config.RecoveryLease <= 0 {
		config.RecoveryLease = time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	rows, err := pool.Query(ctx, `SELECT installation_id,nats_domain,stream_name,durable_name,
		stream_created_unix_nano::text,consumer_created_unix_nano::text,history_epoch::text,
		history_start_sequence::text
		FROM analytics_history_streams
		WHERE installation_id=$1 AND nats_domain=$2 AND stream_name=$3 AND durable_name=$4
		AND retired_at IS NULL
		LIMIT 2`, config.InstallationID, config.NATSDomain, config.StreamName, config.DurableName)
	if err != nil {
		return nil, IngestHistoryGenerationV1{}, err
	}
	defer rows.Close()
	var generation IngestHistoryGenerationV1
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			continue
		}
		var streamCreated, consumerCreated, historyStart string
		if err := rows.Scan(&generation.InstallationID, &generation.NATSDomain, &generation.StreamName, &generation.DurableName,
			&streamCreated, &consumerCreated, &generation.HistoryEpoch, &historyStart); err != nil {
			return nil, IngestHistoryGenerationV1{}, err
		}
		generation.StreamCreatedUnixNano, err = strconv.ParseUint(streamCreated, 10, 64)
		if err != nil {
			return nil, IngestHistoryGenerationV1{}, ErrInvalidResponse
		}
		generation.ConsumerCreatedUnixNano, err = strconv.ParseUint(consumerCreated, 10, 64)
		if err != nil {
			return nil, IngestHistoryGenerationV1{}, ErrInvalidResponse
		}
		generation.HistoryStartSequence, err = strconv.ParseUint(historyStart, 10, 64)
		if err != nil {
			return nil, IngestHistoryGenerationV1{}, ErrInvalidResponse
		}
	}
	if err := rows.Err(); err != nil {
		return nil, IngestHistoryGenerationV1{}, err
	}
	if count != 1 {
		return nil, IngestHistoryGenerationV1{}, ErrIngestHistoryGenerationUnavailable
	}
	if err := ValidateIngestHistoryGenerationV1(generation); err != nil {
		return nil, IngestHistoryGenerationV1{}, ErrIngestHistoryGenerationUnavailable
	}
	return &postgresIngestHistoryV1{pool: pool, config: config, generation: generation}, generation, nil
}

func (history *postgresIngestHistoryV1) Receive(ctx context.Context, receipt IngestReceiptV1) (IngestReceiptStateV1, error) {
	if err := history.validateReceipt(receipt); err != nil {
		return 0, err
	}
	tx, err := history.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	persisted, state, err := history.receiptTx(ctx, tx, receipt.Key, true)
	if errors.Is(err, pgx.ErrNoRows) {
		result, insertErr := tx.Exec(ctx, `INSERT INTO analytics_ingest_receipts(
			history_epoch,stream_sequence,receipt_identity_sha256,generation_sha256,message_id,payload_sha256,
			canonical_event_sha256,clickhouse_token,state,received_at,created_at,updated_at
		) VALUES($1,$2::numeric,$3,$4,$5,$6,$7,$8,'received',$9,$9,$9)
		ON CONFLICT(history_epoch,stream_sequence) DO NOTHING`,
			history.generation.HistoryEpoch, receipt.Key.StreamSequence, receipt.ReceiptIdentitySHA256[:], receipt.GenerationSHA256[:],
			receipt.MessageID, receipt.PayloadSHA256[:], receipt.CanonicalEventSHA256[:], receipt.ClickHouseToken, history.now())
		if insertErr != nil {
			return 0, mapHistoryPGError(insertErr)
		}
		if result.RowsAffected() == 0 {
			persisted, state, err = history.receiptTx(ctx, tx, receipt.Key, true)
			if err != nil {
				return 0, err
			}
			persisted.SchemaVersion, persisted.Key = receipt.SchemaVersion, receipt.Key
			if _, err := ClassifyIngestReceiptReplayV1(persisted, receipt); err != nil {
				return 0, err
			}
			if err := history.classifyRealtimeExpectedCountsTx(ctx, tx, receipt); err != nil {
				return 0, err
			}
			if err := history.classifyAccessWindowContributionsTx(ctx, tx, receipt); err != nil {
				return 0, err
			}
			if err := mapHistoryCommitOutcomeV1(tx.Commit(ctx)); err != nil {
				return 0, err
			}
			return parseReceiptStateV1(state)
		}
		if err := history.persistRealtimeExpectedCountsTx(ctx, tx, receipt); err != nil {
			return 0, err
		}
		if err := history.persistAccessWindowContributionsTx(ctx, tx, receipt); err != nil {
			return 0, err
		}
		if err := mapHistoryCommitOutcomeV1(tx.Commit(ctx)); err != nil {
			return 0, err
		}
		return IngestReceiptStateReceived, nil
	}
	if err != nil {
		return 0, err
	}
	persisted.SchemaVersion = receipt.SchemaVersion
	persisted.Key = receipt.Key
	if _, err := ClassifyIngestReceiptReplayV1(persisted, receipt); err != nil {
		return 0, err
	}
	if err := history.classifyRealtimeExpectedCountsTx(ctx, tx, receipt); err != nil {
		return 0, err
	}
	if err := history.classifyAccessWindowContributionsTx(ctx, tx, receipt); err != nil {
		return 0, err
	}
	if err := mapHistoryCommitOutcomeV1(tx.Commit(ctx)); err != nil {
		return 0, err
	}
	return parseReceiptStateV1(state)
}

func (history *postgresIngestHistoryV1) MarkPrepared(ctx context.Context, receipt IngestReceiptV1) (IngestHistoryProgressV1, error) {
	if err := history.validateReceipt(receipt); err != nil {
		return IngestHistoryProgressV1{}, err
	}
	tx, err := history.pool.Begin(ctx)
	if err != nil {
		return IngestHistoryProgressV1{}, err
	}
	defer tx.Rollback(ctx)
	if err := history.lockAndClassifyReceipt(ctx, tx, receipt); err != nil {
		return IngestHistoryProgressV1{}, err
	}
	_, err = tx.Exec(ctx, `SELECT analytics_ingest_mark_prepared_098($1,$2::numeric,$3,$4)`, history.epochUUID(), receipt.Key.StreamSequence,
		receipt.ReceiptIdentitySHA256[:], history.now())
	if err != nil {
		return IngestHistoryProgressV1{}, mapReceiptPGError(err)
	}
	progress, err := history.progressTx(ctx, tx)
	if err != nil {
		return IngestHistoryProgressV1{}, err
	}
	if err := mapHistoryCommitOutcomeV1(tx.Commit(ctx)); err != nil {
		return IngestHistoryProgressV1{}, err
	}
	return progress, nil
}

func (history *postgresIngestHistoryV1) MarkBrokerAckObserved(ctx context.Context, key IngestReceiptKeyV1) error {
	if err := ValidateIngestReceiptKeyV1(history.generation, key); err != nil {
		return err
	}
	var identity []byte
	if err := history.pool.QueryRow(ctx, `SELECT receipt_identity_sha256 FROM analytics_ingest_receipts
		WHERE history_epoch=$1 AND stream_sequence=$2::numeric`, history.epochUUID(), key.StreamSequence).Scan(&identity); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIngestReceiptConflict
		}
		return err
	}
	_, err := history.pool.Exec(ctx, `SELECT analytics_ingest_mark_broker_ack_observed_098($1,$2::numeric,$3,$4)`, history.epochUUID(), key.StreamSequence, identity, history.now())
	return mapReceiptPGError(err)
}

func (history *postgresIngestHistoryV1) ReconcileBroker(ctx context.Context, claim IngestRecoveryClaimV1, snapshot IngestBrokerHistorySnapshotV1) (IngestHistoryProgressV1, error) {
	if snapshot.Generation != history.generation {
		return IngestHistoryProgressV1{}, ErrIngestHistoryGenerationChanged
	}
	recoveryID, token, err := history.claimUUIDs(claim)
	if err != nil {
		return IngestHistoryProgressV1{}, err
	}
	_, err = history.pool.Exec(ctx, `SELECT analytics_history_reconcile_recovery_098($1,$2,$3::numeric,$4::numeric,$5)`, recoveryID, token, snapshot.ConsumerAckFloor, snapshot.StreamAckFloor, history.now())
	if err != nil {
		return IngestHistoryProgressV1{}, mapRecoveryWriteOutcomeV1(err)
	}
	return history.progress(ctx)
}

func (history *postgresIngestHistoryV1) ScheduleRecovery(ctx context.Context, generation IngestHistoryGenerationV1) error {
	if generation != history.generation {
		return ErrIngestHistoryGenerationChanged
	}
	_, err := history.pool.Exec(ctx, `SELECT analytics_history_schedule_recovery_098($1,$2,$3)`, history.epochUUID(), "broker_reconcile_required", history.now())
	return mapHistoryPGError(err)
}

func (history *postgresIngestHistoryV1) ClaimScheduledRecovery(ctx context.Context, generation IngestHistoryGenerationV1) (IngestRecoveryClaimV1, bool, error) {
	if generation != history.generation {
		return IngestRecoveryClaimV1{}, false, ErrIngestHistoryGenerationChanged
	}
	now := history.now()
	leaseExpires := now.Add(history.config.RecoveryLease)
	token := uuid.New()
	var recoveryID *string
	err := history.pool.QueryRow(ctx, `SELECT analytics_history_claim_recovery_098($1,$2,$3,$4,$5)`, history.epochUUID(), history.config.ClaimedBy, token, now, leaseExpires).Scan(&recoveryID)
	if err != nil {
		return IngestRecoveryClaimV1{}, false, mapHistoryPGError(err)
	}
	if recoveryID == nil || *recoveryID == "" {
		return IngestRecoveryClaimV1{}, false, nil
	}
	return IngestRecoveryClaimV1{RecoveryID: *recoveryID, ClaimedBy: history.config.ClaimedBy, Token: token.String(), LeaseExpiresAt: leaseExpires}, true, nil
}

func (history *postgresIngestHistoryV1) CompleteScheduledRecovery(ctx context.Context, claim IngestRecoveryClaimV1) error {
	recoveryID, token, err := history.claimUUIDs(claim)
	if err != nil {
		return err
	}
	_, err = history.pool.Exec(ctx, `SELECT analytics_history_complete_recovery_098($1,$2,$3)`, recoveryID, token, history.now())
	return mapRecoveryWriteOutcomeV1(err)
}

func (history *postgresIngestHistoryV1) validateReceipt(receipt IngestReceiptV1) error {
	if history == nil || history.pool == nil {
		return ErrInvalidConfiguration
	}
	if receipt.SchemaVersion != 1 {
		return ErrIngestReceiptConflict
	}
	if err := ValidateIngestReceiptKeyV1(history.generation, receipt.Key); err != nil {
		return err
	}
	if receipt.MessageID == "" || receipt.PayloadSHA256 == ([sha256.Size]byte{}) ||
		receipt.CanonicalEventSHA256 == ([sha256.Size]byte{}) || receipt.GenerationSHA256 == ([sha256.Size]byte{}) ||
		receipt.ReceiptIdentitySHA256 == ([sha256.Size]byte{}) {
		return ErrIngestReceiptConflict
	}
	if receipt.GenerationSHA256 != canonicalGenerationDigestV1(history.generation) ||
		receipt.ClickHouseToken != ClickHouseIngestTokenV1(receipt) {
		return ErrIngestReceiptConflict
	}
	identityReceipt := receipt
	identityReceipt.ClickHouseToken = ""
	if receipt.ReceiptIdentitySHA256 != receiptIdentityDigestV1(identityReceipt) {
		return ErrIngestReceiptConflict
	}
	if err := validateRealtimeExpectedCountsV1(receipt.RealtimeExpectedCounts); err != nil {
		return err
	}
	if err := validateAccessWindowContributionsV1(receipt.AccessWindowContributions); err != nil {
		return err
	}
	return nil
}

func (history *postgresIngestHistoryV1) lockAndClassifyReceipt(ctx context.Context, tx pgx.Tx, receipt IngestReceiptV1) error {
	persisted, _, err := history.receiptTx(ctx, tx, receipt.Key, true)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIngestReceiptConflict
		}
		return err
	}
	persisted.SchemaVersion, persisted.Key = receipt.SchemaVersion, receipt.Key
	if _, err = ClassifyIngestReceiptReplayV1(persisted, receipt); err != nil {
		return err
	}
	if err := history.classifyRealtimeExpectedCountsTx(ctx, tx, receipt); err != nil {
		return err
	}
	return history.classifyAccessWindowContributionsTx(ctx, tx, receipt)
}

func (history *postgresIngestHistoryV1) receiptTx(
	ctx context.Context,
	tx pgx.Tx,
	key IngestReceiptKeyV1,
	lock bool,
) (IngestReceiptV1, string, error) {
	query := `SELECT message_id,payload_sha256,canonical_event_sha256,generation_sha256,
		receipt_identity_sha256,clickhouse_token,state FROM analytics_ingest_receipts
		WHERE history_epoch=$1 AND stream_sequence=$2::numeric`
	if lock {
		query += ` FOR UPDATE`
	}
	var persisted IngestReceiptV1
	var payload, canonical, generation, identity []byte
	var state string
	err := tx.QueryRow(ctx, query, history.epochUUID(), key.StreamSequence).Scan(
		&persisted.MessageID, &payload, &canonical, &generation, &identity, &persisted.ClickHouseToken, &state,
	)
	if err != nil {
		return IngestReceiptV1{}, "", err
	}
	if len(payload) != 32 || len(canonical) != 32 || len(generation) != 32 || len(identity) != 32 {
		return IngestReceiptV1{}, "", ErrInvalidResponse
	}
	copy(persisted.PayloadSHA256[:], payload)
	copy(persisted.CanonicalEventSHA256[:], canonical)
	copy(persisted.GenerationSHA256[:], generation)
	copy(persisted.ReceiptIdentitySHA256[:], identity)
	return persisted, state, nil
}

func validateRealtimeExpectedCountsV1(counts []RealtimeExpectedCountV1) error {
	if len(counts) > 128 {
		return ErrIngestReceiptConflict
	}
	total := uint64(0)
	for index, count := range counts {
		if count.Hour.IsZero() || count.Hour.Location() != time.UTC || !count.Hour.Equal(count.Hour.Truncate(time.Hour)) ||
			!validUUID(count.TenantID) || nilUUID(count.TenantID) || strings.ToLower(count.TenantID) != count.TenantID ||
			!validUUID(count.SiteID) || nilUUID(count.SiteID) || strings.ToLower(count.SiteID) != count.SiteID ||
			!required(count.Host, 253) || strings.ToLower(count.Host) != count.Host || count.EventCount == 0 {
			return ErrIngestReceiptConflict
		}
		total += uint64(count.EventCount)
		if total > DefaultMaxEventsPerEnvelope {
			return ErrIngestReceiptConflict
		}
		if index > 0 && !realtimeExpectedCountLess(counts[index-1], count) {
			return ErrIngestReceiptConflict
		}
	}
	return nil
}

func realtimeExpectedCountLess(left, right RealtimeExpectedCountV1) bool {
	if !left.Hour.Equal(right.Hour) {
		return left.Hour.Before(right.Hour)
	}
	if left.TenantID != right.TenantID {
		return left.TenantID < right.TenantID
	}
	if left.SiteID != right.SiteID {
		return left.SiteID < right.SiteID
	}
	if left.Host != right.Host {
		return left.Host < right.Host
	}
	return left.ListenPort < right.ListenPort
}

func (history *postgresIngestHistoryV1) persistRealtimeExpectedCountsTx(
	ctx context.Context,
	tx pgx.Tx,
	receipt IngestReceiptV1,
) error {
	createdAt := history.now()
	for _, count := range receipt.RealtimeExpectedCounts {
		result, err := tx.Exec(ctx, `INSERT INTO analytics_realtime_expected_counts_131(
			history_epoch,stream_sequence,hour,scope_id,tenant_id,site_id,host,listen_port,expected_events,created_at
		) SELECT $1,$2::numeric,$3,scope.id,$4::uuid,$5::uuid,$6,$7,$8,$9
		  FROM access_scopes scope
		  WHERE scope.kind='tenant' AND scope.tenant_id=$4::uuid
		  ON CONFLICT DO NOTHING`, history.generation.HistoryEpoch, receipt.Key.StreamSequence, count.Hour,
			count.TenantID, count.SiteID, count.Host, count.ListenPort, count.EventCount, createdAt)
		if err != nil {
			return mapHistoryPGError(err)
		}
		if result.RowsAffected() != 1 {
			return ErrIngestReceiptConflict
		}
	}
	return nil
}

func (history *postgresIngestHistoryV1) classifyRealtimeExpectedCountsTx(
	ctx context.Context,
	tx pgx.Tx,
	receipt IngestReceiptV1,
) error {
	rows, err := tx.Query(ctx, `SELECT hour,tenant_id::text,site_id::text,host,listen_port,expected_events
		FROM analytics_realtime_expected_counts_131
		WHERE history_epoch=$1 AND stream_sequence=$2::numeric
		ORDER BY hour,tenant_id,site_id,host,listen_port`, history.generation.HistoryEpoch, receipt.Key.StreamSequence)
	if err != nil {
		return mapHistoryPGError(err)
	}
	defer rows.Close()
	persisted := make([]RealtimeExpectedCountV1, 0, len(receipt.RealtimeExpectedCounts))
	for rows.Next() {
		var count RealtimeExpectedCountV1
		var port, events int32
		if err := rows.Scan(&count.Hour, &count.TenantID, &count.SiteID, &count.Host, &port, &events); err != nil ||
			port < 0 || port > 65535 || events < 1 || events > DefaultMaxEventsPerEnvelope {
			return ErrIngestReceiptConflict
		}
		count.Hour = count.Hour.UTC()
		count.ListenPort, count.EventCount = uint16(port), uint16(events)
		persisted = append(persisted, count)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(persisted) == 0 && len(receipt.RealtimeExpectedCounts) > 0 {
		return history.persistRealtimeExpectedCountsTx(ctx, tx, receipt)
	}
	if !slices.Equal(persisted, receipt.RealtimeExpectedCounts) {
		return ErrIngestReceiptConflict
	}
	return nil
}

func (history *postgresIngestHistoryV1) persistAccessWindowContributionsTx(
	ctx context.Context,
	tx pgx.Tx,
	receipt IngestReceiptV1,
) error {
	recordedAt := history.now()
	for _, contribution := range receipt.AccessWindowContributions {
		result, err := tx.Exec(ctx, `INSERT INTO analytics_access_source_window_contributions_208(
			history_epoch,stream_sequence,event_id,scope_id,tenant_id,installation_id,site_id,node_id,
			package_subscription_id,config_version_id,host,listen_port,window_start,window_end,
			source_watermark,finalized_through,dependency_state,evidence_sha256,recorded_at
		) SELECT $1,$2::numeric,$3,scope.id,$4::uuid,$5,$6::uuid,$7::uuid,NULLIF($8,'')::uuid,
			$9::uuid,$10,$11,$12,$13,$14::numeric,$15,$16,$17,$18
		  FROM access_scopes scope
		  WHERE scope.kind='tenant' AND scope.tenant_id=$4::uuid
		  ON CONFLICT DO NOTHING`, history.generation.HistoryEpoch, receipt.Key.StreamSequence,
			contribution.EventID, contribution.TenantID, contribution.InstallationID, contribution.SiteID,
			contribution.NodeID, contribution.PackageSubscriptionID, contribution.ConfigVersionID,
			contribution.Host, contribution.ListenPort, contribution.WindowStart, contribution.WindowEnd,
			strconv.FormatUint(contribution.SourceWatermark, 10), contribution.FinalizedThrough,
			contribution.DependencyState, contribution.EvidenceSHA256[:], recordedAt)
		if err != nil {
			return mapHistoryPGError(err)
		}
		if result.RowsAffected() != 1 {
			return ErrIngestReceiptConflict
		}
	}
	return nil
}

func (history *postgresIngestHistoryV1) classifyAccessWindowContributionsTx(
	ctx context.Context,
	tx pgx.Tx,
	receipt IngestReceiptV1,
) error {
	rows, err := tx.Query(ctx, `SELECT event_id,tenant_id::text,installation_id,site_id::text,node_id::text,
		COALESCE(package_subscription_id::text,''),config_version_id::text,host,listen_port,
		window_start,window_end,source_watermark::text,finalized_through,dependency_state,evidence_sha256
		FROM analytics_access_source_window_contributions_208
		WHERE history_epoch=$1 AND stream_sequence=$2::numeric
		ORDER BY event_id`, history.generation.HistoryEpoch, receipt.Key.StreamSequence)
	if err != nil {
		return mapHistoryPGError(err)
	}
	defer rows.Close()
	persisted := make([]AccessWindowContributionV1, 0, len(receipt.AccessWindowContributions))
	for rows.Next() {
		var contribution AccessWindowContributionV1
		var port int32
		var sourceWatermark string
		var evidence []byte
		if err := rows.Scan(&contribution.EventID, &contribution.TenantID, &contribution.InstallationID,
			&contribution.SiteID, &contribution.NodeID, &contribution.PackageSubscriptionID,
			&contribution.ConfigVersionID, &contribution.Host, &port, &contribution.WindowStart,
			&contribution.WindowEnd, &sourceWatermark, &contribution.FinalizedThrough,
			&contribution.DependencyState, &evidence); err != nil || port < 1 || port > 65535 || len(evidence) != sha256.Size {
			return ErrIngestReceiptConflict
		}
		contribution.SourceWatermark, err = strconv.ParseUint(sourceWatermark, 10, 64)
		if err != nil {
			return ErrIngestReceiptConflict
		}
		contribution.MetricVersion = MetricVersion
		contribution.ListenPort = uint16(port)
		contribution.WindowStart = contribution.WindowStart.UTC()
		contribution.WindowEnd = contribution.WindowEnd.UTC()
		contribution.FinalizedThrough = contribution.FinalizedThrough.UTC()
		copy(contribution.EvidenceSHA256[:], evidence)
		persisted = append(persisted, contribution)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(persisted) == 0 && len(receipt.AccessWindowContributions) > 0 {
		return history.persistAccessWindowContributionsTx(ctx, tx, receipt)
	}
	if !slices.Equal(persisted, receipt.AccessWindowContributions) {
		return ErrIngestReceiptConflict
	}
	return nil
}

func (history *postgresIngestHistoryV1) progress(ctx context.Context) (IngestHistoryProgressV1, error) {
	return history.progressQuerier(ctx, history.pool)
}

func (history *postgresIngestHistoryV1) progressTx(ctx context.Context, tx pgx.Tx) (IngestHistoryProgressV1, error) {
	return history.progressQuerier(ctx, tx)
}

type historyQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (history *postgresIngestHistoryV1) progressQuerier(ctx context.Context, queryer historyQueryRower) (IngestHistoryProgressV1, error) {
	var consumer, stream, prepared, revision string
	if err := queryer.QueryRow(ctx, `SELECT broker_consumer_ack_floor::text,broker_stream_ack_floor::text,
		prepared_stream_floor::text,revision::text FROM analytics_history_streams WHERE history_epoch=$1`, history.epochUUID()).Scan(&consumer, &stream, &prepared, &revision); err != nil {
		return IngestHistoryProgressV1{}, err
	}
	consumerFloor, err := strconv.ParseUint(consumer, 10, 64)
	if err != nil {
		return IngestHistoryProgressV1{}, ErrInvalidResponse
	}
	streamFloor, err := strconv.ParseUint(stream, 10, 64)
	if err != nil {
		return IngestHistoryProgressV1{}, ErrInvalidResponse
	}
	preparedFloor, err := strconv.ParseUint(prepared, 10, 64)
	if err != nil {
		return IngestHistoryProgressV1{}, ErrInvalidResponse
	}
	revisionValue, err := strconv.ParseUint(revision, 10, 64)
	if err != nil {
		return IngestHistoryProgressV1{}, ErrInvalidResponse
	}
	return IngestHistoryProgressV1{Generation: history.generation, BrokerConsumerAckFloor: consumerFloor, BrokerStreamAckFloor: streamFloor,
		PreparedStreamFloor: preparedFloor, CommittedStreamAckFloor: min(preparedFloor, streamFloor), Revision: revisionValue}, nil
}

func (history *postgresIngestHistoryV1) claimUUIDs(claim IngestRecoveryClaimV1) (uuid.UUID, uuid.UUID, error) {
	if history == nil || claim.RecoveryID == "" || claim.Token == "" || claim.ClaimedBy == "" || claim.LeaseExpiresAt.IsZero() {
		return uuid.Nil, uuid.Nil, ErrIngestRecoveryFenced
	}
	recoveryID, err := uuid.Parse(claim.RecoveryID)
	if err != nil {
		return uuid.Nil, uuid.Nil, ErrIngestRecoveryFenced
	}
	token, err := uuid.Parse(claim.Token)
	if err != nil {
		return uuid.Nil, uuid.Nil, ErrIngestRecoveryFenced
	}
	return recoveryID, token, nil
}

func (history *postgresIngestHistoryV1) epochUUID() uuid.UUID {
	epoch, _ := uuid.Parse(history.generation.HistoryEpoch)
	return epoch
}

func (history *postgresIngestHistoryV1) now() time.Time { return history.config.Now().UTC() }

func parseReceiptStateV1(value string) (IngestReceiptStateV1, error) {
	switch value {
	case "received":
		return IngestReceiptStateReceived, nil
	case "prepared":
		return IngestReceiptStatePrepared, nil
	case "broker_ack_observed":
		return IngestReceiptStateBrokerAckObserved, nil
	default:
		return 0, ErrInvalidResponse
	}
}

func mapHistoryPGError(err error) error {
	if err == nil {
		return nil
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P9803", "P9802":
			return ErrIngestRecoveryFenced
		case "P9800", "P9801":
			return ErrIngestHistoryGenerationUnavailable
		}
	}
	if strings.Contains(strings.ToLower(err.Error()), "receipt") && strings.Contains(strings.ToLower(err.Error()), "conflict") {
		return ErrIngestReceiptConflict
	}
	return err
}

func mapReceiptPGError(err error) error {
	if err == nil {
		return nil
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "P9803" {
		return ErrIngestReceiptConflict
	}
	return mapHistoryPGError(err)
}

func mapHistoryCommitOutcomeV1(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(ErrIngestWriteOutcomeUnknown, err)
}

func mapRecoveryWriteOutcomeV1(err error) error {
	if err == nil {
		return nil
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return mapHistoryPGError(err)
	}
	return mapHistoryCommitOutcomeV1(err)
}

var _ IngestHistoryAuthorityV1 = (*postgresIngestHistoryV1)(nil)

func (history *postgresIngestHistoryV1) String() string {
	if history == nil {
		return "analytics.postgresIngestHistoryV1<nil>"
	}
	return fmt.Sprintf("analytics.postgresIngestHistoryV1{%s/%s}", history.generation.InstallationID, history.generation.HistoryEpoch)
}
