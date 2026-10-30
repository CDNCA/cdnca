package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRealtimeCoverageStore struct {
	pool *pgxpool.Pool
}

func NewPostgresRealtimeCoverageStore(pool *pgxpool.Pool) (*PostgresRealtimeCoverageStore, error) {
	if pool == nil {
		return nil, ErrInvalidServiceConfig
	}
	return &PostgresRealtimeCoverageStore{pool: pool}, nil
}

const pendingRealtimeCoverageSQL = `SELECT contribution.scope_id::text,contribution.tenant_id::text,
	contribution.site_id::text,contribution.host,contribution.listen_port,
	contribution.window_start,contribution.window_end
FROM analytics_access_source_window_contributions_208 contribution
JOIN access_scopes scope ON scope.id=contribution.scope_id AND scope.kind='tenant'
	AND scope.tenant_id=contribution.tenant_id
JOIN sites site ON site.scope_id=contribution.scope_id AND site.id=contribution.site_id
WHERE contribution.window_end<=$1
  AND NOT EXISTS (
	SELECT 1 FROM analytics_realtime_source_windows_184 finalized
	WHERE finalized.scope_id=contribution.scope_id
	  AND finalized.window_start=contribution.window_start
	  AND finalized.site_id=contribution.site_id
	  AND finalized.host=contribution.host
	  AND finalized.listen_port=contribution.listen_port
  )
GROUP BY contribution.scope_id,contribution.tenant_id,contribution.site_id,
	contribution.host,contribution.listen_port,contribution.window_start,contribution.window_end
ORDER BY contribution.window_start,contribution.scope_id,contribution.site_id,
	contribution.host,contribution.listen_port
LIMIT ($2::integer+1)`

func (store *PostgresRealtimeCoverageStore) PendingRealtimeCoverage(
	ctx context.Context,
	cutoff time.Time,
	maximum int,
) ([]RealtimeCoverageCandidateV1, error) {
	if store == nil || store.pool == nil || ctx == nil || cutoff.IsZero() || cutoff.Location() != time.UTC ||
		maximum < 1 || maximum > maximumRealtimeCoverageWindows {
		return nil, ErrRealtimeCoverageConflict
	}
	if err := store.captureRealtimeRoster(ctx, cutoff.Truncate(time.Hour)); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, pendingRealtimeCoverageSQL, cutoff, maximum)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]RealtimeCoverageCandidateV1, 0, maximum)
	for rows.Next() {
		var candidate RealtimeCoverageCandidateV1
		var listenPort int32
		if err := rows.Scan(
			&candidate.ScopeID, &candidate.TenantID, &candidate.SiteID, &candidate.Host, &listenPort,
			&candidate.WindowStart, &candidate.WindowEnd,
		); err != nil {
			return nil, err
		}
		if listenPort < 1 || listenPort > 65535 {
			return nil, ErrRealtimeCoverageConflict
		}
		candidate.ListenPort = uint16(listenPort)
		candidate.WindowStart = candidate.WindowStart.UTC()
		candidate.WindowEnd = candidate.WindowEnd.UTC()
		if !validRealtimeCoverageCandidate(candidate) {
			return nil, ErrRealtimeCoverageConflict
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

func (store *PostgresRealtimeCoverageStore) LoadRealtimeCoverage(
	ctx context.Context,
	candidate RealtimeCoverageCandidateV1,
) (RealtimeCoverageSnapshotV1, error) {
	if store == nil || store.pool == nil || ctx == nil || !validRealtimeCoverageCandidate(candidate) {
		return RealtimeCoverageSnapshotV1{}, ErrRealtimeCoverageConflict
	}
	if err := store.captureRealtimeRoster(ctx, candidate.WindowStart); err != nil {
		return RealtimeCoverageSnapshotV1{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return RealtimeCoverageSnapshotV1{}, err
	}
	defer tx.Rollback(ctx)
	snapshot, err := loadRealtimeCoverageSnapshotTx(ctx, tx, candidate)
	if err != nil {
		return RealtimeCoverageSnapshotV1{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RealtimeCoverageSnapshotV1{}, err
	}
	return snapshot, nil
}

const realtimeCoverageSiteSQL = `SELECT EXISTS(
	SELECT 1
	FROM sites site
	JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant' AND scope.tenant_id=$2::uuid
	WHERE site.scope_id=$1::uuid AND site.id=$3::uuid
	  AND site.deleted_at IS NULL AND site.enabled AND site.status='active'
	  AND site.created_at<=$6 AND site.updated_at<=$6
	  AND ($5::integer::text=ANY(site.http_ports) OR
		(site.https_enabled AND $5::integer::text=ANY(site.https_ports)))
	  AND (site.domain=$4 OR EXISTS (
		SELECT 1 FROM (
			SELECT fact.action,fact.occurred_at
			FROM site_domain_facts fact
			WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id AND fact.canonical_domain=$4
			ORDER BY fact.global_sequence DESC LIMIT 1
		) latest WHERE latest.action='activate' AND latest.occurred_at<=$6
	  ))
	  AND NOT EXISTS (
		SELECT 1 FROM site_domain_facts changed
		WHERE changed.scope_id=site.scope_id AND changed.site_id=site.id AND changed.occurred_at>$6
	  )
)`

const realtimeCoverageAccessSQL = `SELECT contribution.node_id::text,contribution.config_version_id::text,
	contribution.source_watermark::text,contribution.finalized_through,
	contribution.evidence_sha256,contribution.recorded_at
FROM analytics_access_source_window_contributions_208 contribution
WHERE contribution.scope_id=$1::uuid AND contribution.tenant_id=$2::uuid
	AND contribution.site_id=$3::uuid AND contribution.host=$4
	AND contribution.listen_port=$5 AND contribution.window_start=$6 AND contribution.window_end=$7
ORDER BY contribution.node_id,contribution.history_epoch,contribution.stream_sequence`

func loadRealtimeCoverageSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	candidate RealtimeCoverageCandidateV1,
) (RealtimeCoverageSnapshotV1, error) {
	var stableSite bool
	if err := tx.QueryRow(ctx, realtimeCoverageSiteSQL,
		candidate.ScopeID, candidate.TenantID, candidate.SiteID, candidate.Host,
		candidate.ListenPort, candidate.WindowStart,
	).Scan(&stableSite); err != nil {
		return RealtimeCoverageSnapshotV1{}, err
	}
	if !stableSite {
		return RealtimeCoverageSnapshotV1{}, ErrRealtimeCoverageConflict
	}

	sources, err := realtimeRosterForCandidate(ctx, tx, candidate)
	if err != nil {
		return RealtimeCoverageSnapshotV1{}, err
	}

	byNode := make(map[string]int, len(sources))
	for index, source := range sources {
		if _, duplicate := byNode[source.NodeID]; duplicate || !validUUID(source.NodeID) ||
			!validUUID(source.ConfigVersionID) {
			return RealtimeCoverageSnapshotV1{}, ErrRealtimeCoverageConflict
		}
		byNode[source.NodeID] = index
	}
	rows, err := tx.Query(ctx, realtimeCoverageAccessSQL,
		candidate.ScopeID, candidate.TenantID, candidate.SiteID, candidate.Host, candidate.ListenPort,
		candidate.WindowStart, candidate.WindowEnd,
	)
	if err != nil {
		return RealtimeCoverageSnapshotV1{}, err
	}
	seenAccess := make(map[string]struct{}, len(sources))
	for rows.Next() {
		var nodeID, configVersionID, encodedWatermark string
		var finalizedThrough, recordedAt time.Time
		var evidence []byte
		if err := rows.Scan(
			&nodeID, &configVersionID, &encodedWatermark, &finalizedThrough, &evidence, &recordedAt,
		); err != nil {
			rows.Close()
			return RealtimeCoverageSnapshotV1{}, err
		}
		index, expected := byNode[nodeID]
		_, duplicate := seenAccess[nodeID]
		if !expected || duplicate || sources[index].ConfigVersionID != configVersionID || len(evidence) != sha256.Size {
			rows.Close()
			return RealtimeCoverageSnapshotV1{}, ErrRealtimeCoverageConflict
		}
		watermark, err := strconv.ParseUint(encodedWatermark, 10, 64)
		if err != nil {
			rows.Close()
			return RealtimeCoverageSnapshotV1{}, ErrRealtimeCoverageConflict
		}
		seenAccess[nodeID] = struct{}{}
		sources[index].AccessPresent = true
		sources[index].AccessSourceWatermark = watermark
		sources[index].AccessFinalizedThrough = finalizedThrough.UTC()
		copy(sources[index].AccessEvidenceSHA256[:], evidence)
		sources[index].AccessRecordedAt = recordedAt.UTC()
		if !validRealtimeCoverageSource(sources[index], candidate) {
			rows.Close()
			return RealtimeCoverageSnapshotV1{}, ErrRealtimeCoverageConflict
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RealtimeCoverageSnapshotV1{}, err
	}
	rows.Close()
	return RealtimeCoverageSnapshotV1{Candidate: candidate, Sources: sources}, nil
}

func (store *PostgresRealtimeCoverageStore) CommitRealtimeCoverage(
	ctx context.Context,
	snapshot RealtimeCoverageSnapshotV1,
	fact RealtimeCoverageFactV1,
) (bool, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		!validRealtimeCoverageFact(snapshot, fact) {
		return false, ErrRealtimeCoverageConflict
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	persistedSnapshot, err := loadRealtimeCoverageSnapshotTx(ctx, tx, snapshot.Candidate)
	if err != nil {
		return false, err
	}
	if !equalRealtimeCoverageSnapshot(snapshot, persistedSnapshot) {
		return false, ErrRealtimeCoverageConflict
	}
	result, err := tx.Exec(ctx, `INSERT INTO analytics_realtime_source_windows_184(
		scope_id,tenant_id,site_id,host,listen_port,window_start,window_end,
		access_sources_expected,access_sources_finalized,connection_sources_expected,connection_sources_finalized,
		access_source_watermark,access_finalized_through,connection_source_watermark,connection_finalized_through,
		evidence_sha256,recorded_at
	) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
	ON CONFLICT(scope_id,window_start,site_id,host,listen_port) DO NOTHING`,
		fact.Candidate.ScopeID, fact.Candidate.TenantID, fact.Candidate.SiteID, fact.Candidate.Host,
		fact.Candidate.ListenPort, fact.Candidate.WindowStart, fact.Candidate.WindowEnd,
		fact.AccessSourcesExpected, fact.AccessSourcesFinalized,
		fact.ConnectionSourcesExpected, fact.ConnectionSourcesFinalized,
		fact.AccessSourceWatermark, fact.AccessFinalizedThrough,
		fact.ConnectionSourceWatermark, fact.ConnectionFinalizedThrough,
		fact.EvidenceSHA256[:], fact.RecordedAt,
	)
	if err != nil {
		return false, err
	}
	inserted := result.RowsAffected() == 1
	if !inserted {
		persisted, err := loadRealtimeCoverageFactTx(ctx, tx, fact.Candidate)
		if err != nil {
			return false, err
		}
		if !equalRealtimeCoverageFact(fact, persisted) {
			return false, ErrRealtimeCoverageConflict
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return inserted, nil
}

func loadRealtimeCoverageFactTx(
	ctx context.Context,
	tx pgx.Tx,
	candidate RealtimeCoverageCandidateV1,
) (RealtimeCoverageFactV1, error) {
	var fact RealtimeCoverageFactV1
	var listenPort int32
	var evidence []byte
	err := tx.QueryRow(ctx, `SELECT scope_id::text,tenant_id::text,site_id::text,host,listen_port,
		window_start,window_end,access_sources_expected,access_sources_finalized,
		connection_sources_expected,connection_sources_finalized,access_source_watermark,
		access_finalized_through,connection_source_watermark,connection_finalized_through,
		evidence_sha256,recorded_at
	FROM analytics_realtime_source_windows_184
	WHERE scope_id=$1::uuid AND window_start=$2 AND site_id=$3::uuid AND host=$4 AND listen_port=$5`,
		candidate.ScopeID, candidate.WindowStart, candidate.SiteID, candidate.Host, candidate.ListenPort,
	).Scan(
		&fact.Candidate.ScopeID, &fact.Candidate.TenantID, &fact.Candidate.SiteID, &fact.Candidate.Host, &listenPort,
		&fact.Candidate.WindowStart, &fact.Candidate.WindowEnd,
		&fact.AccessSourcesExpected, &fact.AccessSourcesFinalized,
		&fact.ConnectionSourcesExpected, &fact.ConnectionSourcesFinalized,
		&fact.AccessSourceWatermark, &fact.AccessFinalizedThrough,
		&fact.ConnectionSourceWatermark, &fact.ConnectionFinalizedThrough,
		&evidence, &fact.RecordedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RealtimeCoverageFactV1{}, ErrRealtimeCoverageConflict
	}
	if err != nil {
		return RealtimeCoverageFactV1{}, err
	}
	if listenPort < 1 || listenPort > 65535 || len(evidence) != sha256.Size {
		return RealtimeCoverageFactV1{}, ErrRealtimeCoverageConflict
	}
	fact.Candidate.ListenPort = uint16(listenPort)
	fact.Candidate.WindowStart = fact.Candidate.WindowStart.UTC()
	fact.Candidate.WindowEnd = fact.Candidate.WindowEnd.UTC()
	fact.AccessSourceWatermark = fact.AccessSourceWatermark.UTC()
	fact.AccessFinalizedThrough = fact.AccessFinalizedThrough.UTC()
	fact.ConnectionSourceWatermark = fact.ConnectionSourceWatermark.UTC()
	fact.ConnectionFinalizedThrough = fact.ConnectionFinalizedThrough.UTC()
	fact.RecordedAt = fact.RecordedAt.UTC()
	copy(fact.EvidenceSHA256[:], evidence)
	return fact, nil
}

func validRealtimeCoverageFact(snapshot RealtimeCoverageSnapshotV1, fact RealtimeCoverageFactV1) bool {
	if !equalRealtimeCoverageCandidate(snapshot.Candidate, fact.Candidate) || len(snapshot.Sources) < 1 ||
		fact.AccessSourcesExpected != len(snapshot.Sources) || fact.AccessSourcesFinalized != len(snapshot.Sources) ||
		fact.ConnectionSourcesExpected != len(snapshot.Sources) || fact.ConnectionSourcesFinalized != len(snapshot.Sources) ||
		fact.EvidenceSHA256 == ([sha256.Size]byte{}) {
		return false
	}
	for _, value := range []time.Time{
		fact.AccessSourceWatermark, fact.AccessFinalizedThrough,
		fact.ConnectionSourceWatermark, fact.ConnectionFinalizedThrough, fact.RecordedAt,
	} {
		if value.IsZero() || value.Location() != time.UTC {
			return false
		}
	}
	return !fact.AccessFinalizedThrough.Before(fact.Candidate.WindowEnd) &&
		!fact.ConnectionFinalizedThrough.Before(fact.Candidate.WindowEnd) &&
		!fact.AccessSourceWatermark.Before(fact.AccessFinalizedThrough) &&
		!fact.ConnectionSourceWatermark.Before(fact.ConnectionFinalizedThrough) &&
		!fact.RecordedAt.Before(fact.AccessSourceWatermark) &&
		!fact.RecordedAt.Before(fact.ConnectionSourceWatermark)
}

func equalRealtimeCoverageSnapshot(left, right RealtimeCoverageSnapshotV1) bool {
	if !equalRealtimeCoverageCandidate(left.Candidate, right.Candidate) || len(left.Sources) != len(right.Sources) {
		return false
	}
	leftSources := append([]RealtimeCoverageSourceV1(nil), left.Sources...)
	rightSources := append([]RealtimeCoverageSourceV1(nil), right.Sources...)
	sort.Slice(leftSources, func(i, j int) bool { return leftSources[i].NodeID < leftSources[j].NodeID })
	sort.Slice(rightSources, func(i, j int) bool { return rightSources[i].NodeID < rightSources[j].NodeID })
	for index := range leftSources {
		if leftSources[index].NodeID != rightSources[index].NodeID ||
			leftSources[index].ConfigVersionID != rightSources[index].ConfigVersionID ||
			leftSources[index].AccessPresent != rightSources[index].AccessPresent ||
			leftSources[index].AccessSourceWatermark != rightSources[index].AccessSourceWatermark ||
			!leftSources[index].AccessFinalizedThrough.Equal(rightSources[index].AccessFinalizedThrough) ||
			leftSources[index].AccessEvidenceSHA256 != rightSources[index].AccessEvidenceSHA256 ||
			!leftSources[index].AccessRecordedAt.Equal(rightSources[index].AccessRecordedAt) {
			return false
		}
	}
	return true
}

func equalRealtimeCoverageCandidate(left, right RealtimeCoverageCandidateV1) bool {
	return left.ScopeID == right.ScopeID && left.TenantID == right.TenantID && left.SiteID == right.SiteID &&
		left.Host == right.Host && left.ListenPort == right.ListenPort &&
		left.WindowStart.Equal(right.WindowStart) && left.WindowEnd.Equal(right.WindowEnd)
}

func equalRealtimeCoverageFact(left, right RealtimeCoverageFactV1) bool {
	return equalRealtimeCoverageCandidate(left.Candidate, right.Candidate) &&
		left.AccessSourcesExpected == right.AccessSourcesExpected &&
		left.AccessSourcesFinalized == right.AccessSourcesFinalized &&
		left.ConnectionSourcesExpected == right.ConnectionSourcesExpected &&
		left.ConnectionSourcesFinalized == right.ConnectionSourcesFinalized &&
		left.AccessSourceWatermark.Equal(right.AccessSourceWatermark) &&
		left.AccessFinalizedThrough.Equal(right.AccessFinalizedThrough) &&
		left.ConnectionSourceWatermark.Equal(right.ConnectionSourceWatermark) &&
		left.ConnectionFinalizedThrough.Equal(right.ConnectionFinalizedThrough) &&
		bytes.Equal(left.EvidenceSHA256[:], right.EvidenceSHA256[:]) &&
		left.RecordedAt.Equal(right.RecordedAt)
}
