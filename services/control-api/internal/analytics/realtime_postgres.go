package analytics

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type realtimeEvidenceQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgresRealtimeExpectedCountReader struct {
	queryer realtimeEvidenceQueryRower
	now     func() time.Time
}

type RealtimeV2CoverageAuthority struct {
	TenantID                   string
	From                       time.Time
	To                         time.Time
	SiteID                     string
	Domain                     string
	ListenPort                 uint16
	RequestedWindows           uint16
	CoveredWindows             uint16
	ExpectedDimensions         uint64
	CoveredDimensions          uint64
	AccessSourcesExpected      uint64
	AccessSourcesFinalized     uint64
	ConnectionSourcesExpected  uint64
	ConnectionSourcesFinalized uint64
	FinalizedThrough           time.Time
	SourceWatermark            time.Time
}

type RealtimeV2CoverageReader interface {
	RealtimeV2Coverage(context.Context, analyticsrealtime.Scope, analyticsrealtime.Filter) (RealtimeV2CoverageAuthority, error)
}

func NewPostgresRealtimeExpectedCountReader(pool *pgxpool.Pool) (*PostgresRealtimeExpectedCountReader, error) {
	if pool == nil {
		return nil, ErrInvalidServiceConfig
	}
	return &PostgresRealtimeExpectedCountReader{queryer: pool}, nil
}

const realtimeExpectedEvidenceSQL = `WITH requested AS (
	SELECT generate_series($2::timestamptz,$3::timestamptz-interval '1 hour',interval '1 hour') AS hour
), dimensions AS (
	SELECT requested.hour,(item->>'scope_id')::uuid AS scope_id,(item->>'tenant_id')::uuid AS tenant_id,
		(item->>'site_id')::uuid AS site_id,item->>'host' AS host,(item->>'listen_port')::integer AS listen_port,
		count(DISTINCT item->>'node_id') AS nodes,bool_and((item->>'stable')::boolean) AS stable
	FROM requested JOIN analytics_realtime_source_rosters_247 roster ON roster.window_start=requested.hour
	CROSS JOIN LATERAL jsonb_array_elements(roster.sources) item
	WHERE roster.evidence_sha256=sha256(convert_to(roster.sources::text,'UTF8'))
	  AND (NOT $7::boolean OR (item->>'tenant_id')::uuid=$1::uuid)
	  AND ($4='' OR (item->>'site_id')::uuid=NULLIF($4,'')::uuid)
	  AND ($5='' OR item->>'host'=ANY(string_to_array($5,' ')))
	  AND ($6::integer=0 OR (item->>'listen_port')::integer=$6::integer)
	GROUP BY requested.hour,item->>'scope_id',item->>'tenant_id',item->>'site_id',item->>'host',item->>'listen_port'
), rostered AS (
	SELECT requested.hour
	FROM requested JOIN analytics_realtime_source_rosters_247 roster ON roster.window_start=requested.hour
	WHERE roster.evidence_sha256=sha256(convert_to(roster.sources::text,'UTF8'))
), activity AS (
	SELECT contribution.window_start AS hour
	FROM analytics_access_source_window_contributions_208 contribution
	WHERE contribution.window_start >= $2 AND contribution.window_start < $3
	  AND (NOT $7::boolean OR contribution.tenant_id=$1::uuid)
	  AND ($4='' OR contribution.site_id=NULLIF($4,'')::uuid)
	  AND ($5='' OR contribution.host=ANY(string_to_array($5,' ')))
	  AND ($6::integer=0 OR contribution.listen_port=$6::integer)
	UNION
	SELECT expected.hour
	FROM analytics_realtime_expected_counts_131 expected
	WHERE expected.hour >= $2 AND expected.hour < $3
	  AND (NOT $7::boolean OR expected.tenant_id=$1::uuid)
	  AND ($4='' OR expected.site_id=NULLIF($4,'')::uuid)
	  AND ($5='' OR expected.host=ANY(string_to_array($5,' ')))
	  AND ($6::integer=0 OR expected.listen_port=$6::integer)
), proven AS (
	-- A recorded roster with no matching listener proves an empty hour only
	-- after the hour has closed past the coverage grace and nothing reported
	-- activity for the same filter. Any report without a listener stays open.
	SELECT requested.hour,
		EXISTS(SELECT 1 FROM rostered WHERE rostered.hour=requested.hour)
		AND NOT EXISTS(SELECT 1 FROM dimensions WHERE dimensions.hour=requested.hour)
		AND NOT EXISTS(SELECT 1 FROM activity WHERE activity.hour=requested.hour)
		AND requested.hour+interval '1 hour'<=$8::timestamptz AS empty_proven
	FROM requested
), coverage AS (
	SELECT requested.hour,dimensions.scope_id,dimensions.nodes,dimensions.stable,
		source.access_sources_expected,source.access_sources_finalized,source.connection_sources_expected,source.connection_sources_finalized,
		LEAST(source.access_finalized_through,source.connection_finalized_through) AS finalized_through,
		LEAST(source.access_source_watermark,source.connection_source_watermark) AS source_watermark
	FROM requested LEFT JOIN dimensions ON dimensions.hour=requested.hour
	LEFT JOIN analytics_realtime_source_windows_184 source ON source.window_start=requested.hour
	 AND source.scope_id=dimensions.scope_id AND source.tenant_id=dimensions.tenant_id
	 AND source.site_id=dimensions.site_id AND source.host=dimensions.host AND source.listen_port=dimensions.listen_port
), projected AS (
	SELECT coverage.hour,count(coverage.scope_id)>0 OR bool_or(proven.empty_proven) AS covered,
		COALESCE(bool_and(COALESCE(stable AND nodes>0 AND access_sources_expected=nodes AND access_sources_finalized=access_sources_expected AND
			connection_sources_expected=nodes AND connection_sources_finalized=connection_sources_expected AND
			finalized_through>=coverage.hour+interval '1 hour' AND source_watermark>=coverage.hour+interval '1 hour',false)),false)
			OR bool_or(proven.empty_proven) AS complete,
		COALESCE(sum(coverage.nodes),0) AS access_sources_expected,
		COALESCE(sum(coverage.access_sources_finalized),0) AS access_sources_finalized,
		COALESCE(sum(coverage.nodes),0) AS connection_sources_expected,
		COALESCE(sum(coverage.connection_sources_finalized),0) AS connection_sources_finalized,
		COALESCE(min(coverage.finalized_through),
			CASE WHEN bool_or(proven.empty_proven) THEN coverage.hour+interval '1 hour' END) AS finalized_through,
		COALESCE(min(coverage.source_watermark),
			CASE WHEN bool_or(proven.empty_proven) THEN coverage.hour+interval '1 hour' END) AS source_watermark
	FROM coverage JOIN proven ON proven.hour=coverage.hour GROUP BY coverage.hour
), expected AS (
	SELECT expected.hour,sum(expected.expected_events) AS events
	FROM analytics_realtime_expected_counts_131 expected
	JOIN access_scopes scope ON scope.id=expected.scope_id
	WHERE scope.kind='tenant' AND (NOT $7::boolean OR scope.tenant_id=$1::uuid)
	  AND expected.hour >= $2 AND expected.hour < $3
	  AND ($4='' OR expected.site_id=NULLIF($4,'')::uuid)
	  AND ($5='' OR expected.host=ANY(string_to_array($5,' ')))
	  AND ($6::integer=0 OR expected.listen_port=$6::integer)
	GROUP BY expected.hour
), settled AS (
	SELECT projected.*,projected.covered AND projected.complete AS settled FROM projected
)
-- Counts and sources aggregate settled hours only; unsettled hours are listed
-- so a partial read can exclude them. A fully settled range is unchanged.
SELECT COALESCE((SELECT sum(expected.events) FROM expected JOIN settled ON settled.hour=expected.hour
		WHERE settled.settled),0)::text,
	(SELECT count(*) FROM requested)::text,
	count(*) FILTER(WHERE settled.settled)::text,
	COALESCE(bool_and(settled.settled),false),
	COALESCE(sum(settled.access_sources_expected) FILTER(WHERE settled.settled),0)::text,
	COALESCE(sum(settled.access_sources_finalized) FILTER(WHERE settled.settled),0)::text,
	COALESCE(sum(settled.connection_sources_expected) FILTER(WHERE settled.settled),0)::text,
	COALESCE(sum(settled.connection_sources_finalized) FILTER(WHERE settled.settled),0)::text,
	max(settled.finalized_through) FILTER(WHERE settled.settled),
	max(settled.source_watermark) FILTER(WHERE settled.settled),
	COALESCE(array_agg(settled.hour ORDER BY settled.hour) FILTER(WHERE NOT settled.settled),'{}')
FROM settled`

const realtimeV2CoverageSQL = `WITH requested AS (
	SELECT generate_series($2::timestamptz,$3::timestamptz-interval '1 hour',interval '1 hour') AS hour
), dimensions AS (
	SELECT expected.hour,expected.scope_id,expected.site_id,expected.host,expected.listen_port
	FROM analytics_realtime_expected_counts_131 expected
	JOIN access_scopes scope ON scope.id=expected.scope_id AND scope.kind='tenant'
	WHERE expected.tenant_id=$1::uuid AND expected.hour >= $2 AND expected.hour < $3
	  AND ($4='' OR expected.site_id=NULLIF($4,'')::uuid)
	  AND ($5='' OR expected.host=$5)
	  AND ($6::integer=0 OR expected.listen_port=$6::integer)
	UNION
	SELECT contribution.window_start,contribution.scope_id,contribution.site_id,
		contribution.host,contribution.listen_port
	FROM analytics_access_source_window_contributions_208 contribution
	JOIN access_scopes scope ON scope.id=contribution.scope_id AND scope.kind='tenant'
	WHERE contribution.tenant_id=$1::uuid AND contribution.window_start >= $2 AND contribution.window_start < $3
	  AND ($4='' OR contribution.site_id=NULLIF($4,'')::uuid)
	  AND ($5='' OR contribution.host=$5)
	  AND ($6::integer=0 OR contribution.listen_port=$6::integer)
), projected AS (
	SELECT requested.hour,count(dimensions.scope_id) AS dimensions_expected,
		count(source.scope_id) AS dimensions_covered,
		COALESCE(bool_and(source.access_sources_expected>0 AND
			source.access_sources_finalized=source.access_sources_expected AND
			source.connection_sources_expected>0 AND
			source.connection_sources_finalized=source.connection_sources_expected),false) AS complete,
		COALESCE(sum(source.access_sources_expected),0) AS access_sources_expected,
		COALESCE(sum(source.access_sources_finalized),0) AS access_sources_finalized,
		COALESCE(sum(source.connection_sources_expected),0) AS connection_sources_expected,
		COALESCE(sum(source.connection_sources_finalized),0) AS connection_sources_finalized,
		min(LEAST(source.access_finalized_through,source.connection_finalized_through)) AS finalized_through,
		min(LEAST(source.access_source_watermark,source.connection_source_watermark)) AS source_watermark
	FROM requested
	LEFT JOIN dimensions ON dimensions.hour=requested.hour
	LEFT JOIN analytics_realtime_source_windows_184 source
	  ON source.scope_id=dimensions.scope_id AND source.window_start=dimensions.hour
	 AND source.site_id=dimensions.site_id AND source.host=dimensions.host
	 AND source.listen_port=dimensions.listen_port
	GROUP BY requested.hour
)
SELECT (SELECT count(*) FROM requested)::text,
	count(*) FILTER(WHERE dimensions_expected>0 AND dimensions_covered=dimensions_expected AND complete)::text,
	COALESCE(bool_and(dimensions_expected>0 AND dimensions_covered=dimensions_expected AND complete),false),
	COALESCE(sum(dimensions_expected),0)::text,COALESCE(sum(dimensions_covered),0)::text,
	COALESCE(sum(access_sources_expected),0)::text,COALESCE(sum(access_sources_finalized),0)::text,
	COALESCE(sum(connection_sources_expected),0)::text,COALESCE(sum(connection_sources_finalized),0)::text,
	min(finalized_through),min(source_watermark)
FROM projected`

func (reader *PostgresRealtimeExpectedCountReader) ExpectedRealtimeEvidence(
	ctx context.Context,
	scope Scope,
	filter RealtimeFilter,
) (RealtimeExpectedEvidence, error) {
	if reader == nil || reader.queryer == nil || ctx == nil ||
		(scope.kind != scopeTenant && scope.kind != scopeAdmin) || !validRealtimeFilter(filter) {
		return RealtimeExpectedEvidence{}, ErrInvalidInput
	}
	filter = realtimeCoverageFilter(filter)
	tenantID, tenantScoped := nilUUIDValue, false
	if scope.kind == scopeTenant {
		tenantID, tenantScoped = scope.tenantID, true
	}
	var encodedExpected, encodedRequested, encodedCovered string
	var encodedAccessExpected, encodedAccessFinalized, encodedConnectionExpected, encodedConnectionFinalized string
	var complete bool
	var finalizedThrough, sourceWatermark *time.Time
	var missingWindows []time.Time
	now := time.Now
	if reader.now != nil {
		now = reader.now
	}
	emptyProofCutoff := now().UTC().Add(-defaultRealtimeCoverageGrace)
	err := reader.queryer.QueryRow(ctx, realtimeExpectedEvidenceSQL,
		tenantID, filter.From, filter.To, filter.SiteID, filter.Host, filter.ListenPort, tenantScoped, emptyProofCutoff).Scan(
		&encodedExpected, &encodedRequested, &encodedCovered, &complete,
		&encodedAccessExpected, &encodedAccessFinalized, &encodedConnectionExpected, &encodedConnectionFinalized,
		&finalizedThrough, &sourceWatermark, &missingWindows)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return RealtimeExpectedEvidence{}, err
		}
		return RealtimeExpectedEvidence{}, fmt.Errorf("%w: source window authority unavailable", ErrRealtimeEvidenceUnavailable)
	}
	values := make([]uint64, 7)
	for index, encoded := range []string{encodedExpected, encodedRequested, encodedCovered, encodedAccessExpected,
		encodedAccessFinalized, encodedConnectionExpected, encodedConnectionFinalized} {
		values[index], err = strconv.ParseUint(encoded, 10, 64)
		if err != nil {
			return RealtimeExpectedEvidence{}, ErrRealtimeEvidenceUnavailable
		}
	}
	if values[1] == 0 || values[1] > maximumRealtimePoints+1 || values[2] > values[1] {
		return RealtimeExpectedEvidence{}, ErrRealtimeEvidenceUnavailable
	}
	// Partial evidence names every uncovered or unfinalized hour. It is never
	// complete evidence: Service.Realtime rejects it unless the caller opted into
	// partial coverage (the minute panel), and reconciliation is skipped there.
	if len(missingWindows) > 0 {
		if uint64(len(missingWindows)) != values[1]-values[2] || !validRealtimeMissingWindows(missingWindows, filter) {
			return RealtimeExpectedEvidence{}, ErrRealtimeEvidenceUnavailable
		}
		epoch := time.Unix(0, 0).UTC()
		evidence := RealtimeExpectedEvidence{
			TenantID: scope.tenantID, From: filter.From, To: filter.To, SiteID: filter.SiteID, Host: filter.Host, ListenPort: filter.ListenPort,
			ExpectedEvents: values[0], RequestedWindows: uint16(values[1]), CoveredWindows: uint16(values[2]),
			AccessSourcesExpected: values[3], AccessSourcesFinalized: values[4],
			ConnectionSourcesExpected: values[5], ConnectionSourcesFinalized: values[6],
			FinalizedThrough: epoch, SourceWatermark: epoch, MissingWindows: make([]time.Time, len(missingWindows)),
		}
		for index, window := range missingWindows {
			evidence.MissingWindows[index] = window.UTC()
		}
		if finalizedThrough != nil {
			evidence.FinalizedThrough = finalizedThrough.UTC()
		}
		if sourceWatermark != nil {
			evidence.SourceWatermark = sourceWatermark.UTC()
		}
		return evidence, nil
	}
	// Zero sources are accepted only as a proven-empty aggregate: no expected
	// events and no access or connection source in any requested window.
	provenEmpty := values[0] == 0 && values[3] == 0 && values[5] == 0
	if values[2] != values[1] || !complete ||
		(values[3] == 0 || values[5] == 0) && !provenEmpty || values[4] != values[3] || values[6] != values[5] ||
		finalizedThrough == nil || sourceWatermark == nil || finalizedThrough.IsZero() || sourceWatermark.IsZero() ||
		finalizedThrough.Before(filter.To) || sourceWatermark.Before(filter.To) {
		return RealtimeExpectedEvidence{}, ErrRealtimeEvidenceUnavailable
	}
	return RealtimeExpectedEvidence{
		TenantID: scope.tenantID, From: filter.From, To: filter.To, SiteID: filter.SiteID, Host: filter.Host, ListenPort: filter.ListenPort,
		ExpectedEvents: values[0], RequestedWindows: uint16(values[1]), CoveredWindows: uint16(values[2]),
		AccessSourcesExpected: values[3], AccessSourcesFinalized: values[4],
		ConnectionSourcesExpected: values[5], ConnectionSourcesFinalized: values[6],
		FinalizedThrough: finalizedThrough.UTC(), SourceWatermark: sourceWatermark.UTC(),
	}, nil
}

// Missing windows must be strictly increasing hour starts inside the
// enclosing coverage interval.
func validRealtimeMissingWindows(windows []time.Time, coverage RealtimeFilter) bool {
	for index, window := range windows {
		window = window.UTC()
		if !window.Equal(window.Truncate(time.Hour)) || window.Before(coverage.From) || !window.Before(coverage.To) ||
			index > 0 && !windows[index-1].Before(window) {
			return false
		}
	}
	return true
}

func (reader *PostgresRealtimeExpectedCountReader) RealtimeV2Coverage(
	ctx context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) (RealtimeV2CoverageAuthority, error) {
	if reader == nil || reader.queryer == nil || ctx == nil || !validRealtimeV2CoverageInput(scope, filter) {
		return RealtimeV2CoverageAuthority{}, analyticsrealtime.ErrInvalidRequest
	}
	from := filter.From.Truncate(time.Hour)
	to := filter.To.Truncate(time.Hour)
	if !filter.To.Equal(to) {
		to = to.Add(time.Hour)
	}
	var encodedRequested, encodedCovered, encodedExpectedDimensions, encodedCoveredDimensions string
	var encodedAccessExpected, encodedAccessFinalized, encodedConnectionExpected, encodedConnectionFinalized string
	var complete bool
	var finalizedThrough, sourceWatermark *time.Time
	err := reader.queryer.QueryRow(ctx, realtimeV2CoverageSQL,
		scope.TenantID, from, to, filter.SiteID, filter.Domain, filter.ListenPort).Scan(
		&encodedRequested, &encodedCovered, &complete, &encodedExpectedDimensions, &encodedCoveredDimensions,
		&encodedAccessExpected, &encodedAccessFinalized, &encodedConnectionExpected, &encodedConnectionFinalized,
		&finalizedThrough, &sourceWatermark)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return RealtimeV2CoverageAuthority{}, err
		}
		return RealtimeV2CoverageAuthority{}, fmt.Errorf("%w: realtime coverage authority unavailable", analyticsrealtime.ErrDependencyUnavailable)
	}
	values := make([]uint64, 8)
	for index, encoded := range []string{
		encodedRequested, encodedCovered, encodedExpectedDimensions, encodedCoveredDimensions,
		encodedAccessExpected, encodedAccessFinalized, encodedConnectionExpected, encodedConnectionFinalized,
	} {
		values[index], err = strconv.ParseUint(encoded, 10, 64)
		if err != nil {
			return RealtimeV2CoverageAuthority{}, analyticsrealtime.ErrDependencyUnavailable
		}
	}
	if values[0] == 0 || values[0] > maximumRealtimePoints || values[1] != values[0] || !complete ||
		values[2] == 0 || values[3] != values[2] || values[4] == 0 || values[5] != values[4] ||
		values[6] == 0 || values[7] != values[6] || finalizedThrough == nil || sourceWatermark == nil {
		return RealtimeV2CoverageAuthority{}, analyticsrealtime.ErrDependencyUnavailable
	}
	finalizedThroughUTC, sourceWatermarkUTC := finalizedThrough.UTC(), sourceWatermark.UTC()
	if finalizedThroughUTC.IsZero() || sourceWatermarkUTC.IsZero() ||
		finalizedThroughUTC.Before(to) || sourceWatermarkUTC.Before(to) {
		return RealtimeV2CoverageAuthority{}, analyticsrealtime.ErrDependencyUnavailable
	}
	return RealtimeV2CoverageAuthority{
		TenantID: scope.TenantID, From: filter.From, To: filter.To, SiteID: filter.SiteID,
		Domain: filter.Domain, ListenPort: filter.ListenPort,
		RequestedWindows: uint16(values[0]), CoveredWindows: uint16(values[1]),
		ExpectedDimensions: values[2], CoveredDimensions: values[3],
		AccessSourcesExpected: values[4], AccessSourcesFinalized: values[5],
		ConnectionSourcesExpected: values[6], ConnectionSourcesFinalized: values[7],
		FinalizedThrough: finalizedThroughUTC, SourceWatermark: sourceWatermarkUTC,
	}, nil
}

func validRealtimeV2CoverageInput(scope analyticsrealtime.Scope, filter analyticsrealtime.Filter) bool {
	if !validUUID(scope.TenantID) || strings.ToLower(scope.TenantID) != scope.TenantID || filter.From.IsZero() ||
		filter.To.IsZero() || filter.From.Location() != time.UTC || filter.To.Location() != time.UTC ||
		!filter.From.Equal(filter.From.Truncate(time.Millisecond)) || !filter.To.Equal(filter.To.Truncate(time.Millisecond)) ||
		!filter.From.Before(filter.To) || filter.To.Sub(filter.From) > 31*24*time.Hour ||
		filter.SiteID != "" && (!validUUID(filter.SiteID) || strings.ToLower(filter.SiteID) != filter.SiteID) {
		return false
	}
	return filter.Domain == "" || validConnectionDomain(filter.Domain)
}
