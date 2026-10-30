package analytics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
)

const realtimeV2MaximumPoints = 240

const realtimeV2AccessSQL = `WITH access AS
(
    SELECT facts.*, events.node_id AS node_id
    FROM site_realtime_access_facts_v1 FINAL AS facts
    INNER JOIN access_events FINAL AS events
        ON events.tenant_id = facts.tenant_id
        AND events.event_id = facts.event_id
        AND events.ingested_at = facts.ingested_at
    WHERE facts.metric_version = 1 AND events.metric_version = 1
        AND facts.ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
        AND events.ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
        AND facts.occurred_at >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND facts.occurred_at < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND facts.tenant_id = {tenant_id:UUID}
        AND ({has_site:UInt8} = 0 OR facts.site_id = {site_id:UUID})
        AND ({has_node:UInt8} = 0 OR events.node_id = {node_id:UUID})
        AND ({has_domain:UInt8} = 0 OR facts.host = {domain:String})
        AND ({has_port:UInt8} = 0 OR facts.listen_port = {listen_port:UInt16})
)
`

const realtimeV2SnapshotSQL = realtimeV2AccessSQL + `
,
connections AS
(
    SELECT updated_at AS snapshot_at
    FROM connections_ingest_receipts_v1 FINAL
    WHERE schema_version IN (1,2) AND state_rank >= 2
        AND updated_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
        AND occurred_at >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND occurred_at < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND tenant_id = {tenant_id:UUID}
        AND ({has_site:UInt8} = 0 OR site_id = {site_id:UUID})
        AND ({has_node:UInt8} = 0 OR node_id = {node_id:UUID})
        AND ({has_domain:UInt8} = 0 OR domain = {domain:String})
        AND ({has_port:UInt8} = 0 OR listen_port = {listen_port:UInt16})
        AND node_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND domain != ''
        AND listen_port BETWEEN 1 AND 65535
        AND source_watermark > 0
        AND finalized_through <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
),
snapshot_facts AS
(
    SELECT ingested_at AS snapshot_at FROM access
    UNION ALL
    SELECT snapshot_at FROM connections
)
SELECT
    toInt64(toUnixTimestamp64Milli(max(snapshot_at))) AS snapshot_ms,
    toInt64(toUnixTimestamp64Milli(now64(3, 'UTC')) + 300000) AS expires_at_ms
FROM snapshot_facts
FORMAT JSONEachRow`

const realtimeV2BasicSQL = realtimeV2AccessSQL + `,
connections AS
(
    SELECT *
    FROM connections_ingest_receipts_v1 FINAL
    WHERE schema_version IN (1,2) AND state_rank >= 2
        AND updated_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
        AND occurred_at >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND occurred_at < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND tenant_id = {tenant_id:UUID}
        AND ({has_site:UInt8} = 0 OR site_id = {site_id:UUID})
        AND ({has_node:UInt8} = 0 OR node_id = {node_id:UUID})
        AND ({has_domain:UInt8} = 0 OR domain = {domain:String})
        AND ({has_port:UInt8} = 0 OR listen_port = {listen_port:UInt16})
        AND node_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND domain != ''
        AND listen_port BETWEEN 1 AND 65535
        AND source_watermark > 0
        AND finalized_through <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
)
SELECT 'summary' AS kind, {snapshot_ms:UInt64} AS snapshot_ms, NULL AS bucket_ms,
    toUInt64(count()) AS fact_count, toUInt64(count()) AS requests,
    toUInt64(sum(toUInt128(request_bytes) + toUInt128(response_bytes))) AS traffic_bytes,
    sum(toUInt128(request_bytes) + toUInt128(response_bytes)) * 8.0 / ({to_ms:UInt64} - {from_ms:UInt64}) * 1000.0 AS bandwidth_bps,
    (SELECT max(connections) FROM connections) AS connections,
    toInt64(toUnixTimestamp64Milli((SELECT max(finalized_through) FROM connections))) AS connection_finalized_through_ms
FROM access
UNION ALL
SELECT 'series', {snapshot_ms:UInt64}, toInt64(toUnixTimestamp64Milli(toStartOfInterval(
        occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
        fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String}))),
    NULL, toUInt64(count()), toUInt64(sum(toUInt128(request_bytes) + toUInt128(response_bytes))),
    sum(toUInt128(request_bytes) + toUInt128(response_bytes)) * 8.0 / {bucket_ms:UInt64} * 1000.0,
    (SELECT max(connections) FROM connections AS receipt
        WHERE toStartOfInterval(receipt.occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
                  fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String}) =
              toStartOfInterval(access.occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
                  fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String})), NULL
FROM access
GROUP BY toStartOfInterval(occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
    fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String})
ORDER BY kind, bucket_ms
FORMAT JSONEachRow`

const realtimeV2QualitySQL = realtimeV2AccessSQL + `
SELECT 'summary' AS kind, {snapshot_ms:UInt64} AS snapshot_ms, NULL AS bucket_ms,
    toUInt64(count()) AS fact_count,
    toUInt64(countIf(status_code >= 200 AND status_code < 300)) AS status_2xx,
    toUInt64(countIf(status_code >= 300 AND status_code < 400)) AS status_3xx,
    toUInt64(countIf(status_code >= 400 AND status_code < 500)) AS status_4xx,
    toUInt64(countIf(status_code >= 500 AND status_code < 600)) AS status_5xx,
    toUInt64(countIf(lower(cache_status) = 'hit')) AS cache_hits,
    toUInt64(countIf(lower(cache_status) = 'miss')) AS cache_misses,
    toUInt64(countIf(status_code >= 500 OR upstream_result != '')) AS errors,
    avg(duration_us) AS average_duration_us
FROM access
UNION ALL
SELECT 'series', {snapshot_ms:UInt64}, toInt64(toUnixTimestamp64Milli(toStartOfInterval(
        occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
        fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String}))), NULL,
    toUInt64(countIf(status_code >= 200 AND status_code < 300)),
    toUInt64(countIf(status_code >= 300 AND status_code < 400)),
    toUInt64(countIf(status_code >= 400 AND status_code < 500)),
    toUInt64(countIf(status_code >= 500 AND status_code < 600)), NULL, NULL, NULL, NULL
FROM access
GROUP BY toStartOfInterval(occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
    fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String})
ORDER BY kind, bucket_ms
FORMAT JSONEachRow`

const realtimeV2OriginSQL = realtimeV2AccessSQL + `
SELECT 'summary' AS kind, {snapshot_ms:UInt64} AS snapshot_ms, NULL AS bucket_ms,
    toUInt64(count()) AS fact_count, avg(origin_connect_us) AS connect_us,
    avg(origin_first_byte_us) AS first_byte_us, avg(origin_total_us) AS total_us
FROM access
UNION ALL
SELECT 'series', {snapshot_ms:UInt64}, toInt64(toUnixTimestamp64Milli(toStartOfInterval(
        occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
        fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String}))), NULL,
    avg(origin_connect_us), avg(origin_first_byte_us), avg(origin_total_us)
FROM access
GROUP BY toStartOfInterval(occurred_at, toIntervalMillisecond({bucket_ms:UInt64}),
    fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC'), {timezone:String})
ORDER BY kind, bucket_ms
FORMAT JSONEachRow`

const realtimeV2RankSQL = realtimeV2AccessSQL + `
SELECT {snapshot_ms:UInt64} AS snapshot_ms, toUInt64(sum(count()) OVER ()) AS fact_count,
    multiIf({rank_by:String} = 'host', host, {rank_by:String} = 'site', toString(site_id),
        {rank_by:String} = 'node', toString(node_id), {rank_by:String} = 'status_code', toString(status_code), '') AS key,
    key AS label, toUInt64(count()) AS requests,
    toUInt64(sum(toUInt128(request_bytes) + toUInt128(response_bytes))) AS traffic_bytes
FROM access
GROUP BY key
HAVING {has_after:UInt8} = 0 OR traffic_bytes < {after_traffic:UInt64}
    OR (traffic_bytes = {after_traffic:UInt64} AND requests < {after_requests:UInt64})
    OR (traffic_bytes = {after_traffic:UInt64} AND requests = {after_requests:UInt64} AND key > {after_key:String})
ORDER BY traffic_bytes DESC, requests DESC, key ASC
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

type RealtimeV2Source struct {
	client   *Client
	coverage RealtimeV2CoverageReader
}

func NewRealtimeV2Source(client *Client, coverage RealtimeV2CoverageReader) (*RealtimeV2Source, error) {
	if client == nil || coverage == nil {
		return nil, analyticsrealtime.ErrInvalidConfig
	}
	return &RealtimeV2Source{client: client, coverage: coverage}, nil
}

type realtimeV2SnapshotWireRow struct {
	SnapshotMS  *int64 `json:"snapshot_ms"`
	ExpiresAtMS *int64 `json:"expires_at_ms"`
}

func (source *RealtimeV2Source) ResolveSnapshot(
	ctx context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) (analyticsrealtime.Snapshot, error) {
	if err := source.valid(ctx, scope, filter, false); err != nil {
		return analyticsrealtime.Snapshot{}, err
	}
	authority, err := source.coverage.RealtimeV2Coverage(ctx, scope, filter)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return analyticsrealtime.Snapshot{}, err
		}
		return analyticsrealtime.Snapshot{}, fmt.Errorf("%w: realtime coverage", analyticsrealtime.ErrDependencyUnavailable)
	}
	if !validRealtimeV2CoverageAuthority(authority, scope, filter) {
		return analyticsrealtime.Snapshot{}, analyticsrealtime.ErrDependencyUnavailable
	}
	parameters := realtimeV2Parameters(scope, filter, time.Now().UTC().Truncate(time.Millisecond))
	rows, err := queryRows[realtimeV2SnapshotWireRow](source.client, ctx, realtimeV2SnapshotSQL, parameters, 1)
	if err != nil {
		return analyticsrealtime.Snapshot{}, realtimeV2Error(err)
	}
	if len(rows) != 1 || rows[0].SnapshotMS == nil || rows[0].ExpiresAtMS == nil {
		return analyticsrealtime.Snapshot{}, analyticsrealtime.ErrInvalidSnapshot
	}
	snapshot := analyticsrealtime.Snapshot{
		At: time.UnixMilli(*rows[0].SnapshotMS).UTC(), SourceWatermark: uint64(authority.SourceWatermark.UnixMilli()),
		FinalizedThrough: authority.FinalizedThrough, ExpiresAt: time.UnixMilli(*rows[0].ExpiresAtMS).UTC(),
	}
	if !validRealtimeV2Snapshot(snapshot, filter) {
		return analyticsrealtime.Snapshot{}, analyticsrealtime.ErrInvalidSnapshot
	}
	return snapshot, nil
}

func validRealtimeV2CoverageAuthority(
	authority RealtimeV2CoverageAuthority,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) bool {
	coverageFrom := filter.From.Truncate(time.Hour)
	coverageTo := filter.To.Truncate(time.Hour)
	if !filter.To.Equal(coverageTo) {
		coverageTo = coverageTo.Add(time.Hour)
	}
	windows := coverageTo.Sub(coverageFrom) / time.Hour
	return authority.TenantID == scope.TenantID && authority.From.Equal(filter.From) && authority.To.Equal(filter.To) &&
		authority.SiteID == filter.SiteID && authority.Domain == filter.Domain && authority.ListenPort == filter.ListenPort &&
		windows > 0 && windows <= realtimeV2MaximumPoints && uint64(authority.RequestedWindows) == uint64(windows) &&
		authority.CoveredWindows == authority.RequestedWindows && authority.ExpectedDimensions > 0 &&
		authority.CoveredDimensions == authority.ExpectedDimensions && authority.AccessSourcesExpected > 0 &&
		authority.AccessSourcesFinalized == authority.AccessSourcesExpected && authority.ConnectionSourcesExpected > 0 &&
		authority.ConnectionSourcesFinalized == authority.ConnectionSourcesExpected &&
		authority.FinalizedThrough.Location() == time.UTC && authority.SourceWatermark.Location() == time.UTC &&
		!authority.FinalizedThrough.Before(coverageTo) && !authority.SourceWatermark.Before(coverageTo) &&
		authority.SourceWatermark.UnixMilli() > 0
}

type realtimeV2BasicWireRow struct {
	Kind                         string   `json:"kind"`
	SnapshotMS                   *int64   `json:"snapshot_ms"`
	BucketMS                     *int64   `json:"bucket_ms"`
	FactCount                    *uint64  `json:"fact_count"`
	Requests                     *uint64  `json:"requests"`
	TrafficBytes                 *uint64  `json:"traffic_bytes"`
	BandwidthBPS                 *float64 `json:"bandwidth_bps"`
	Connections                  *uint64  `json:"connections"`
	ConnectionFinalizedThroughMS *int64   `json:"connection_finalized_through_ms"`
}

func (source *RealtimeV2Source) LoadBasic(
	ctx context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) (analyticsrealtime.Basic, error) {
	if err := source.valid(ctx, scope, filter, true); err != nil {
		return analyticsrealtime.Basic{}, err
	}
	rows, err := queryRows[realtimeV2BasicWireRow](source.client, ctx, realtimeV2BasicSQL,
		realtimeV2Parameters(scope, filter, filter.Snapshot.At), realtimeV2RowBudget(filter, 1))
	if err != nil {
		return analyticsrealtime.Basic{}, realtimeV2Error(err)
	}
	var result analyticsrealtime.Basic
	seenSummary := false
	for _, row := range rows {
		if !realtimeV2SnapshotMatches(row.SnapshotMS, filter.Snapshot) {
			return analyticsrealtime.Basic{}, analyticsrealtime.ErrInvalidSnapshot
		}
		switch row.Kind {
		case "summary":
			if row.FactCount != nil && *row.FactCount == 0 {
				return analyticsrealtime.Basic{}, analyticsrealtime.ErrFactsMissing
			}
			if seenSummary || row.FactCount == nil || row.Requests == nil || row.TrafficBytes == nil ||
				row.BandwidthBPS == nil {
				return analyticsrealtime.Basic{}, analyticsrealtime.ErrInvalidResponse
			}
			if row.Connections == nil || row.ConnectionFinalizedThroughMS == nil ||
				time.UnixMilli(*row.ConnectionFinalizedThroughMS).UTC().Before(filter.To) ||
				time.UnixMilli(*row.ConnectionFinalizedThroughMS).UTC().After(filter.Snapshot.At) {
				return analyticsrealtime.Basic{}, analyticsrealtime.ErrDependencyUnavailable
			}
			seenSummary = true
			result.FactCount, result.Requests, result.TrafficBytes = *row.FactCount, *row.Requests, *row.TrafficBytes
			result.BandwidthBPS, result.Connections = *row.BandwidthBPS, *row.Connections
		case "series":
			if row.BucketMS == nil || row.Requests == nil || row.TrafficBytes == nil || row.BandwidthBPS == nil || row.Connections == nil {
				return analyticsrealtime.Basic{}, analyticsrealtime.ErrInvalidResponse
			}
			result.Series = append(result.Series, analyticsrealtime.BasicPoint{
				Bucket: time.UnixMilli(*row.BucketMS).UTC(), Requests: *row.Requests,
				TrafficBytes: *row.TrafficBytes, BandwidthBPS: *row.BandwidthBPS, Connections: *row.Connections,
			})
		default:
			return analyticsrealtime.Basic{}, analyticsrealtime.ErrInvalidResponse
		}
	}
	if !seenSummary || result.FactCount == 0 {
		return analyticsrealtime.Basic{}, analyticsrealtime.ErrFactsMissing
	}
	if !validRealtimeV2Basic(result, filter) {
		return analyticsrealtime.Basic{}, analyticsrealtime.ErrInvalidResponse
	}
	return result, nil
}

type realtimeV2QualityWireRow struct {
	Kind              string   `json:"kind"`
	SnapshotMS        *int64   `json:"snapshot_ms"`
	BucketMS          *int64   `json:"bucket_ms"`
	FactCount         *uint64  `json:"fact_count"`
	Status2xx         *uint64  `json:"status_2xx"`
	Status3xx         *uint64  `json:"status_3xx"`
	Status4xx         *uint64  `json:"status_4xx"`
	Status5xx         *uint64  `json:"status_5xx"`
	CacheHits         *uint64  `json:"cache_hits"`
	CacheMisses       *uint64  `json:"cache_misses"`
	Errors            *uint64  `json:"errors"`
	AverageDurationUS *float64 `json:"average_duration_us"`
}

func (source *RealtimeV2Source) LoadQuality(
	ctx context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) (analyticsrealtime.Quality, error) {
	if err := source.valid(ctx, scope, filter, true); err != nil {
		return analyticsrealtime.Quality{}, err
	}
	rows, err := queryRows[realtimeV2QualityWireRow](source.client, ctx, realtimeV2QualitySQL,
		realtimeV2Parameters(scope, filter, filter.Snapshot.At), realtimeV2RowBudget(filter, 1))
	if err != nil {
		return analyticsrealtime.Quality{}, realtimeV2Error(err)
	}
	var result analyticsrealtime.Quality
	seenSummary := false
	for _, row := range rows {
		if !realtimeV2SnapshotMatches(row.SnapshotMS, filter.Snapshot) {
			return analyticsrealtime.Quality{}, analyticsrealtime.ErrInvalidSnapshot
		}
		switch row.Kind {
		case "summary":
			if row.FactCount != nil && *row.FactCount == 0 {
				return analyticsrealtime.Quality{}, analyticsrealtime.ErrFactsMissing
			}
			if seenSummary || row.FactCount == nil || row.Status2xx == nil || row.Status3xx == nil || row.Status4xx == nil ||
				row.Status5xx == nil || row.CacheHits == nil || row.CacheMisses == nil || row.Errors == nil || row.AverageDurationUS == nil {
				return analyticsrealtime.Quality{}, analyticsrealtime.ErrInvalidResponse
			}
			seenSummary = true
			result.FactCount = *row.FactCount
			result.Status2xx, result.Status3xx, result.Status4xx, result.Status5xx = *row.Status2xx, *row.Status3xx, *row.Status4xx, *row.Status5xx
			result.CacheHits, result.CacheMisses, result.Errors = *row.CacheHits, *row.CacheMisses, *row.Errors
			result.AverageDurationUS = *row.AverageDurationUS
		case "series":
			if row.BucketMS == nil || row.Status2xx == nil || row.Status3xx == nil || row.Status4xx == nil || row.Status5xx == nil {
				return analyticsrealtime.Quality{}, analyticsrealtime.ErrInvalidResponse
			}
			result.Series = append(result.Series, analyticsrealtime.QualityPoint{
				Bucket: time.UnixMilli(*row.BucketMS).UTC(), Status2xx: *row.Status2xx,
				Status3xx: *row.Status3xx, Status4xx: *row.Status4xx, Status5xx: *row.Status5xx,
			})
		default:
			return analyticsrealtime.Quality{}, analyticsrealtime.ErrInvalidResponse
		}
	}
	if !seenSummary || result.FactCount == 0 {
		return analyticsrealtime.Quality{}, analyticsrealtime.ErrFactsMissing
	}
	if !validRealtimeV2Quality(result, filter) {
		return analyticsrealtime.Quality{}, analyticsrealtime.ErrInvalidResponse
	}
	return result, nil
}

type realtimeV2OriginWireRow struct {
	Kind        string   `json:"kind"`
	SnapshotMS  *int64   `json:"snapshot_ms"`
	BucketMS    *int64   `json:"bucket_ms"`
	FactCount   *uint64  `json:"fact_count"`
	ConnectUS   *float64 `json:"connect_us"`
	FirstByteUS *float64 `json:"first_byte_us"`
	TotalUS     *float64 `json:"total_us"`
}

func (source *RealtimeV2Source) LoadOrigin(
	ctx context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) (analyticsrealtime.Origin, error) {
	if err := source.valid(ctx, scope, filter, true); err != nil {
		return analyticsrealtime.Origin{}, err
	}
	rows, err := queryRows[realtimeV2OriginWireRow](source.client, ctx, realtimeV2OriginSQL,
		realtimeV2Parameters(scope, filter, filter.Snapshot.At), realtimeV2RowBudget(filter, 1))
	if err != nil {
		return analyticsrealtime.Origin{}, realtimeV2Error(err)
	}
	var result analyticsrealtime.Origin
	seenSummary := false
	for _, row := range rows {
		if !realtimeV2SnapshotMatches(row.SnapshotMS, filter.Snapshot) {
			return analyticsrealtime.Origin{}, analyticsrealtime.ErrInvalidSnapshot
		}
		if row.Kind == "summary" && row.FactCount != nil && *row.FactCount == 0 {
			return analyticsrealtime.Origin{}, analyticsrealtime.ErrFactsMissing
		}
		if row.ConnectUS == nil || row.FirstByteUS == nil || row.TotalUS == nil {
			return analyticsrealtime.Origin{}, analyticsrealtime.ErrInvalidResponse
		}
		switch row.Kind {
		case "summary":
			if seenSummary || row.FactCount == nil {
				return analyticsrealtime.Origin{}, analyticsrealtime.ErrInvalidResponse
			}
			seenSummary = true
			result.FactCount, result.ConnectUS, result.FirstByteUS, result.TotalUS = *row.FactCount, *row.ConnectUS, *row.FirstByteUS, *row.TotalUS
		case "series":
			if row.BucketMS == nil {
				return analyticsrealtime.Origin{}, analyticsrealtime.ErrInvalidResponse
			}
			result.Series = append(result.Series, analyticsrealtime.OriginPoint{
				Bucket: time.UnixMilli(*row.BucketMS).UTC(), ConnectUS: *row.ConnectUS,
				FirstByteUS: *row.FirstByteUS, TotalUS: *row.TotalUS,
			})
		default:
			return analyticsrealtime.Origin{}, analyticsrealtime.ErrInvalidResponse
		}
	}
	if !seenSummary || result.FactCount == 0 {
		return analyticsrealtime.Origin{}, analyticsrealtime.ErrFactsMissing
	}
	if !validRealtimeV2Origin(result, filter) {
		return analyticsrealtime.Origin{}, analyticsrealtime.ErrInvalidResponse
	}
	return result, nil
}

type realtimeV2RankWireRow struct {
	SnapshotMS   *int64  `json:"snapshot_ms"`
	FactCount    *uint64 `json:"fact_count"`
	Key          *string `json:"key"`
	Label        *string `json:"label"`
	Requests     *uint64 `json:"requests"`
	TrafficBytes *uint64 `json:"traffic_bytes"`
}

func (source *RealtimeV2Source) LoadRank(
	ctx context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) (analyticsrealtime.RankResult, error) {
	if err := source.valid(ctx, scope, filter, true); err != nil {
		return analyticsrealtime.RankResult{}, err
	}
	if filter.Limit == 0 || filter.Limit > 100 {
		return analyticsrealtime.RankResult{}, analyticsrealtime.ErrInvalidRequest
	}
	parameters := realtimeV2Parameters(scope, filter, filter.Snapshot.At)
	parameters.Set("param_rank_by", string(filter.RankBy))
	parameters.Set("param_row_limit", strconv.FormatUint(uint64(filter.Limit+1), 10))
	parameters.Set("param_has_after", "0")
	parameters.Set("param_after_traffic", "0")
	parameters.Set("param_after_requests", "0")
	parameters.Set("param_after_key", "")
	if filter.After != nil {
		parameters.Set("param_has_after", "1")
		parameters.Set("param_after_traffic", strconv.FormatUint(filter.After.TrafficBytes, 10))
		parameters.Set("param_after_requests", strconv.FormatUint(filter.After.Requests, 10))
		parameters.Set("param_after_key", filter.After.Key)
	}
	rows, err := queryRows[realtimeV2RankWireRow](source.client, ctx, realtimeV2RankSQL, parameters, int(filter.Limit)+1)
	if err != nil {
		return analyticsrealtime.RankResult{}, realtimeV2Error(err)
	}
	if len(rows) == 0 {
		return analyticsrealtime.RankResult{}, analyticsrealtime.ErrFactsMissing
	}
	result := analyticsrealtime.RankResult{Items: make([]analyticsrealtime.RankItem, 0, min(len(rows), int(filter.Limit)))}
	for _, row := range rows {
		if !realtimeV2SnapshotMatches(row.SnapshotMS, filter.Snapshot) {
			return analyticsrealtime.RankResult{}, analyticsrealtime.ErrInvalidSnapshot
		}
		if row.FactCount == nil || row.Key == nil || row.Label == nil || row.Requests == nil || row.TrafficBytes == nil ||
			*row.FactCount == 0 || *row.Key == "" || *row.Label == "" || *row.Requests == 0 {
			return analyticsrealtime.RankResult{}, analyticsrealtime.ErrInvalidResponse
		}
		if result.FactCount == 0 {
			result.FactCount = *row.FactCount
		} else if result.FactCount != *row.FactCount {
			return analyticsrealtime.RankResult{}, analyticsrealtime.ErrInvalidResponse
		}
		item := analyticsrealtime.RankItem{Key: *row.Key, Label: *row.Label, Requests: *row.Requests, TrafficBytes: *row.TrafficBytes}
		if len(result.Items) > 0 && !realtimeV2RankBefore(result.Items[len(result.Items)-1], item) {
			return analyticsrealtime.RankResult{}, analyticsrealtime.ErrInvalidResponse
		}
		if len(result.Items) < int(filter.Limit) {
			result.Items = append(result.Items, item)
		}
	}
	result.HasMore = len(rows) > int(filter.Limit)
	return result, nil
}

func (source *RealtimeV2Source) valid(
	ctx context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
	requireSnapshot bool,
) error {
	if source == nil || source.client == nil || source.coverage == nil || ctx == nil ||
		!validUUID(scope.TenantID) || nilUUID(scope.TenantID) {
		return analyticsrealtime.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if filter.From.Location() != time.UTC || filter.To.Location() != time.UTC || !filter.From.Before(filter.To) ||
		filter.Bucket <= 0 || realtimeV2BucketCount(filter) > realtimeV2MaximumPoints || !required(filter.Timezone, 64) ||
		filter.Timezone == "Local" || !validOptionalUUID(filter.SiteID) || !validOptionalUUID(filter.NodeID) ||
		!bounded(filter.Domain, 253) {
		return analyticsrealtime.ErrInvalidRequest
	}
	location, err := time.LoadLocation(filter.Timezone)
	if err != nil || location == time.Local {
		return analyticsrealtime.ErrInvalidRequest
	}
	if requireSnapshot && !validRealtimeV2Snapshot(filter.Snapshot, filter) {
		return analyticsrealtime.ErrInvalidSnapshot
	}
	return nil
}

func realtimeV2Parameters(scope analyticsrealtime.Scope, filter analyticsrealtime.Filter, snapshot time.Time) url.Values {
	siteID, hasSite := optionalUUID(filter.SiteID)
	nodeID, hasNode := optionalUUID(filter.NodeID)
	return url.Values{
		"param_tenant_id":   {strings.ToLower(scope.TenantID)},
		"param_from_ms":     {strconv.FormatInt(filter.From.UnixMilli(), 10)},
		"param_to_ms":       {strconv.FormatInt(filter.To.UnixMilli(), 10)},
		"param_snapshot_ms": {strconv.FormatInt(snapshot.UnixMilli(), 10)},
		"param_timezone":    {filter.Timezone},
		"param_has_site":    {hasSite}, "param_site_id": {siteID},
		"param_has_node": {hasNode}, "param_node_id": {nodeID},
		"param_has_domain": {booleanParameter(filter.Domain != "")}, "param_domain": {strings.ToLower(filter.Domain)},
		"param_has_port":    {booleanParameter(filter.ListenPort != 0)},
		"param_listen_port": {strconv.FormatUint(uint64(filter.ListenPort), 10)},
		"param_bucket_ms":   {strconv.FormatInt(filter.Bucket.Milliseconds(), 10)},
	}
}

func validRealtimeV2Snapshot(snapshot analyticsrealtime.Snapshot, filter analyticsrealtime.Filter) bool {
	return snapshot.SourceWatermark > 0 && snapshot.At.Location() == time.UTC && snapshot.FinalizedThrough.Location() == time.UTC &&
		snapshot.ExpiresAt.Location() == time.UTC && !snapshot.At.IsZero() && snapshot.At.Equal(snapshot.At.Truncate(time.Millisecond)) &&
		snapshot.FinalizedThrough.Equal(snapshot.FinalizedThrough.Truncate(time.Millisecond)) &&
		snapshot.ExpiresAt.Equal(snapshot.ExpiresAt.Truncate(time.Millisecond)) && !snapshot.FinalizedThrough.Before(filter.To) &&
		!snapshot.FinalizedThrough.After(snapshot.At) &&
		snapshot.ExpiresAt.After(snapshot.At)
}

func realtimeV2SnapshotMatches(value *int64, snapshot analyticsrealtime.Snapshot) bool {
	return value != nil && *value == snapshot.At.UnixMilli()
}

func realtimeV2RowBudget(filter analyticsrealtime.Filter, fixed int) int {
	return realtimeV2BucketCount(filter) + fixed
}

func realtimeV2BucketCount(filter analyticsrealtime.Filter) int {
	duration := filter.To.Sub(filter.From)
	return int((duration + filter.Bucket - 1) / filter.Bucket)
}

func validRealtimeV2Basic(result analyticsrealtime.Basic, filter analyticsrealtime.Filter) bool {
	if math.IsNaN(result.BandwidthBPS) || math.IsInf(result.BandwidthBPS, 0) || result.BandwidthBPS < 0 {
		return false
	}
	for index, point := range result.Series {
		var previous time.Time
		if index > 0 {
			previous = result.Series[index-1].Bucket
		}
		if !validRealtimeV2Bucket(point.Bucket, filter, index, previous) ||
			math.IsNaN(point.BandwidthBPS) || math.IsInf(point.BandwidthBPS, 0) || point.BandwidthBPS < 0 {
			return false
		}
	}
	return true
}

func validRealtimeV2Quality(result analyticsrealtime.Quality, filter analyticsrealtime.Filter) bool {
	if math.IsNaN(result.AverageDurationUS) || math.IsInf(result.AverageDurationUS, 0) || result.AverageDurationUS < 0 {
		return false
	}
	for index, point := range result.Series {
		var previous time.Time
		if index > 0 {
			previous = result.Series[index-1].Bucket
		}
		if !validRealtimeV2Bucket(point.Bucket, filter, index, previous) {
			return false
		}
	}
	return true
}

func validRealtimeV2Origin(result analyticsrealtime.Origin, filter analyticsrealtime.Filter) bool {
	if !validRealtimeV2Timing(result.ConnectUS, result.FirstByteUS, result.TotalUS) {
		return false
	}
	for index, point := range result.Series {
		var previous time.Time
		if index > 0 {
			previous = result.Series[index-1].Bucket
		}
		if !validRealtimeV2Bucket(point.Bucket, filter, index, previous) ||
			!validRealtimeV2Timing(point.ConnectUS, point.FirstByteUS, point.TotalUS) {
			return false
		}
	}
	return true
}

func validRealtimeV2Bucket(bucket time.Time, filter analyticsrealtime.Filter, index int, previous time.Time) bool {
	return bucket.Location() == time.UTC && !bucket.Before(filter.From) && bucket.Before(filter.To) &&
		bucket.Sub(filter.From)%filter.Bucket == 0 && (index == 0 || previous.Before(bucket))
}

func validRealtimeV2Timing(connect, firstByte, total float64) bool {
	return !math.IsNaN(connect) && !math.IsInf(connect, 0) && !math.IsNaN(firstByte) && !math.IsInf(firstByte, 0) &&
		!math.IsNaN(total) && !math.IsInf(total, 0) && connect >= 0 && connect <= firstByte && firstByte <= total
}

func realtimeV2RankBefore(previous, current analyticsrealtime.RankItem) bool {
	if previous.TrafficBytes != current.TrafficBytes {
		return previous.TrafficBytes > current.TrafficBytes
	}
	if previous.Requests != current.Requests {
		return previous.Requests > current.Requests
	}
	return previous.Key < current.Key
}

func realtimeV2Error(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var storageError *HTTPError
	if errors.Is(err, ErrTransport) || errors.As(err, &storageError) {
		return fmt.Errorf("%w: analytics storage", analyticsrealtime.ErrDependencyUnavailable)
	}
	return analyticsrealtime.ErrInvalidResponse
}
