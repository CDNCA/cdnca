package analytics

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

type PackageUsageBucket string

const (
	PackageUsageBucketHour    PackageUsageBucket = "hour"
	PackageUsageBucketDay     PackageUsageBucket = "day"
	maximumPackageUsagePoints                    = 168
)

// Package usage reads the 400-day package facts (package_metric_access_facts_v1),
// not raw access_events whose TTL follows access_logs_days (default 7 days):
// a billing period older than the access log retention keeps its usage.
const packageUsageSnapshotSQL = `WITH now64(3, 'UTC') AS snapshot
SELECT
    toInt64(toUnixTimestamp64Milli(greatest(snapshot, coalesce(access.last_ingested_at, snapshot)))) AS access_snapshot_ms,
    toInt64(toUnixTimestamp64Milli(greatest(snapshot, coalesce(connection.last_updated_at, snapshot)))) AS connection_snapshot_ms
FROM (
    SELECT max(ingested_at) AS last_ingested_at FROM package_metric_access_facts_v1 FINAL
    WHERE metric_version=1 AND tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
) AS access
CROSS JOIN (
    SELECT max(updated_at) AS last_updated_at FROM connections_ingest_receipts_v1 FINAL
    WHERE schema_version=1 AND tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
) AS connection
FORMAT JSONEachRow`

// packageUsageL4FactsSQL: the billed L4 usage attributed to the
// subscription (package_l4_traffic.go: end facts' remainder and in-progress
// checkpoints, L4-USAGE-01). Forwards belong to no site: a site filter
// selects none.
var packageUsageL4FactsSQL = `SELECT at, up + down AS traffic FROM (` + l4UsageRowsSQL(l4FinalizedWindowSQL,
	"{has_site:UInt8}=0 AND tenant_id={l4_tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}") + `)`

const packageUsageAccessWhereSQL = `metric_version=1 AND tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
      AND ingested_at<=fromUnixTimestamp64Milli({access_snapshot_ms:Int64}, 'UTC')
      AND ({has_site:UInt8}=0 OR site_id={site_id:UUID})`

var packageUsageSummarySQL = `WITH
access AS (
    SELECT occurred_at, request_bytes + response_bytes AS total_bytes
    FROM package_metric_access_facts_v1 FINAL
    WHERE ` + packageUsageAccessWhereSQL + `
      AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<{to:DateTime64(3,'UTC')}
),
spread AS (
    SELECT ` + bandwidthSpreadColumns() + `
    FROM package_metric_access_facts_v1 FINAL
    WHERE ` + packageUsageAccessWhereSQL + `
      AND ` + bandwidthSpreadScanSQL("from", "to") + `
),
peak_samples AS (` + bandwidthSpreadSamplesSQL("SELECT e, d, b FROM spread", "from", "to", bandwidthPeakSampleMS) + `),
p95_samples AS (` + bandwidthSpreadSamplesSQL("SELECT e, d, b FROM spread", "from", "to", bandwidth95SampleMS) + `),
connections AS (
    SELECT connections, source_watermark, finalized_through
    FROM connections_ingest_receipts_v1 FINAL
    WHERE schema_version=1 AND state_rank>=2 AND tenant_id={tenant_id:UUID}
      AND package_subscription_id={subscription_id:UUID}
      AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<{to:DateTime64(3,'UTC')}
      AND updated_at<=fromUnixTimestamp64Milli({connection_snapshot_ms:Int64}, 'UTC')
      AND ({has_site:UInt8}=0 OR site_id={site_id:UUID})
),
l4 AS (` + packageUsageL4FactsSQL + `)
SELECT
    toUInt64(coalesce((SELECT sum(total_bytes) FROM access),0)) AS traffic_bytes,
    toUInt64(coalesce((SELECT sum(traffic) FROM l4),0)) AS l4_traffic_bytes,
    coalesce((SELECT ` + bandwidthSpreadBPSSQL("max(v)", bandwidthPeakSampleMS) + ` FROM peak_samples),toUInt64(0)) AS peak_bandwidth_bps,
    least(
        coalesce((SELECT ` + bandwidthSpreadBPSSQL("quantileExactWeighted(0.95)(v, w)", bandwidth95SampleMS) + ` FROM p95_samples),toUInt64(0)),
        coalesce((SELECT ` + bandwidthSpreadBPSSQL("max(v)", bandwidthPeakSampleMS) + ` FROM peak_samples),toUInt64(0))
    ) AS bandwidth_95th_bps,
    toUInt64(coalesce((SELECT max(connections) FROM connections),0)) AS connections,
    toUInt64(coalesce((SELECT max(source_watermark) FROM connections),0)) AS source_watermark,
    toInt64(toUnixTimestamp64Milli(least(
        coalesce((SELECT maxOrNull(occurred_at) FROM access),{to:DateTime64(3,'UTC')}),
        coalesce((SELECT maxOrNull(finalized_through) FROM connections),{to:DateTime64(3,'UTC')})
    ))) AS finalized_through_ms
FORMAT JSONEachRow`

func packageUsageSeriesSQL(interval string, seconds int) string {
	return fmt.Sprintf(`WITH
access AS (
    SELECT toStartOfInterval(occurred_at, INTERVAL 1 %[1]s, {timezone:String}) AS bucket,
           sum(request_bytes + response_bytes) AS traffic_bytes, toUInt64(ceil(sum(response_bytes)*8.0/%[2]d.0)) AS bandwidth_bps
    FROM package_metric_access_facts_v1 FINAL
    WHERE %[3]s
      AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<{to:DateTime64(3,'UTC')}
    GROUP BY bucket
), connections AS (
    SELECT toStartOfInterval(occurred_at, INTERVAL 1 %[1]s, {timezone:String}) AS bucket, max(connections) AS connections
    FROM connections_ingest_receipts_v1 FINAL
    WHERE schema_version=1 AND state_rank>=2 AND tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
      AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<{to:DateTime64(3,'UTC')}
      AND updated_at<=fromUnixTimestamp64Milli({connection_snapshot_ms:Int64}, 'UTC')
      AND ({has_site:UInt8}=0 OR site_id={site_id:UUID})
    GROUP BY bucket
), l4 AS (
    SELECT toStartOfInterval(at, INTERVAL 1 %[1]s, {timezone:String}) AS bucket, sum(traffic) AS l4_traffic_bytes
    FROM (%[4]s) GROUP BY bucket
), buckets AS (
    SELECT bucket FROM access UNION DISTINCT SELECT bucket FROM connections UNION DISTINCT SELECT bucket FROM l4
)
SELECT toInt64(toUnixTimestamp(buckets.bucket))*1000 AS bucket_ms,
       toUInt64(coalesce(access.traffic_bytes,0)) AS traffic_bytes,
       toUInt64(coalesce(l4.l4_traffic_bytes,0)) AS l4_traffic_bytes,
       toUInt64(coalesce(access.bandwidth_bps,0)) AS bandwidth_bps,
       toUInt64(coalesce(connections.connections,0)) AS connections
FROM buckets
LEFT JOIN access ON access.bucket=buckets.bucket
LEFT JOIN connections ON connections.bucket=buckets.bucket
LEFT JOIN l4 ON l4.bucket=buckets.bucket
WHERE ({has_after:UInt8}=0 OR buckets.bucket>fromUnixTimestamp64Milli({after_ms:Int64}, 'UTC'))
ORDER BY buckets.bucket LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`, interval, seconds, packageUsageAccessWhereSQL, packageUsageL4FactsSQL)
}

var (
	packageUsageSeriesHourSQL = packageUsageSeriesSQL("HOUR", 3600)
	packageUsageSeriesDaySQL  = packageUsageSeriesSQL("DAY", 86400)
)

type PackageUsageRequest struct {
	TenantScopeID, SubscriptionID, SiteID  string
	From, To, AfterBucket                  time.Time
	AccessSnapshotAt, ConnectionSnapshotAt time.Time
	Timezone                               string
	Bucket                                 PackageUsageBucket
	Limit                                  int
	// L4TenantID is the scope's tenants.id, which L4 session facts carry;
	// "" leaves out L4 bytes (none with a site filter either).
	L4TenantID string
}

// PackageUsagePoint / PackageUsageResult: TrafficBytes is the total billed
// against the monthly traffic, HTTPTrafficBytes + L4TrafficBytes.
type PackageUsagePoint struct {
	Bucket                                  time.Time `json:"bucket"`
	TrafficBytes, BandwidthBPS, Connections uint64
	HTTPTrafficBytes, L4TrafficBytes        uint64
}

type PackageUsageResult struct {
	MetricSchemaVersion                                                            string
	TrafficBytes, PeakBandwidthBPS, Bandwidth95thBPS, Connections, SourceWatermark uint64
	HTTPTrafficBytes, L4TrafficBytes                                               uint64
	FinalizedThrough, AccessSnapshotAt, ConnectionSnapshotAt                       time.Time
	Delayed, HasMore                                                               bool
	Series                                                                         []PackageUsagePoint
}

type packageUsageSnapshotRow struct {
	AccessSnapshotMS     int64 `json:"access_snapshot_ms"`
	ConnectionSnapshotMS int64 `json:"connection_snapshot_ms"`
}
type packageUsageSummaryRow struct {
	TrafficBytes       uint64 `json:"traffic_bytes"`
	L4TrafficBytes     uint64 `json:"l4_traffic_bytes"`
	PeakBandwidthBPS   uint64 `json:"peak_bandwidth_bps"`
	Bandwidth95thBPS   uint64 `json:"bandwidth_95th_bps"`
	Connections        uint64 `json:"connections"`
	SourceWatermark    uint64 `json:"source_watermark"`
	FinalizedThroughMS int64  `json:"finalized_through_ms"`
}
type packageUsageSeriesRow struct {
	BucketMS       int64  `json:"bucket_ms"`
	TrafficBytes   uint64 `json:"traffic_bytes"`
	L4TrafficBytes uint64 `json:"l4_traffic_bytes"`
	BandwidthBPS   uint64 `json:"bandwidth_bps"`
	Connections    uint64 `json:"connections"`
}

func (client *Client) PackageUsage(ctx context.Context, request PackageUsageRequest) (PackageUsageResult, error) {
	if !validPackageUsageRequest(client, ctx, request) {
		return PackageUsageResult{}, ErrInvalidInput
	}
	tenantID, err := client.tenantOfScope(ctx, request.TenantScopeID)
	if err != nil {
		return PackageUsageResult{}, err
	}
	parameters := url.Values{
		"param_tenant_id": {tenantID}, "param_subscription_id": {request.SubscriptionID},
		"param_site_id": {orNilUUID(request.SiteID)}, "param_has_site": {packageUsageBoolParameter(request.SiteID != "")},
		"param_from": {clickHouseTime(request.From)}, "param_to": {clickHouseTime(request.To)},
		"param_timezone": {request.Timezone},
	}
	setPackageL4Parameters(parameters, request.L4TenantID)
	accessSnapshot, connectionSnapshot := request.AccessSnapshotAt, request.ConnectionSnapshotAt
	if accessSnapshot.IsZero() {
		rows, err := queryRows[packageUsageSnapshotRow](client, ctx, packageUsageSnapshotSQL, parameters, 1)
		if err != nil || len(rows) != 1 || rows[0].AccessSnapshotMS <= 0 || rows[0].ConnectionSnapshotMS <= 0 {
			if err != nil {
				return PackageUsageResult{}, err
			}
			return PackageUsageResult{}, ErrInvalidResponse
		}
		accessSnapshot, connectionSnapshot = time.UnixMilli(rows[0].AccessSnapshotMS).UTC(), time.UnixMilli(rows[0].ConnectionSnapshotMS).UTC()
	}
	parameters.Set("param_access_snapshot_ms", strconv.FormatInt(accessSnapshot.UnixMilli(), 10))
	parameters.Set("param_connection_snapshot_ms", strconv.FormatInt(connectionSnapshot.UnixMilli(), 10))
	summaryRows, err := queryRows[packageUsageSummaryRow](client, ctx, packageUsageSummarySQL, parameters, 1)
	if err != nil || len(summaryRows) != 1 {
		if err != nil {
			return PackageUsageResult{}, err
		}
		return PackageUsageResult{}, ErrInvalidResponse
	}
	parameters.Set("param_has_after", packageUsageBoolParameter(!request.AfterBucket.IsZero()))
	parameters.Set("param_after_ms", strconv.FormatInt(request.AfterBucket.UnixMilli(), 10))
	parameters.Set("param_row_limit", strconv.Itoa(request.Limit+1))
	seriesSQL := packageUsageSeriesHourSQL
	if request.Bucket == PackageUsageBucketDay {
		seriesSQL = packageUsageSeriesDaySQL
	}
	seriesRows, err := queryRows[packageUsageSeriesRow](client, ctx, seriesSQL, parameters, request.Limit+1)
	if err != nil {
		return PackageUsageResult{}, err
	}
	hasMore := len(seriesRows) > request.Limit
	if hasMore {
		seriesRows = seriesRows[:request.Limit]
	}
	series := make([]PackageUsagePoint, len(seriesRows))
	for index, row := range seriesRows {
		bucket := time.UnixMilli(row.BucketMS).UTC()
		if bucket.Before(request.From.Add(-24*time.Hour)) || !bucket.Before(request.To) || index > 0 && !series[index-1].Bucket.Before(bucket) {
			return PackageUsageResult{}, ErrInvalidResponse
		}
		total, ok := addTraffic(row.TrafficBytes, row.L4TrafficBytes)
		if !ok {
			return PackageUsageResult{}, ErrInvalidResponse
		}
		series[index] = PackageUsagePoint{Bucket: bucket, TrafficBytes: total, HTTPTrafficBytes: row.TrafficBytes,
			L4TrafficBytes: row.L4TrafficBytes, BandwidthBPS: row.BandwidthBPS, Connections: row.Connections}
	}
	summary := summaryRows[0]
	finalized := time.UnixMilli(summary.FinalizedThroughMS).UTC()
	if finalized.After(request.To) || finalized.Before(request.From.Add(-time.Millisecond)) {
		return PackageUsageResult{}, ErrInvalidResponse
	}
	total, ok := addTraffic(summary.TrafficBytes, summary.L4TrafficBytes)
	if !ok {
		return PackageUsageResult{}, ErrInvalidResponse
	}
	return PackageUsageResult{
		MetricSchemaVersion: "package-usage/v1", TrafficBytes: total,
		HTTPTrafficBytes: summary.TrafficBytes, L4TrafficBytes: summary.L4TrafficBytes,
		PeakBandwidthBPS: summary.PeakBandwidthBPS, Bandwidth95thBPS: summary.Bandwidth95thBPS,
		Connections: summary.Connections, SourceWatermark: summary.SourceWatermark,
		FinalizedThrough: finalized, Delayed: finalized.Before(request.To), AccessSnapshotAt: accessSnapshot,
		ConnectionSnapshotAt: connectionSnapshot, Series: series, HasMore: hasMore,
	}, nil
}

func validPackageUsageRequest(client *Client, ctx context.Context, request PackageUsageRequest) bool {
	if client == nil || ctx == nil || !validUUID(request.TenantScopeID) || nilUUID(request.TenantScopeID) ||
		!validUUID(request.SubscriptionID) || nilUUID(request.SubscriptionID) || !validOptionalUUID(request.SiteID) ||
		!validL4TenantID(request.L4TenantID) ||
		request.From.IsZero() || request.To.IsZero() || request.From.Location() != time.UTC || request.To.Location() != time.UTC ||
		!request.From.Before(request.To) || request.To.Sub(request.From) > packageMetricFactRetention ||
		request.From.Nanosecond()%int(time.Millisecond) != 0 || request.To.Nanosecond()%int(time.Millisecond) != 0 ||
		request.Limit < 1 || request.Limit > maximumPackageUsagePoints ||
		(request.Bucket != PackageUsageBucketHour && request.Bucket != PackageUsageBucketDay) {
		return false
	}
	if _, err := time.LoadLocation(request.Timezone); err != nil || len(request.Timezone) > 64 {
		return false
	}
	hasAfter := !request.AfterBucket.IsZero()
	hasSnapshots := !request.AccessSnapshotAt.IsZero() && !request.ConnectionSnapshotAt.IsZero()
	if hasAfter != hasSnapshots || request.AccessSnapshotAt.IsZero() != request.ConnectionSnapshotAt.IsZero() {
		return false
	}
	for _, value := range []time.Time{request.AfterBucket, request.AccessSnapshotAt, request.ConnectionSnapshotAt} {
		if !value.IsZero() && (value.Location() != time.UTC || value.Nanosecond()%int(time.Millisecond) != 0) {
			return false
		}
	}
	return !hasAfter || (!request.AfterBucket.Before(request.From.Add(-24*time.Hour)) && request.AfterBucket.Before(request.To))
}

func packageUsageBoolParameter(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// addTraffic is HTTP + L4 bytes, false on overflow.
func addTraffic(http, l4 uint64) (uint64, bool) {
	total := http + l4
	return total, total >= http
}
