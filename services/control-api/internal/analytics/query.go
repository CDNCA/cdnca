package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const packageMetricFactRetention = 400 * 24 * time.Hour

const packageMetricSQL = `SELECT
    if(
        {metric:String}='traffic_bytes',
        if(sum(toUInt128(request_bytes)+toUInt128(response_bytes))>18446744073709551615,NULL,
           toUInt64(sum(toUInt128(request_bytes)+toUInt128(response_bytes)))),
        if(ceil(sum(toUInt128(response_bytes))*8.0/dateDiff('millisecond',
           {period_start:DateTime64(3,'UTC')},{period_end:DateTime64(3,'UTC')})*1000.0)>18446744073709551615,NULL,
           toUInt64(ceil(sum(toUInt128(response_bytes))*8.0/dateDiff('millisecond',
           {period_start:DateTime64(3,'UTC')},{period_end:DateTime64(3,'UTC')})*1000.0)))
    ) AS value,
    -- occurred_at is not Nullable: max() over no rows is the epoch, not NULL.
    toInt64(toUnixTimestamp64Milli(if(count()=0,{period_end:DateTime64(3,'UTC')},max(occurred_at)))) AS observed_at_ms,
    toInt64(toUnixTimestamp64Milli({period_end:DateTime64(3,'UTC')})) AS finalized_through_ms,
    lower(hex(SHA256(toJSONString(tuple(
        {tenant_id:UUID},{subscription_id:UUID},{metric:String},
        {period_start:DateTime64(3,'UTC')},{period_end:DateTime64(3,'UTC')},
        count(),uniqExact(event_id),sum(toUInt128(request_bytes)),sum(toUInt128(response_bytes)),
        min(event_id),max(event_id),groupBitXor(cityHash64(tuple(
            installation_id,event_id,occurred_at,request_bytes,response_bytes,ingested_at))),max(ingested_at)
    ))))) AS source_evidence_digest
FROM package_metric_access_facts_v1 FINAL
WHERE tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
  AND occurred_at>={period_start:DateTime64(3,'UTC')}
  AND occurred_at<{period_end:DateTime64(3,'UTC')}
  AND NOT ({exclude_blocked:UInt8}=1 AND blocked)
FORMAT JSONEachRow`

const connectionsPackageMetricSQL = `SELECT
    if(count()=0,NULL,toUInt64(max(active_connections))) AS value,
    if(count()=0,NULL,toInt64(toUnixTimestamp64Milli(max(sampled_at)))) AS observed_at_ms,
    if(count()=0,NULL,toInt64(toUnixTimestamp64Milli(max(window_end)))) AS finalized_through_ms,
    if(count()=0,NULL,lower(hex(SHA256(toJSONString(tuple(
        {tenant_id:UUID},{subscription_id:UUID},'connections',
        {period_start:DateTime64(3,'UTC')},{period_end:DateTime64(3,'UTC')},
        count(),uniqExact(sample_id),max(active_connections),max(ingested_at)
    )))))) AS source_evidence_digest
FROM package_metric_connection_facts_v1 FINAL
WHERE tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
  AND window_start>={period_start:DateTime64(3,'UTC')}
  AND window_end<={period_end:DateTime64(3,'UTC')}
FORMAT JSONEachRow`

type PackageMetricRequest struct {
	TenantScopeID  string
	SubscriptionID string
	Metric         string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	// ExcludeBlocked drops node-answered block pages from traffic and
	// bandwidth (openresty security block_page_not_counted, FX60).
	ExcludeBlocked bool
}

func excludeBlockedParameter(exclude bool) string {
	if exclude {
		return "1"
	}
	return "0"
}

type PackageMetricResult struct {
	Value                uint64
	ObservedAt           time.Time
	FinalizedThrough     time.Time
	SourceEvidenceDigest [sha256.Size]byte
}

type packageMetricResponseRow struct {
	Value                *uint64 `json:"value"`
	ObservedAtMS         *int64  `json:"observed_at_ms"`
	FinalizedThroughMS   *int64  `json:"finalized_through_ms"`
	SourceEvidenceDigest *string `json:"source_evidence_digest"`
}

func (client *Client) PackageMetric(ctx context.Context, request PackageMetricRequest) (PackageMetricResult, error) {
	if client == nil || ctx == nil || !validUUID(request.TenantScopeID) || nilUUID(request.TenantScopeID) ||
		!validUUID(request.SubscriptionID) || nilUUID(request.SubscriptionID) ||
		(request.Metric != "traffic_bytes" && request.Metric != "bandwidth_bps" && request.Metric != "connections") ||
		request.PeriodStart.IsZero() || request.PeriodEnd.IsZero() || request.PeriodStart.Location() != time.UTC ||
		request.PeriodEnd.Location() != time.UTC || !request.PeriodStart.Before(request.PeriodEnd) ||
		request.PeriodStart.Nanosecond()%int(time.Millisecond) != 0 || request.PeriodEnd.Nanosecond()%int(time.Millisecond) != 0 ||
		request.PeriodEnd.Sub(request.PeriodStart) > packageMetricFactRetention {
		return PackageMetricResult{}, ErrInvalidInput
	}
	tenantID, err := client.tenantOfScope(ctx, request.TenantScopeID)
	if err != nil {
		return PackageMetricResult{}, err
	}
	parameters := url.Values{
		"param_tenant_id": {tenantID}, "param_subscription_id": {request.SubscriptionID},
		"param_metric": {request.Metric}, "param_period_start": {clickHouseTime(request.PeriodStart)},
		"param_period_end":      {clickHouseTime(request.PeriodEnd)},
		"param_exclude_blocked": {excludeBlockedParameter(request.ExcludeBlocked)},
	}
	query := packageMetricSQL
	if request.Metric == "connections" {
		query = connectionsPackageMetricSQL
	}
	rows, err := queryRows[packageMetricResponseRow](client, ctx, query, parameters, 1)
	if err != nil || len(rows) != 1 {
		if err != nil {
			return PackageMetricResult{}, err
		}
		return PackageMetricResult{}, ErrInvalidResponse
	}
	row := rows[0]
	if row.Value == nil || row.ObservedAtMS == nil || row.FinalizedThroughMS == nil || row.SourceEvidenceDigest == nil ||
		len(*row.SourceEvidenceDigest) != sha256.Size*2 || strings.ToLower(*row.SourceEvidenceDigest) != *row.SourceEvidenceDigest {
		return PackageMetricResult{}, ErrInvalidResponse
	}
	digest, err := hex.DecodeString(*row.SourceEvidenceDigest)
	if err != nil || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) {
		return PackageMetricResult{}, ErrInvalidResponse
	}
	observedAt := time.UnixMilli(*row.ObservedAtMS).UTC()
	finalizedThrough := time.UnixMilli(*row.FinalizedThroughMS).UTC()
	if observedAt.Before(request.PeriodStart) || observedAt.After(finalizedThrough) || !finalizedThrough.Equal(request.PeriodEnd) {
		return PackageMetricResult{}, ErrInvalidResponse
	}
	result := PackageMetricResult{Value: *row.Value, ObservedAt: observedAt, FinalizedThrough: finalizedThrough}
	copy(result.SourceEvidenceDigest[:], digest)
	return result, nil
}

const summarySQL = `SELECT
    toUInt16(1) AS metric_version,
    toUInt64(sum(request_count_value)) AS request_count,
    toUInt64(sum(request_bytes_value)) AS request_bytes,
    toUInt64(sum(response_bytes_value)) AS response_bytes,
    toUInt64(sum(request_bytes_value) + sum(response_bytes_value)) AS total_bytes,
    sum(response_bytes_value) * 8.0 / {duration_seconds:UInt64} AS average_bandwidth_bps,
    toUInt64(sum(status_2xx_value)) AS status_2xx,
    toUInt64(sum(status_3xx_value)) AS status_3xx,
    toUInt64(sum(status_4xx_value)) AS status_4xx,
    toUInt64(sum(status_5xx_value)) AS status_5xx,
    toUInt64(sum(security_events_value)) AS security_events,
    toUInt64(sum(security_rows_value)) AS security_event_rows,
    toUInt64(sum(cache_hit_value)) AS cache_hit_requests,
    toUInt64(sum(cache_hit_bytes_value)) AS cache_hit_bytes,
    toUInt64(uniqExactIf(client_ip_value, request_count_value = 1)) AS unique_client_ips
FROM
(
    SELECT
        toUInt64(1) AS request_count_value,
        tupleElement(latest, 5) AS request_bytes_value,
        tupleElement(latest, 6) AS response_bytes_value,
        if(tupleElement(latest, 4) >= 200 AND tupleElement(latest, 4) < 300, 1, 0) AS status_2xx_value,
        if(tupleElement(latest, 4) >= 300 AND tupleElement(latest, 4) < 400, 1, 0) AS status_3xx_value,
        if(tupleElement(latest, 4) >= 400 AND tupleElement(latest, 4) < 500, 1, 0) AS status_4xx_value,
        if(tupleElement(latest, 4) >= 500 AND tupleElement(latest, 4) < 600, 1, 0) AS status_5xx_value,
        toUInt64(0) AS security_events_value,
        toUInt64(0) AS security_rows_value,
        if(lower(tupleElement(latest, 7)) = 'hit', toUInt64(1), toUInt64(0)) AS cache_hit_value,
        if(lower(tupleElement(latest, 7)) = 'hit', tupleElement(latest, 5) + tupleElement(latest, 6), toUInt64(0)) AS cache_hit_bytes_value,
        tupleElement(latest, 8) AS client_ip_value
    FROM
    (
        SELECT argMax(
            tuple(occurred_at, site_id, node_id, status_code, request_bytes, response_bytes, cache_status, client_ip),
            tuple(ingested_at, occurred_at, site_id, node_id, status_code, request_bytes, response_bytes, cache_status, client_ip)
        ) AS latest
        FROM access_hourly_facts_v1
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
    UNION ALL
    SELECT
        toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0),
        toUInt64(tupleElement(latest, 4)), toUInt64(1), toUInt64(0), toUInt64(0), toIPv6('::')
    FROM
    (
        SELECT argMax(
            tuple(occurred_at, site_id, node_id, requests),
            tuple(ingested_at, occurred_at, site_id, node_id, requests)
        ) AS latest
        FROM security_hourly_facts_v1
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
)
FORMAT JSONEachRow`

// blockedIPCountSQL counts distinct client IPs blocked in the requested
// window: global firewall blocks plus CC rules that auto-banned the client
// (temporary_ban, FX36). It is kept separate from security_events: the latter is an event
// count and must never be presented as a blocked-IP count.
const blockedIPCountSQL = `SELECT
    toUInt64(uniqExact(client_ip)) AS blocked_ip_count
FROM security_events FINAL
WHERE metric_version = 1
    AND ((event_type = 'global_firewall' AND action = 'block') OR (event_type = 'cc' AND action = 'temporary_ban'))
    AND occurred_at >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
    AND occurred_at < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
    AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
FORMAT JSONEachRow`

const blockedIPTrendSQL = `SELECT
    toUnixTimestamp(toStartOfHour(occurred_at, 'UTC')) AS bucket_unix,
    toUInt64(uniqExact(client_ip)) AS blocked_ip_count
FROM security_events FINAL
WHERE metric_version = 1
    AND ((event_type = 'global_firewall' AND action = 'block') OR (event_type = 'cc' AND action = 'temporary_ban'))
    AND occurred_at >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
    AND occurred_at < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
    AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
GROUP BY bucket_unix
ORDER BY bucket_unix
FORMAT JSONEachRow`

// peakBandwidthBucketSeconds is the window the home page peak is measured
// over; the hourly trend average flattens short bursts (FX36).
const peakBandwidthBucketSeconds = 300

// peakBandwidthSQL returns the response bytes of the busiest 5-minute bucket,
// using the same latest-version deduplication as summarySQL.
const peakBandwidthSQL = `SELECT
    toUInt64(coalesce(max(bucket_bytes), 0)) AS peak_bucket_bytes
FROM
(
    SELECT toStartOfFiveMinutes(tupleElement(latest, 1)) AS bucket, sum(tupleElement(latest, 4)) AS bucket_bytes
    FROM
    (
        SELECT argMax(
            tuple(occurred_at, site_id, node_id, response_bytes),
            tuple(ingested_at, occurred_at, site_id, node_id, response_bytes)
        ) AS latest
        FROM access_hourly_facts_v1
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
    GROUP BY bucket
)
FORMAT JSONEachRow`

// fix-waflogdetail: the WAF overview counts exactly the hits the security
// log lists (analyticslog.SecurityLogActions): block, challenge, log
// (observed) and temporary_ban (the node's WAF auto block); allow is not a hit.
// wafActionsAddUp reports whether the per-action counts (block, challenge,
// log, temporary_ban) add up to the attack total, as the action-scoped
// queries guarantee (fix-waflogdetail2): the page shows no number that the
// action cards cannot account for.
func wafActionsAddUp(attacks, blocked, challenged, observed, autoBlocked uint64) bool {
	sum := blocked + challenged
	if sum < blocked {
		return false
	}
	if sum += observed; sum < observed {
		return false
	}
	if sum += autoBlocked; sum < autoBlocked {
		return false
	}
	return sum == attacks
}

const wafOverviewSQL = `SELECT
    toUInt64(count()) AS attacks,
    toUInt64(countIf(action = 'block')) AS blocked,
    toUInt64(countIf(action = 'challenge')) AS intercepted,
    toUInt64(countIf(action = 'log')) AS observed,
    toUInt64(countIf(action = 'temporary_ban')) AS auto_blocked,
    toUInt64(uniqExact(client_ip)) AS clients
FROM security_events FINAL
WHERE metric_version = 1
    AND event_type = 'waf'
    AND action IN ('block', 'challenge', 'log', 'temporary_ban')
    AND occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
    AND occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
    AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
	    AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(host)))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
FORMAT JSONEachRow`

const wafTrendSQL = `SELECT
    toUnixTimestamp(toStartOfHour(occurred_at, 'UTC')) AS bucket_unix,
    toUInt64(count()) AS attacks,
    toUInt64(countIf(action = 'block')) AS blocked,
    toUInt64(countIf(action = 'challenge')) AS intercepted,
    toUInt64(countIf(action = 'log')) AS observed,
    toUInt64(countIf(action = 'temporary_ban')) AS auto_blocked,
    toUInt64(uniqExact(client_ip)) AS clients
FROM security_events FINAL
WHERE metric_version = 1
    AND event_type = 'waf'
    AND action IN ('block', 'challenge', 'log', 'temporary_ban')
    AND occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
    AND occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
    AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
	    AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(host)))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
GROUP BY bucket_unix
ORDER BY bucket_unix
FORMAT JSONEachRow`

var wafBreakdownSQL = `WITH scoped AS
(
	    SELECT host, path, client_ip, country_code, carrier, rule_id
    FROM security_events FINAL
    WHERE metric_version = 1
        AND event_type = 'waf'
        AND action IN ('block', 'challenge', 'log', 'temporary_ban')
        AND occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
        AND occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
        AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
        AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
	        AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(host)))
        AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
)
SELECT dimension, key, count
FROM
(
    SELECT 'attack_type' AS dimension, if(empty(rule_id), '__unknown__', rule_id) AS key, toUInt64(count()) AS count FROM scoped GROUP BY key
    UNION ALL
	    SELECT 'domain', if(empty(host), '__unknown__', lower(host)) AS key, toUInt64(count()) FROM scoped GROUP BY key
    UNION ALL
    SELECT 'client', ` + clientIPTextSQL("client_ip") + `, toUInt64(count()) FROM scoped GROUP BY client_ip
    UNION ALL
    SELECT 'country', if(empty(country_code), '__unknown__', country_code), toUInt64(count()) FROM scoped GROUP BY country_code
    UNION ALL
	    SELECT 'carrier', if(empty(carrier), '__unknown__', carrier), toUInt64(count()) FROM scoped GROUP BY carrier
	    UNION ALL
	    SELECT 'uri', if(empty(path), '__unknown__', path) AS key, toUInt64(count()) FROM scoped GROUP BY key
)
ORDER BY dimension ASC, count DESC, key ASC
LIMIT 10 BY dimension
FORMAT JSONEachRow`

const trendSQL = `SELECT
    toUnixTimestamp(hour) AS bucket_unix,
    toUInt16(1) AS metric_version,
    toUInt64(sum(request_count_value)) AS request_count,
    toUInt64(sum(request_bytes_value)) AS request_bytes,
    toUInt64(sum(response_bytes_value)) AS response_bytes,
    toUInt64(sum(request_bytes_value) + sum(response_bytes_value)) AS total_bytes,
    sum(response_bytes_value) * 8.0 / 3600.0 AS average_bandwidth_bps,
    toUInt64(sum(status_2xx_value)) AS status_2xx,
    toUInt64(sum(status_3xx_value)) AS status_3xx,
    toUInt64(sum(status_4xx_value)) AS status_4xx,
    toUInt64(sum(status_5xx_value)) AS status_5xx,
    toUInt64(sum(security_events_value)) AS security_events,
    toUInt64(sum(security_rows_value)) AS security_event_rows,
    toUInt64(sum(cache_hit_value)) AS cache_hit_requests,
    toUInt64(sum(cache_hit_bytes_value)) AS cache_hit_bytes,
    toUInt64(uniqExactIf(client_ip_value, request_count_value = 1)) AS unique_client_ips
FROM
(
    SELECT
        toStartOfHour(tupleElement(latest, 1), 'UTC') AS hour,
        toUInt64(1) AS request_count_value,
        tupleElement(latest, 5) AS request_bytes_value,
        tupleElement(latest, 6) AS response_bytes_value,
        if(tupleElement(latest, 4) >= 200 AND tupleElement(latest, 4) < 300, 1, 0) AS status_2xx_value,
        if(tupleElement(latest, 4) >= 300 AND tupleElement(latest, 4) < 400, 1, 0) AS status_3xx_value,
        if(tupleElement(latest, 4) >= 400 AND tupleElement(latest, 4) < 500, 1, 0) AS status_4xx_value,
        if(tupleElement(latest, 4) >= 500 AND tupleElement(latest, 4) < 600, 1, 0) AS status_5xx_value,
        toUInt64(0) AS security_events_value,
        toUInt64(0) AS security_rows_value,
        if(lower(tupleElement(latest, 7)) = 'hit', toUInt64(1), toUInt64(0)) AS cache_hit_value,
        if(lower(tupleElement(latest, 7)) = 'hit', tupleElement(latest, 5) + tupleElement(latest, 6), toUInt64(0)) AS cache_hit_bytes_value,
        tupleElement(latest, 8) AS client_ip_value
    FROM
    (
        SELECT argMax(
            tuple(occurred_at, site_id, node_id, status_code, request_bytes, response_bytes, cache_status, client_ip),
            tuple(ingested_at, occurred_at, site_id, node_id, status_code, request_bytes, response_bytes, cache_status, client_ip)
        ) AS latest
        FROM access_hourly_facts_v1
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
    UNION ALL
    SELECT
        toStartOfHour(tupleElement(latest, 1), 'UTC'),
        toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0), toUInt64(0),
        toUInt64(tupleElement(latest, 4)), toUInt64(1), toUInt64(0), toUInt64(0), toIPv6('::')
    FROM
    (
        SELECT argMax(
            tuple(occurred_at, site_id, node_id, requests),
            tuple(ingested_at, occurred_at, site_id, node_id, requests)
        ) AS latest
        FROM security_hourly_facts_v1
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
)
GROUP BY hour
ORDER BY hour
FORMAT JSONEachRow`

const topBySiteSQL = `SELECT
    toString(site_id) AS key,
    toUInt64(sum(request_count)) AS request_count,
    toUInt64(sum(response_bytes)) AS response_bytes,
    toUInt64(0) AS security_events
FROM access_hourly_v1
WHERE metric_version = 1
    AND hour >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
    AND hour < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
GROUP BY site_id
ORDER BY response_bytes DESC, request_count DESC, key
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

const topByNodeSQL = `SELECT
    toString(node_id) AS key,
    toUInt64(sum(request_count)) AS request_count,
    toUInt64(sum(response_bytes)) AS response_bytes,
    toUInt64(0) AS security_events
FROM access_hourly_v1
WHERE metric_version = 1
    AND hour >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
    AND hour < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
GROUP BY node_id
ORDER BY response_bytes DESC, request_count DESC, key
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

const topByStatusSQL = `SELECT
    toString(status_code) AS key,
    toUInt64(sum(request_count)) AS request_count,
    toUInt64(sum(response_bytes)) AS response_bytes,
    toUInt64(0) AS security_events
FROM access_hourly_v1
WHERE metric_version = 1
    AND hour >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
    AND hour < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
GROUP BY status_code
ORDER BY request_count DESC, response_bytes DESC, key
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

const topBySecurityActionSQL = `SELECT
    action AS key,
    toUInt64(0) AS request_count,
    toUInt64(0) AS response_bytes,
    toUInt64(sum(security_requests)) AS security_events
FROM security_hourly_v1
WHERE metric_version = 1
    AND hour >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
    AND hour < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
    AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
    AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
    AND ({has_node:UInt8} = 0 OR node_id = toUUID({node_id:String}))
GROUP BY action
ORDER BY security_events DESC, key
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

type trendRow struct {
	BucketUnix          int64   `json:"bucket_unix"`
	MetricVersion       uint16  `json:"metric_version"`
	RequestCount        uint64  `json:"request_count"`
	RequestBytes        uint64  `json:"request_bytes"`
	ResponseBytes       uint64  `json:"response_bytes"`
	TotalBytes          uint64  `json:"total_bytes"`
	AverageBandwidthBPS float64 `json:"average_bandwidth_bps"`
	Status2xx           uint64  `json:"status_2xx"`
	Status3xx           uint64  `json:"status_3xx"`
	Status4xx           uint64  `json:"status_4xx"`
	Status5xx           uint64  `json:"status_5xx"`
	SecurityEvents      uint64  `json:"security_events"`
	SecurityEventRows   uint64  `json:"security_event_rows"`
	CacheHitRequests    uint64  `json:"cache_hit_requests"`
	CacheHitBytes       uint64  `json:"cache_hit_bytes"`
	UniqueClientIPs     uint64  `json:"unique_client_ips"`
}

type trendResponseRow struct {
	BucketUnix *int64 `json:"bucket_unix"`
	summaryResponseRow
}

type summaryResponseRow struct {
	MetricVersion       *uint16  `json:"metric_version"`
	RequestCount        *uint64  `json:"request_count"`
	RequestBytes        *uint64  `json:"request_bytes"`
	ResponseBytes       *uint64  `json:"response_bytes"`
	TotalBytes          *uint64  `json:"total_bytes"`
	AverageBandwidthBPS *float64 `json:"average_bandwidth_bps"`
	Status2xx           *uint64  `json:"status_2xx"`
	Status3xx           *uint64  `json:"status_3xx"`
	Status4xx           *uint64  `json:"status_4xx"`
	Status5xx           *uint64  `json:"status_5xx"`
	SecurityEvents      *uint64  `json:"security_events"`
	SecurityEventRows   *uint64  `json:"security_event_rows"`
	CacheHitRequests    *uint64  `json:"cache_hit_requests"`
	CacheHitBytes       *uint64  `json:"cache_hit_bytes"`
	UniqueClientIPs     *uint64  `json:"unique_client_ips"`
}

type peakBandwidthResponseRow struct {
	PeakBucketBytes *uint64 `json:"peak_bucket_bytes"`
}

type blockedIPCountResponseRow struct {
	Count *uint64 `json:"blocked_ip_count"`
}

type blockedIPTrendResponseRow struct {
	BucketUnix *int64  `json:"bucket_unix"`
	Count      *uint64 `json:"blocked_ip_count"`
}

type wafOverviewResponseRow struct {
	Attacks     *uint64 `json:"attacks"`
	Blocked     *uint64 `json:"blocked"`
	Intercepted *uint64 `json:"intercepted"`
	Observed    *uint64 `json:"observed"`
	AutoBlocked *uint64 `json:"auto_blocked"`
	Clients     *uint64 `json:"clients"`
}

type wafTrendResponseRow struct {
	BucketUnix  *int64  `json:"bucket_unix"`
	Attacks     *uint64 `json:"attacks"`
	Blocked     *uint64 `json:"blocked"`
	Intercepted *uint64 `json:"intercepted"`
	Observed    *uint64 `json:"observed"`
	AutoBlocked *uint64 `json:"auto_blocked"`
	Clients     *uint64 `json:"clients"`
}

type wafBreakdownResponseRow struct {
	Dimension *string `json:"dimension"`
	Key       *string `json:"key"`
	Count     *uint64 `json:"count"`
}

type topResponseRow struct {
	Key            *string `json:"key"`
	RequestCount   *uint64 `json:"request_count"`
	ResponseBytes  *uint64 `json:"response_bytes"`
	SecurityEvents *uint64 `json:"security_events"`
}

func (row summaryResponseRow) summary() (Summary, bool) {
	if row.MetricVersion == nil || row.RequestCount == nil || row.RequestBytes == nil || row.ResponseBytes == nil ||
		row.TotalBytes == nil || row.AverageBandwidthBPS == nil || row.Status2xx == nil || row.Status3xx == nil ||
		row.Status4xx == nil || row.Status5xx == nil || row.SecurityEvents == nil || row.SecurityEventRows == nil || *row.MetricVersion != MetricVersion ||
		row.CacheHitRequests == nil || row.CacheHitBytes == nil || row.UniqueClientIPs == nil ||
		math.IsNaN(*row.AverageBandwidthBPS) || math.IsInf(*row.AverageBandwidthBPS, 0) || *row.AverageBandwidthBPS < 0 {
		return Summary{}, false
	}
	if *row.RequestBytes > math.MaxUint64-*row.ResponseBytes ||
		*row.TotalBytes != *row.RequestBytes+*row.ResponseBytes {
		return Summary{}, false
	}
	if *row.ResponseBytes == 0 && *row.AverageBandwidthBPS != 0 {
		return Summary{}, false
	}
	statusTotal := *row.Status2xx
	for _, bucket := range []uint64{*row.Status3xx, *row.Status4xx, *row.Status5xx} {
		if statusTotal > math.MaxUint64-bucket {
			return Summary{}, false
		}
		statusTotal += bucket
	}
	if statusTotal > *row.RequestCount || *row.RequestCount == 0 &&
		(*row.RequestBytes != 0 || *row.ResponseBytes != 0 || *row.TotalBytes != 0 || statusTotal != 0) {
		return Summary{}, false
	}
	if *row.CacheHitRequests > *row.RequestCount || *row.CacheHitBytes > *row.TotalBytes ||
		*row.UniqueClientIPs > *row.RequestCount {
		return Summary{}, false
	}
	return Summary{
		MetricVersion: *row.MetricVersion, RequestCount: *row.RequestCount, RequestBytes: *row.RequestBytes,
		ResponseBytes: *row.ResponseBytes, TotalBytes: *row.TotalBytes, AverageBandwidthBPS: *row.AverageBandwidthBPS,
		Status2xx: *row.Status2xx, Status3xx: *row.Status3xx, Status4xx: *row.Status4xx, Status5xx: *row.Status5xx,
		SecurityEvents: *row.SecurityEvents, SecurityEventRows: *row.SecurityEventRows, CacheHitRequests: *row.CacheHitRequests, CacheHitBytes: *row.CacheHitBytes,
		UniqueClientIPs: *row.UniqueClientIPs,
	}, true
}

func (row topResponseRow) item() (TopItem, bool) {
	if row.Key == nil || row.RequestCount == nil || row.ResponseBytes == nil || row.SecurityEvents == nil {
		return TopItem{}, false
	}
	return TopItem{Key: *row.Key, RequestCount: *row.RequestCount, ResponseBytes: *row.ResponseBytes, SecurityEvents: *row.SecurityEvents}, true
}

func (client *Client) Summary(ctx context.Context, scope Scope, filter Filter) (Summary, error) {
	parameters, err := queryParametersWithValidation(scope, filter, validateSummaryScopeFilter)
	if err != nil {
		return Summary{}, err
	}
	rows, err := queryRows[summaryResponseRow](client, ctx, summarySQL, parameters, 1)
	if err != nil {
		return Summary{}, err
	}
	if len(rows) != 1 {
		return Summary{}, ErrInvalidResponse
	}
	summary, ok := rows[0].summary()
	if !ok {
		return Summary{}, ErrInvalidResponse
	}
	durationSeconds := float64(filter.To.UTC().Sub(filter.From.UTC()) / time.Second)
	expectedBandwidth := float64(summary.ResponseBytes) * 8 / durationSeconds
	if math.Abs(summary.AverageBandwidthBPS-expectedBandwidth) > 1e-12+1e-9*math.Abs(expectedBandwidth) {
		return Summary{}, ErrInvalidResponse
	}
	return summary, nil
}

// PeakBandwidth returns the busiest 5-minute window's average bandwidth in the
// requested snapshot-bounded window.
func (client *Client) PeakBandwidth(ctx context.Context, scope Scope, filter Filter) (PeakBandwidth, error) {
	parameters, err := queryParameters(scope, filter)
	if err != nil {
		return PeakBandwidth{}, err
	}
	rows, err := queryRows[peakBandwidthResponseRow](client, ctx, peakBandwidthSQL, parameters, 1)
	if err != nil {
		return PeakBandwidth{}, err
	}
	if len(rows) != 1 || rows[0].PeakBucketBytes == nil || *rows[0].PeakBucketBytes > math.MaxUint64/8 {
		return PeakBandwidth{}, ErrInvalidResponse
	}
	return PeakBandwidth{
		PeakBandwidthBPS: *rows[0].PeakBucketBytes * 8 / peakBandwidthBucketSeconds,
		BucketSeconds:    peakBandwidthBucketSeconds,
	}, nil
}

// BlockedIPCount returns the distinct client-IP count for global firewall
// blocks and CC auto-bans in the requested snapshot-bounded window.
func (client *Client) BlockedIPCount(ctx context.Context, scope Scope, filter Filter) (uint64, error) {
	parameters, err := queryParameters(scope, filter)
	if err != nil {
		return 0, err
	}
	rows, err := queryRows[blockedIPCountResponseRow](client, ctx, blockedIPCountSQL, parameters, 1)
	if err != nil {
		return 0, err
	}
	if len(rows) != 1 || rows[0].Count == nil {
		return 0, ErrInvalidResponse
	}
	return *rows[0].Count, nil
}

func (client *Client) BlockedIPTrend(ctx context.Context, scope Scope, filter Filter) ([]BlockedIPTrendPoint, error) {
	parameters, err := queryParameters(scope, filter)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[blockedIPTrendResponseRow](client, ctx, blockedIPTrendSQL, parameters, int(filter.To.Sub(filter.From)/time.Hour))
	if err != nil {
		return nil, err
	}
	from, to := filter.From.UTC(), filter.To.UTC()
	points := make([]BlockedIPTrendPoint, len(rows))
	for index, row := range rows {
		if row.BucketUnix == nil || row.Count == nil {
			return nil, ErrInvalidResponse
		}
		bucket := time.Unix(*row.BucketUnix, 0).UTC()
		if !bucket.Equal(bucket.Truncate(time.Hour)) || bucket.Before(from) || !bucket.Before(to) ||
			(index > 0 && !points[index-1].Hour.Before(bucket)) {
			return nil, ErrInvalidResponse
		}
		points[index] = BlockedIPTrendPoint{Hour: bucket, BlockedIPCount: *row.Count}
	}
	return points, nil
}

func (client *Client) WAFOverview(ctx context.Context, scope Scope, filter Filter) (WAFOverview, error) {
	parameters, err := queryParametersWithValidation(scope, filter, validateWAFScopeFilter)
	if err != nil {
		return WAFOverview{}, err
	}
	summaryRows, err := queryRows[wafOverviewResponseRow](client, ctx, wafOverviewSQL, parameters, 1)
	if err != nil {
		return WAFOverview{}, err
	}
	if len(summaryRows) != 1 || summaryRows[0].Attacks == nil || summaryRows[0].Blocked == nil ||
		summaryRows[0].Intercepted == nil || summaryRows[0].Observed == nil || summaryRows[0].AutoBlocked == nil ||
		summaryRows[0].Clients == nil || !wafActionsAddUp(*summaryRows[0].Attacks, *summaryRows[0].Blocked,
		*summaryRows[0].Intercepted, *summaryRows[0].Observed, *summaryRows[0].AutoBlocked) {
		return WAFOverview{}, ErrInvalidResponse
	}
	trendRows, err := queryRows[wafTrendResponseRow](client, ctx, wafTrendSQL, parameters, int(filter.To.Sub(filter.From)/time.Hour))
	if err != nil {
		return WAFOverview{}, err
	}
	from, to := filter.From.UTC(), filter.To.UTC()
	trend := make([]WAFTrendPoint, len(trendRows))
	for index, row := range trendRows {
		if row.BucketUnix == nil || row.Attacks == nil || row.Blocked == nil || row.Intercepted == nil || row.Observed == nil ||
			row.AutoBlocked == nil || row.Clients == nil ||
			!wafActionsAddUp(*row.Attacks, *row.Blocked, *row.Intercepted, *row.Observed, *row.AutoBlocked) {
			return WAFOverview{}, ErrInvalidResponse
		}
		bucket := time.Unix(*row.BucketUnix, 0).UTC()
		if !bucket.Equal(bucket.Truncate(time.Hour)) || bucket.Before(from) || !bucket.Before(to) ||
			(index > 0 && !trend[index-1].Hour.Before(bucket)) {
			return WAFOverview{}, ErrInvalidResponse
		}
		trend[index] = WAFTrendPoint{Hour: bucket, Attacks: *row.Attacks, Blocked: *row.Blocked,
			Intercepted: *row.Intercepted, Observed: *row.Observed, AutoBlocked: *row.AutoBlocked, Clients: *row.Clients}
	}
	breakdownRows, err := queryRows[wafBreakdownResponseRow](client, ctx, wafBreakdownSQL, parameters, 60)
	if err != nil {
		return WAFOverview{}, err
	}
	breakdowns, ok := wafBreakdowns(breakdownRows)
	if !ok {
		return WAFOverview{}, ErrInvalidResponse
	}
	return WAFOverview{Attacks: *summaryRows[0].Attacks, Blocked: *summaryRows[0].Blocked,
		Intercepted: *summaryRows[0].Intercepted, Observed: *summaryRows[0].Observed,
		AutoBlocked: *summaryRows[0].AutoBlocked, Clients: *summaryRows[0].Clients, Trend: trend,
		AttackTypes: breakdowns["attack_type"], TopDomains: breakdowns["domain"], TopClients: breakdowns["client"],
		TopCountries: breakdowns["country"], TopProvinces: []WAFRankItem{}, TopCarriers: breakdowns["carrier"],
		TopURIs: breakdowns["uri"]}, nil
}

func wafBreakdowns(rows []wafBreakdownResponseRow) (map[string][]WAFRankItem, bool) {
	result := map[string][]WAFRankItem{
		"attack_type": {}, "domain": {}, "client": {}, "country": {}, "carrier": {}, "uri": {},
	}
	for _, row := range rows {
		if row.Dimension == nil || row.Key == nil || row.Count == nil || *row.Count == 0 ||
			len(*row.Key) == 0 || len(*row.Key) > maxRankKeyBytes || strings.TrimSpace(*row.Key) != *row.Key ||
			strings.IndexFunc(*row.Key, unicode.IsControl) >= 0 {
			return nil, false
		}
		items, known := result[*row.Dimension]
		if !known || len(items) >= 10 {
			return nil, false
		}
		if len(items) > 0 && (items[len(items)-1].Count < *row.Count ||
			(items[len(items)-1].Count == *row.Count && items[len(items)-1].Key >= *row.Key)) {
			return nil, false
		}
		result[*row.Dimension] = append(items, WAFRankItem{Key: *row.Key, Count: *row.Count})
	}
	return result, true
}

func (client *Client) Trend(ctx context.Context, scope Scope, filter Filter) ([]TrendPoint, error) {
	parameters, err := queryParameters(scope, filter)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[trendResponseRow](client, ctx, trendSQL, parameters, int(filter.To.Sub(filter.From)/time.Hour))
	if err != nil {
		return nil, err
	}
	from, to := filter.From.UTC(), filter.To.UTC()
	points := make([]TrendPoint, len(rows))
	for index, row := range rows {
		if row.BucketUnix == nil {
			return nil, ErrInvalidResponse
		}
		bucket := time.Unix(*row.BucketUnix, 0).UTC()
		summary, valid := row.summaryResponseRow.summary()
		if !valid || !bucket.Equal(bucket.Truncate(time.Hour)) ||
			bucket.Before(from) || !bucket.Before(to) || index > 0 && !points[index-1].Hour.Before(bucket) {
			return nil, ErrInvalidResponse
		}
		points[index] = TrendPoint{
			Hour: bucket, MetricVersion: summary.MetricVersion,
			RequestCount: summary.RequestCount, RequestBytes: summary.RequestBytes, ResponseBytes: summary.ResponseBytes,
			TotalBytes: summary.TotalBytes, AverageBandwidthBPS: summary.AverageBandwidthBPS,
			Status2xx: summary.Status2xx, Status3xx: summary.Status3xx, Status4xx: summary.Status4xx,
			Status5xx: summary.Status5xx, SecurityEvents: summary.SecurityEvents, SecurityEventRows: summary.SecurityEventRows,
			CacheHitRequests: summary.CacheHitRequests, CacheHitBytes: summary.CacheHitBytes, UniqueClientIPs: summary.UniqueClientIPs,
		}
	}
	return points, nil
}

func (client *Client) Top(
	ctx context.Context,
	scope Scope,
	filter Filter,
	dimension TopDimension,
	limit uint16,
) ([]TopItem, error) {
	if limit == 0 || limit > 100 {
		return nil, ErrInvalidInput
	}
	query, ok := topQuery(dimension)
	if !ok {
		return nil, ErrInvalidInput
	}
	parameters, err := queryParameters(scope, filter)
	if err != nil {
		return nil, err
	}
	parameters.Set("param_row_limit", strconv.FormatUint(uint64(limit), 10))
	rows, err := queryRows[topResponseRow](client, ctx, query, parameters, int(limit))
	if err != nil {
		return nil, err
	}
	items := make([]TopItem, len(rows))
	for index, row := range rows {
		item, ok := row.item()
		if !ok {
			return nil, ErrInvalidResponse
		}
		items[index] = item
	}
	if len(items) > int(limit) || !validTopItems(items, dimension) {
		return nil, ErrInvalidResponse
	}
	return items, nil
}

func queryRows[T any](client *Client, ctx context.Context, query string, parameters url.Values, maximumRows int) ([]T, error) {
	if maximumRows <= 0 {
		return nil, ErrInvalidResponse
	}
	var rows []T
	err := client.execute(ctx, client.queryTimeout, []byte(query), parameters, true, func(encoded []byte) error {
		if !utf8.Valid(encoded) {
			return ErrInvalidResponse
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		for {
			var encodedRow json.RawMessage
			if err := decoder.Decode(&encodedRow); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			if err := validateUniqueJSONKeys(encodedRow); err != nil {
				return err
			}
			var row T
			rowDecoder := json.NewDecoder(bytes.NewReader(encodedRow))
			rowDecoder.DisallowUnknownFields()
			if err := rowDecoder.Decode(&row); err != nil {
				return err
			}
			if len(rows) >= maximumRows {
				return ErrInvalidResponse
			}
			rows = append(rows, row)
		}
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

const maxTopSecurityActionBytes = 64

func validTopItems(rows []TopItem, dimension TopDimension) bool {
	seen := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		if !validTopKey(row.Key, dimension) {
			return false
		}
		if _, exists := seen[row.Key]; exists {
			return false
		}
		seen[row.Key] = struct{}{}
		switch dimension {
		case TopBySite, TopByNode, TopByStatusCode:
			if row.RequestCount == 0 || row.SecurityEvents != 0 {
				return false
			}
		case TopBySecurityAction:
			if row.SecurityEvents == 0 || row.RequestCount != 0 || row.ResponseBytes != 0 {
				return false
			}
		default:
			return false
		}
		if index > 0 && !topItemBefore(dimension, rows[index-1], row) {
			return false
		}
	}
	return true
}

func validTopKey(key string, dimension TopDimension) bool {
	if key == "" || !utf8.ValidString(key) || strings.TrimSpace(key) != key || strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return false
	}
	switch dimension {
	case TopBySite, TopByNode:
		return validUUID(key) && strings.ToLower(key) == key && !nilUUID(key)
	case TopByStatusCode:
		status, err := strconv.Atoi(key)
		return err == nil && status >= 100 && status <= 599 && strconv.Itoa(status) == key
	case TopBySecurityAction:
		return len(key) <= maxTopSecurityActionBytes
	default:
		return false
	}
}

func topItemBefore(dimension TopDimension, previous, current TopItem) bool {
	switch dimension {
	case TopBySite, TopByNode:
		if previous.ResponseBytes != current.ResponseBytes {
			return previous.ResponseBytes > current.ResponseBytes
		}
		if previous.RequestCount != current.RequestCount {
			return previous.RequestCount > current.RequestCount
		}
	case TopByStatusCode:
		if previous.RequestCount != current.RequestCount {
			return previous.RequestCount > current.RequestCount
		}
		if previous.ResponseBytes != current.ResponseBytes {
			return previous.ResponseBytes > current.ResponseBytes
		}
	case TopBySecurityAction:
		if previous.SecurityEvents != current.SecurityEvents {
			return previous.SecurityEvents > current.SecurityEvents
		}
	}
	return previous.Key < current.Key
}

func queryParameters(scope Scope, filter Filter) (url.Values, error) {
	return queryParametersWithValidation(scope, filter, validateScopeFilter)
}

func rankQueryParameters(scope Scope, filter Filter) (url.Values, error) {
	parameters, err := queryParametersWithValidation(scope, filter, validateRankScopeFilter)
	if err != nil {
		return nil, err
	}
	domains, _ := normalizeRankDomainFilter(filter.Domain)
	parameters.Set("param_has_domain", boolParameter(domains != ""))
	parameters.Set("param_domain", domains)
	parameters.Set("param_has_listen_port", boolParameter(filter.ListenPort != 0))
	parameters.Set("param_listen_port", strconv.FormatUint(uint64(filter.ListenPort), 10))
	return parameters, nil
}

func queryParametersWithValidation(scope Scope, filter Filter, validate func(Scope, Filter) error) (url.Values, error) {
	if err := validate(scope, filter); err != nil {
		return nil, err
	}
	snapshot := filter.SnapshotAt
	if snapshot.IsZero() {
		snapshot = time.Now().UTC().Truncate(time.Millisecond)
	}
	tenantID := nilUUIDValue
	tenantScoped := "0"
	if scope.kind == scopeTenant {
		tenantID = scope.tenantID
		tenantScoped = "1"
	}
	siteID, hasSite := optionalUUID(filter.SiteID)
	nodeID, hasNode := optionalUUID(filter.NodeID)
	return url.Values{
		"param_from_ms":          {strconv.FormatInt(filter.From.UnixMilli(), 10)},
		"param_to_ms":            {strconv.FormatInt(filter.To.UnixMilli(), 10)},
		"param_snapshot_ms":      {strconv.FormatInt(snapshot.UnixMilli(), 10)},
		"param_duration_seconds": {strconv.FormatInt(int64(filter.To.Sub(filter.From)/time.Second), 10)},
		"param_tenant_scoped":    {tenantScoped},
		"param_tenant_id":        {tenantID},
		"param_has_site":         {hasSite},
		"param_site_id":          {siteID},
		"param_has_domain":       {boolParameter(filter.Domain != "")},
		"param_domain":           {strings.ToLower(filter.Domain)},
		"param_has_node":         {hasNode},
		"param_node_id":          {nodeID},
	}, nil
}

func optionalUUID(value string) (string, string) {
	if value == "" {
		return nilUUIDValue, "0"
	}
	return strings.ToLower(value), "1"
}

func topQuery(dimension TopDimension) (string, bool) {
	switch dimension {
	case TopBySite:
		return topBySiteSQL, true
	case TopByNode:
		return topByNodeSQL, true
	case TopByStatusCode:
		return topByStatusSQL, true
	case TopBySecurityAction:
		return topBySecurityActionSQL, true
	default:
		return "", false
	}
}
