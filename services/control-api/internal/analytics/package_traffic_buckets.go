package analytics

import (
	"context"
	"net/url"
	"time"
)

// PackageTrafficBucketSize is the node market's usage bucket (marketproto/usage).
const PackageTrafficBucketSize = 5 * time.Minute

const maxPackageTrafficBuckets = 2016 // 7 days of 5-minute buckets

// PackageTrafficBucket is egress and request count of one subscription in one
// 5-minute bucket; empty buckets are not returned.
type PackageTrafficBucket struct {
	Start    time.Time
	BytesOut int64
	Requests int64
}

const packageTrafficBucketsSQL = `SELECT
    toInt64(toUnixTimestamp(toStartOfInterval(occurred_at, INTERVAL 5 MINUTE))) AS bucket_start,
    toInt64(least(sum(toUInt128(response_bytes)), toUInt128(9223372036854775807))) AS bytes_out,
    toInt64(uniqExact(event_id)) AS requests
FROM package_metric_access_facts_v1 FINAL
WHERE tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
  AND occurred_at>={period_start:DateTime64(3,'UTC')}
  AND occurred_at<{period_end:DateTime64(3,'UTC')}
  AND NOT ({exclude_blocked:UInt8}=1 AND blocked)
GROUP BY bucket_start
ORDER BY bucket_start
FORMAT JSONEachRow`

type packageTrafficBucketRow struct {
	BucketStart *int64 `json:"bucket_start"`
	BytesOut    *int64 `json:"bytes_out"`
	Requests    *int64 `json:"requests"`
}

// PackageTrafficBuckets returns 5-minute egress buckets in [start, end); both
// ends must be bucket-aligned UTC and at most 7 days apart.
func (client *Client) PackageTrafficBuckets(ctx context.Context, tenantScopeID, subscriptionID string,
	start, end time.Time,
) ([]PackageTrafficBucket, error) {
	return client.PackageTrafficBucketsFiltered(ctx, tenantScopeID, subscriptionID, start, end, false)
}

// PackageTrafficBucketsFiltered is PackageTrafficBuckets that can drop block
// pages (FX60).
func (client *Client) PackageTrafficBucketsFiltered(ctx context.Context, tenantScopeID, subscriptionID string,
	start, end time.Time, excludeBlocked bool,
) ([]PackageTrafficBucket, error) {
	if client == nil || ctx == nil || !validUUID(tenantScopeID) || nilUUID(tenantScopeID) ||
		!validUUID(subscriptionID) || nilUUID(subscriptionID) || start.Location() != time.UTC || end.Location() != time.UTC ||
		!start.Before(end) || !start.Equal(start.Truncate(PackageTrafficBucketSize)) || !end.Equal(end.Truncate(PackageTrafficBucketSize)) ||
		end.Sub(start) > maxPackageTrafficBuckets*PackageTrafficBucketSize {
		return nil, ErrInvalidInput
	}
	tenantID, err := client.tenantOfScope(ctx, tenantScopeID)
	if err != nil {
		return nil, err
	}
	rows, err := queryRows[packageTrafficBucketRow](client, ctx, packageTrafficBucketsSQL, url.Values{
		"param_tenant_id": {tenantID}, "param_subscription_id": {subscriptionID},
		"param_period_start": {clickHouseTime(start)}, "param_period_end": {clickHouseTime(end)},
		"param_exclude_blocked": {excludeBlockedParameter(excludeBlocked)},
	}, maxPackageTrafficBuckets)
	if err != nil {
		return nil, err
	}
	out := make([]PackageTrafficBucket, 0, len(rows))
	for _, row := range rows {
		if row.BucketStart == nil || row.BytesOut == nil || row.Requests == nil || *row.BytesOut < 0 || *row.Requests < 0 {
			return nil, ErrInvalidResponse
		}
		at := time.Unix(*row.BucketStart, 0).UTC()
		if at.Before(start) || !at.Before(end) || !at.Equal(at.Truncate(PackageTrafficBucketSize)) {
			return nil, ErrInvalidResponse
		}
		out = append(out, PackageTrafficBucket{Start: at, BytesOut: *row.BytesOut, Requests: *row.Requests})
	}
	return out, nil
}

// SubscriptionPeakBucket is one market subscription's realtime peaks in one
// 5-minute bucket (usage report v2, ADR 0012 §5.1): each minute summed over
// the nodes, then the bucket's largest minute.
type SubscriptionPeakBucket struct {
	Start                                                  time.Time
	PeakBPS, MaxConcurrent, MaxRequests, MaxQPS, MaxNewCPS int64
}

// The node rows of subscription_minutes_v1 (ClickHouse 024, FINAL drops a
// node's redelivered minute) summed per minute, the largest minute per bucket.
const subscriptionPeakBucketsSQL = `SELECT
    toInt64(toUnixTimestamp(toStartOfInterval(minute, INTERVAL 5 MINUTE))) AS bucket_start,
    toInt64(least(max(peak_bps), 9223372036854775807)) AS peak_bps,
    toInt64(least(max(connections), 9223372036854775807)) AS max_concurrent,
    toInt64(least(max(requests), 9223372036854775807)) AS max_requests,
    toInt64(least(max(qps), 9223372036854775807)) AS max_qps,
    toInt64(least(max(new_cps), 9223372036854775807)) AS max_new_cps
FROM (
    SELECT minute,
        sum(toUInt128(peak_bps)) AS peak_bps, sum(toUInt128(max_connections)) AS connections,
        sum(toUInt128(max_requests)) AS requests, sum(toUInt128(max_qps)) AS qps,
        sum(toUInt128(max_new_cps)) AS new_cps
    FROM subscription_minutes_v1 FINAL
    WHERE package_subscription_id={subscription_id:UUID}
      AND minute>={period_start:DateTime('UTC')} AND minute<{period_end:DateTime('UTC')}
    GROUP BY minute
)
GROUP BY bucket_start
ORDER BY bucket_start
FORMAT JSONEachRow`

type subscriptionPeakBucketRow struct {
	BucketStart   *int64 `json:"bucket_start"`
	PeakBPS       *int64 `json:"peak_bps"`
	MaxConcurrent *int64 `json:"max_concurrent"`
	MaxRequests   *int64 `json:"max_requests"`
	MaxQPS        *int64 `json:"max_qps"`
	MaxNewCPS     *int64 `json:"max_new_cps"`
}

// SubscriptionPeakBuckets returns the subscription's 5-minute peaks in
// [start, end), same bounds as PackageTrafficBuckets; buckets without minute
// rows are not returned. The rows are keyed by the subscription alone: its ID
// is unique, and their tenant_id is the telemetry tenant, not the scope.
func (client *Client) SubscriptionPeakBuckets(ctx context.Context, subscriptionID string,
	start, end time.Time,
) ([]SubscriptionPeakBucket, error) {
	if client == nil || ctx == nil || !validUUID(subscriptionID) || nilUUID(subscriptionID) ||
		start.Location() != time.UTC || end.Location() != time.UTC ||
		!start.Before(end) || !start.Equal(start.Truncate(PackageTrafficBucketSize)) || !end.Equal(end.Truncate(PackageTrafficBucketSize)) ||
		end.Sub(start) > maxPackageTrafficBuckets*PackageTrafficBucketSize {
		return nil, ErrInvalidInput
	}
	rows, err := queryRows[subscriptionPeakBucketRow](client, ctx, subscriptionPeakBucketsSQL, url.Values{
		"param_subscription_id": {subscriptionID},
		"param_period_start":    {start.Format(time.DateTime)}, "param_period_end": {end.Format(time.DateTime)},
	}, maxPackageTrafficBuckets)
	if err != nil {
		return nil, err
	}
	out := make([]SubscriptionPeakBucket, 0, len(rows))
	for _, row := range rows {
		values := []*int64{row.BucketStart, row.PeakBPS, row.MaxConcurrent, row.MaxRequests, row.MaxQPS, row.MaxNewCPS}
		for _, value := range values {
			if value == nil || *value < 0 {
				return nil, ErrInvalidResponse
			}
		}
		at := time.Unix(*row.BucketStart, 0).UTC()
		if at.Before(start) || !at.Before(end) || !at.Equal(at.Truncate(PackageTrafficBucketSize)) {
			return nil, ErrInvalidResponse
		}
		out = append(out, SubscriptionPeakBucket{Start: at, PeakBPS: *row.PeakBPS, MaxConcurrent: *row.MaxConcurrent,
			MaxRequests: *row.MaxRequests, MaxQPS: *row.MaxQPS, MaxNewCPS: *row.MaxNewCPS})
	}
	return out, nil
}
