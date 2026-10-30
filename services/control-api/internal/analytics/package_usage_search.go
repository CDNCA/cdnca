package analytics

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UsageTarget binds an object to its tenant; independent ID lists would allow
// unintended cross-tenant combinations.
type UsageTarget struct{ TenantID, ObjectID string }

type UsageSearchRequest struct {
	From, To               time.Time
	Timezone               string
	Bucket                 PackageUsageBucket
	ServiceType            string
	Domains                []string
	ListenPorts            []uint16
	Restricted             bool
	Subscriptions, Streams []UsageTarget
	// TenantID 非空时只统计这个租户作用域的事实（用户端"用量查询"）。
	TenantID string
}

type UsageSearchResult struct {
	TrafficBytes, PeakBandwidthBPS, Bandwidth95thBPS uint64
	Series                                           []PackageUsagePoint
}

type usageSearchRow struct {
	BucketMS     int64  `json:"bucket_ms"`
	TrafficBytes uint64 `json:"traffic_bytes"`
	BandwidthBPS uint64 `json:"bandwidth_bps"`
	TotalBytes   uint64 `json:"total_bytes"`
	PeakBPS      uint64 `json:"peak_bps"`
	P95BPS       uint64 `json:"p95_bps"`
}

func ValidateUsageSearch(request UsageSearchRequest) error {
	if request.From.IsZero() || request.To.IsZero() || !request.From.Before(request.To) ||
		request.From.Location() != time.UTC || request.To.Location() != time.UTC ||
		request.From.Nanosecond()%int(time.Millisecond) != 0 || request.To.Nanosecond()%int(time.Millisecond) != 0 {
		return ErrInvalidInput
	}
	location, err := time.LoadLocation(request.Timezone)
	if err != nil || location == time.Local || request.Timezone == "Local" || len(request.Timezone) > 64 {
		return ErrInvalidInput
	}
	step := time.Hour
	if request.Bucket == PackageUsageBucketDay {
		step = 24 * time.Hour
	} else if request.Bucket != PackageUsageBucketHour {
		return ErrInvalidInput
	}
	// Include potentially partial boundary buckets; never truncate a result to
	// the first page while presenting its summary as the entire selected range.
	if request.To.Sub(request.From) > 167*step {
		return ErrInvalidInput
	}
	if request.ServiceType != "all" && request.ServiceType != "site" && request.ServiceType != "stream" {
		return ErrInvalidInput
	}
	if len(request.Domains) > 50 || len(request.ListenPorts) > 50 || len(request.Subscriptions) > 1000 || len(request.Streams) > 1000 {
		return ErrInvalidInput
	}
	if len(request.Domains) > 0 && (len(request.ListenPorts) > 0 || request.ServiceType == "stream") || len(request.ListenPorts) > 0 && request.ServiceType == "site" {
		return ErrInvalidInput
	}
	for _, domain := range request.Domains {
		if !validDomainFilter(domain) || strings.ToLower(domain) != domain {
			return ErrInvalidInput
		}
	}
	for _, port := range request.ListenPorts {
		if port == 0 {
			return ErrInvalidInput
		}
	}
	if request.TenantID != "" && (!validUUID(request.TenantID) || nilUUID(request.TenantID)) {
		return ErrInvalidInput
	}
	for _, targets := range [][]UsageTarget{request.Subscriptions, request.Streams} {
		for _, target := range targets {
			if !validUUID(target.TenantID) || nilUUID(target.TenantID) || !validUUID(target.ObjectID) || nilUUID(target.ObjectID) {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

func (client *Client) SearchPackageUsage(ctx context.Context, request UsageSearchRequest) (UsageSearchResult, error) {
	if client == nil || ctx == nil || ValidateUsageSearch(request) != nil {
		return UsageSearchResult{}, ErrInvalidInput
	}
	parameters := url.Values{
		"param_from":     {request.From.Format("2006-01-02 15:04:05.000")},
		"param_to":       {request.To.Format("2006-01-02 15:04:05.000")},
		"param_timezone": {request.Timezone},
	}
	if request.TenantID != "" {
		parameters.Set("param_tenant", request.TenantID)
	}
	var facts []string
	if request.ServiceType != "stream" && len(request.ListenPorts) == 0 {
		where := "metric_version=1 AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<{to:DateTime64(3,'UTC')}"
		if request.TenantID != "" {
			where += " AND tenant_id={tenant:UUID}"
		}
		if request.Restricted {
			where += " AND (tenant_id,package_subscription_id) IN {subscriptions:Array(Tuple(UUID,UUID))}"
			parameters.Set("param_subscriptions", usageTargetParameter(request.Subscriptions))
		}
		if len(request.Domains) > 0 {
			where += " AND lowerUTF8(host) IN {domains:Array(String)}"
			parameters.Set("param_domains", "['"+strings.Join(request.Domains, "','")+"']")
		}
		// access_metering_facts_v1 keeps every access event's bytes for 400
		// days; raw access_events follow the access log retention (7 days).
		facts = append(facts, "SELECT occurred_at AS at, request_bytes+response_bytes AS traffic, response_bytes AS outbound FROM access_metering_facts_v1 FINAL WHERE "+where)
	}
	if request.ServiceType != "site" && len(request.Domains) == 0 {
		var conditions []string
		if request.TenantID != "" {
			conditions = append(conditions, "tenant_id={tenant:UUID}")
		}
		if request.Restricted {
			conditions = append(conditions, "(tenant_id,stream_id) IN {streams:Array(Tuple(UUID,UUID))}")
			parameters.Set("param_streams", usageTargetParameter(request.Streams))
		}
		if len(request.ListenPorts) > 0 {
			ports := make([]string, len(request.ListenPorts))
			for i, port := range request.ListenPorts {
				ports[i] = strconv.Itoa(int(port))
			}
			conditions = append(conditions, "listen_port IN {ports:Array(UInt16)}")
			parameters.Set("param_ports", "["+strings.Join(ports, ",")+"]")
		}
		// billed L4 usage: end facts' remainder and in-progress checkpoints
		// (L4-USAGE-01), each at the time its bytes moved
		facts = append(facts, "SELECT at, up+down AS traffic, down AS outbound FROM ("+
			l4UsageRowsSQL(l4FinalizedWindowSQL, strings.Join(conditions, " AND "))+")")
	}
	interval, seconds := "HOUR", 3600
	if request.Bucket == PackageUsageBucketDay {
		interval, seconds = "DAY", 86400
	}
	// One ClickHouse query observes one statement snapshot and aggregates the
	// combined series before calculating its percentiles. L4 facts are finalized
	// session counters, not samples of instantaneous bandwidth.
	query := fmt.Sprintf(`WITH facts AS (%s), buckets AS (
 SELECT toStartOfInterval(at, INTERVAL 1 %s, {timezone:String}) AS bucket,
        sum(traffic) AS traffic_bytes, toUInt64(ceil(sum(outbound)*8.0/%d)) AS bandwidth_bps
 FROM facts GROUP BY bucket
)
SELECT toInt64(toUnixTimestamp(bucket))*1000 AS bucket_ms, traffic_bytes, bandwidth_bps,
       sum(traffic_bytes) OVER () AS total_bytes, max(bandwidth_bps) OVER () AS peak_bps,
       toUInt64(quantileExact(0.95)(bandwidth_bps) OVER ()) AS p95_bps
FROM buckets ORDER BY bucket LIMIT 169 FORMAT JSONEachRow`, strings.Join(facts, " UNION ALL "), interval, seconds)
	rows, err := queryRows[usageSearchRow](client, ctx, query, parameters, 168)
	if err != nil {
		return UsageSearchResult{}, err
	}
	result := UsageSearchResult{Series: make([]PackageUsagePoint, 0, len(rows))}
	for i, row := range rows {
		bucket := time.UnixMilli(row.BucketMS).UTC()
		if bucket.Before(request.From.Add(-24*time.Hour)) || !bucket.Before(request.To) ||
			i > 0 && (!result.Series[i-1].Bucket.Before(bucket) || row.TotalBytes != result.TrafficBytes || row.PeakBPS != result.PeakBandwidthBPS || row.P95BPS != result.Bandwidth95thBPS) || row.P95BPS > row.PeakBPS || row.BandwidthBPS > row.PeakBPS {
			return UsageSearchResult{}, ErrInvalidResponse
		}
		result.TrafficBytes, result.PeakBandwidthBPS, result.Bandwidth95thBPS = row.TotalBytes, row.PeakBPS, row.P95BPS
		result.Series = append(result.Series, PackageUsagePoint{Bucket: bucket, TrafficBytes: row.TrafficBytes, BandwidthBPS: row.BandwidthBPS})
	}
	return result, nil
}

func usageTargetParameter(targets []UsageTarget) string {
	parts := make([]string, len(targets))
	for i, target := range targets {
		parts[i] = "('" + target.TenantID + "','" + target.ObjectID + "')"
	}
	return "[" + strings.Join(parts, ",") + "]"
}
