package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

// packageBandwidthFinalizedSQL is the period's busiest 1-second sample with
// every request's bytes spread over its transfer time (bandwidth_spread.go).
// The evidence covers every fact that sent bytes inside the period.
var packageBandwidthFinalizedSQL = `WITH
facts AS (
    SELECT installation_id, event_id, occurred_at, response_bytes, duration_us, ingested_at
    FROM package_metric_access_facts_v1 FINAL
    WHERE tenant_id={tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}
      AND ` + bandwidthSpreadScanSQL("period_start", "period_end") + `
      AND NOT ({exclude_blocked:UInt8}=1 AND blocked)
),
samples AS (` + bandwidthSpreadSamplesSQL("SELECT "+bandwidthSpreadColumns()+" FROM facts", "period_start", "period_end", bandwidthPeakSampleMS) + `),
evidence AS (
    SELECT count() AS event_count, uniqExact(event_id) AS unique_event_count,
        groupBitXor(cityHash64(tuple(installation_id,event_id,occurred_at,response_bytes,duration_us,ingested_at))) AS evidence_xor,
        max(ingested_at) AS last_ingested_at,
        max(least(occurred_at, {period_end:DateTime64(3,'UTC')})) AS observed_at
    FROM facts
),
peak AS (SELECT max(v) AS peak_milli_bytes FROM samples)
SELECT
    if(peak_milli_bytes*8>toUInt128(18446744073709551615)*1000, NULL,
       ` + bandwidthSpreadBPSSQL("peak_milli_bytes", bandwidthPeakSampleMS) + `) AS value,
    toInt64(toUnixTimestamp64Milli(if(event_count=0, {period_end:DateTime64(3,'UTC')}, observed_at))) AS observed_at_ms,
    toInt64(toUnixTimestamp64Milli({period_end:DateTime64(3,'UTC')})) AS finalized_through_ms,
    lower(hex(SHA256(toJSONString(tuple(
        {tenant_id:UUID},{subscription_id:UUID},{metric:String},'peak_1s_spread_v1',
        {period_start:DateTime64(3,'UTC')},{period_end:DateTime64(3,'UTC')},
        peak_milli_bytes,event_count,unique_event_count,evidence_xor,last_ingested_at,
        {period_end:DateTime64(3,'UTC')}
    ))))) AS source_evidence_digest
FROM evidence CROSS JOIN peak
FORMAT JSONEachRow`

func (client *Client) PackageBandwidthFinalized(
	ctx context.Context,
	request PackageMetricRequest,
) (PackageMetricResult, error) {
	if client == nil || ctx == nil || !validUUID(request.TenantScopeID) || nilUUID(request.TenantScopeID) ||
		!validUUID(request.SubscriptionID) || nilUUID(request.SubscriptionID) || request.Metric != "bandwidth_bps" ||
		request.PeriodStart.IsZero() || request.PeriodEnd.IsZero() || request.PeriodStart.Location() != time.UTC ||
		request.PeriodEnd.Location() != time.UTC || !request.PeriodStart.Before(request.PeriodEnd) ||
		!request.PeriodStart.Equal(request.PeriodStart.Truncate(time.Millisecond)) ||
		!request.PeriodEnd.Equal(request.PeriodEnd.Truncate(time.Millisecond)) {
		return PackageMetricResult{}, ErrInvalidInput
	}
	tenantID, err := client.tenantOfScope(ctx, request.TenantScopeID)
	if err != nil {
		return PackageMetricResult{}, err
	}
	parameters := url.Values{
		"param_tenant_id":       {tenantID},
		"param_subscription_id": {request.SubscriptionID},
		"param_metric":          {request.Metric},
		"param_period_start":    {clickHouseTime(request.PeriodStart)},
		"param_period_end":      {clickHouseTime(request.PeriodEnd)},
		"param_exclude_blocked": {excludeBlockedParameter(request.ExcludeBlocked)},
	}
	rows, err := queryRows[packageMetricResponseRow](client, ctx, packageBandwidthFinalizedSQL, parameters, 1)
	if err != nil {
		return PackageMetricResult{}, err
	}
	if len(rows) != 1 {
		return PackageMetricResult{}, ErrInvalidResponse
	}
	row := rows[0]
	if row.Value == nil || row.ObservedAtMS == nil || row.FinalizedThroughMS == nil || row.SourceEvidenceDigest == nil ||
		len(*row.SourceEvidenceDigest) != sha256.Size*2 || strings.ToLower(*row.SourceEvidenceDigest) != *row.SourceEvidenceDigest ||
		strings.Trim(*row.SourceEvidenceDigest, "0") == "" {
		return PackageMetricResult{}, ErrInvalidResponse
	}
	digest, err := hex.DecodeString(*row.SourceEvidenceDigest)
	if err != nil || len(digest) != sha256.Size {
		return PackageMetricResult{}, ErrInvalidResponse
	}
	observedAt := time.UnixMilli(*row.ObservedAtMS).UTC()
	finalizedThrough := time.UnixMilli(*row.FinalizedThroughMS).UTC()
	if observedAt.Before(request.PeriodStart) || observedAt.After(finalizedThrough) ||
		!finalizedThrough.Equal(request.PeriodEnd) {
		return PackageMetricResult{}, ErrInvalidResponse
	}
	result := PackageMetricResult{
		Value: *row.Value, ObservedAt: observedAt, FinalizedThrough: finalizedThrough,
	}
	copy(result.SourceEvidenceDigest[:], digest)
	return result, nil
}
