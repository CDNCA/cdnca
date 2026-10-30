package analytics

import (
	"context"
	"net/url"
	"time"
)

// siteTrafficSQL is a site's request+response bytes in [from, to) from the
// 400-day metering facts (every access event, with or without a package), the
// site traffic limit's usage (ge-analytics). Blocked pages count unless
// excluded (the platform's block_page_not_counted switch, as package traffic).
const siteTrafficSQL = `SELECT
    toUInt64(least(sum(toUInt128(request_bytes)+toUInt128(response_bytes)), toUInt128(18446744073709551615))) AS traffic_bytes
FROM access_metering_facts_v1 FINAL
WHERE metric_version=1 AND tenant_id={tenant_id:UUID} AND site_id={site_id:UUID}
  AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<{to:DateTime64(3,'UTC')}
  AND NOT ({exclude_blocked:UInt8}=1 AND blocked)
FORMAT JSONEachRow`

type SiteTrafficRequest struct {
	TenantScopeID, SiteID string
	From, To              time.Time
	ExcludeBlocked        bool
}

type siteTrafficRow struct {
	TrafficBytes *uint64 `json:"traffic_bytes"`
}

// SiteTraffic is the site's traffic in the window (at most the facts'
// retention).
func (client *Client) SiteTraffic(ctx context.Context, request SiteTrafficRequest) (uint64, error) {
	if client == nil || ctx == nil || !validUUID(request.TenantScopeID) || nilUUID(request.TenantScopeID) ||
		!validUUID(request.SiteID) || nilUUID(request.SiteID) || request.From.IsZero() || !request.From.Before(request.To) ||
		request.To.Sub(request.From) > packageMetricFactRetention {
		return 0, ErrInvalidInput
	}
	tenantID, err := client.tenantOfScope(ctx, request.TenantScopeID)
	if err != nil {
		return 0, err
	}
	rows, err := queryRows[siteTrafficRow](client, ctx, siteTrafficSQL, url.Values{
		"param_tenant_id": {tenantID}, "param_site_id": {request.SiteID},
		"param_from": {clickHouseTime(request.From)}, "param_to": {clickHouseTime(request.To)},
		"param_exclude_blocked": {excludeBlockedParameter(request.ExcludeBlocked)},
	}, 1)
	if err != nil {
		return 0, err
	}
	if len(rows) != 1 || rows[0].TrafficBytes == nil {
		return 0, ErrInvalidResponse
	}
	return *rows[0].TrafficBytes, nil
}
