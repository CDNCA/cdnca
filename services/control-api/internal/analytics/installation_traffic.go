package analytics

import (
	"context"
	"net/url"
	"time"
)

// installationTrafficSQL is the license monthly_traffic_bytes usage
// (fix-usagereport): the package traffic basis (PackageMetric traffic_bytes
// + PackageL4Traffic, checkpoints included) summed over every subscription
// of the installation.
// Bytes not attributed to a package subscription are not in either fact
// table, as for package usage.
var installationTrafficSQL = `SELECT
    toUInt64(least(
        (SELECT coalesce(sum(toUInt128(request_bytes)+toUInt128(response_bytes)),0)
         FROM package_metric_access_facts_v1 FINAL
         WHERE occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<{to:DateTime64(3,'UTC')}
           AND NOT ({exclude_blocked:UInt8}=1 AND blocked))
      + (SELECT coalesce(sum(toUInt128(up)+toUInt128(down)),0)
         FROM (` + l4UsageRowsSQL(l4FinalizedWindowSQL, "package_subscription_id!=toUUID('00000000-0000-0000-0000-000000000000')") + `)),
        toUInt128(9007199254740991))) AS traffic_bytes
FORMAT JSONEachRow`

// InstallationTrafficBytes sums package-attributed HTTP and L4 traffic of
// all tenants in [from, to), capped at the largest quota value.
func (client *Client) InstallationTrafficBytes(ctx context.Context, from, to time.Time, excludeBlocked bool) (uint64, error) {
	if client == nil || ctx == nil || from.IsZero() || !from.Before(to) || from.Location() != time.UTC ||
		to.Location() != time.UTC || to.Sub(from) > packageMetricFactRetention {
		return 0, ErrInvalidInput
	}
	rows, err := queryRows[packageL4TrafficRow](client, ctx, installationTrafficSQL, url.Values{
		"param_from": {clickHouseTime(from)}, "param_to": {clickHouseTime(to)},
		"param_exclude_blocked": {excludeBlockedParameter(excludeBlocked)},
	}, 1)
	if err != nil {
		return 0, err
	}
	if len(rows) != 1 {
		return 0, ErrInvalidResponse
	}
	return rows[0].TrafficBytes, nil
}
