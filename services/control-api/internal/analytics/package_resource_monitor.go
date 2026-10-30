package analytics

import (
	"context"
	"net/url"
	"time"
)

const packageResourceNodeWindow = 2 * time.Minute

const packageResourceNodesSQL = `WITH
access_seconds AS (
    SELECT node_id, toStartOfSecond(occurred_at, 'UTC') AS second,
           sum(toUInt128(response_bytes)) AS response_bytes,
           max(occurred_at) AS observed_at
    FROM access_events FINAL
    WHERE metric_version=1 AND tenant_id={tenant_id:UUID}
      AND package_subscription_id={subscription_id:UUID}
      AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<={at:DateTime64(3,'UTC')}
    GROUP BY node_id, second
),
access AS (
    SELECT node_id,
           argMax(if(response_bytes<=2305843009213693951,toUInt64(response_bytes*8),NULL),second) AS bandwidth_bps,
           toInt64(toUnixTimestamp64Milli(max(observed_at))) AS observed_at_ms
    FROM access_seconds GROUP BY node_id
),
connections AS (
    SELECT node_id, argMax(connections,tuple(occurred_at,updated_at)) AS connections,
           toInt64(toUnixTimestamp64Milli(max(occurred_at))) AS observed_at_ms
    FROM connections_ingest_receipts_v1 FINAL
    WHERE schema_version=1 AND state_rank>=2 AND tenant_id={tenant_id:UUID}
      AND package_subscription_id={subscription_id:UUID}
      AND occurred_at>={from:DateTime64(3,'UTC')} AND occurred_at<={at:DateTime64(3,'UTC')}
    GROUP BY node_id
),
samples AS (
    SELECT node_id, toNullable(bandwidth_bps) AS bandwidth_bps,
           toNullable(observed_at_ms) AS bandwidth_observed_at_ms,
           CAST(NULL,'Nullable(UInt64)') AS connections,
           CAST(NULL,'Nullable(Int64)') AS connections_observed_at_ms
    FROM access
    UNION ALL
    SELECT node_id, CAST(NULL,'Nullable(UInt64)'), CAST(NULL,'Nullable(Int64)'),
           toNullable(connections), toNullable(observed_at_ms)
    FROM connections
)
SELECT toString(node_id) AS node_id,
       max(bandwidth_bps) AS bandwidth_bps,
       max(bandwidth_observed_at_ms) AS bandwidth_observed_at_ms,
       max(connections) AS connections,
       max(connections_observed_at_ms) AS connections_observed_at_ms
FROM samples
GROUP BY node_id
ORDER BY node_id
LIMIT 10001
FORMAT JSONEachRow`

type PackageResourceNodesRequest struct {
	TenantScopeID  string
	SubscriptionID string
	At             time.Time
}

type PackageResourceNodeSnapshot struct {
	NodeID       string
	BandwidthBPS *uint64
	Connections  *uint64
	ObservedAt   time.Time
}

type packageResourceNodeRow struct {
	NodeID                  string  `json:"node_id"`
	BandwidthBPS            *uint64 `json:"bandwidth_bps"`
	BandwidthObservedAtMS   *int64  `json:"bandwidth_observed_at_ms"`
	Connections             *uint64 `json:"connections"`
	ConnectionsObservedAtMS *int64  `json:"connections_observed_at_ms"`
}

func (client *Client) PackageResourceNodes(ctx context.Context, request PackageResourceNodesRequest) ([]PackageResourceNodeSnapshot, error) {
	if client == nil || ctx == nil || !validUUID(request.TenantScopeID) || nilUUID(request.TenantScopeID) ||
		!validUUID(request.SubscriptionID) || nilUUID(request.SubscriptionID) || request.At.IsZero() ||
		request.At.Location() != time.UTC || request.At.Nanosecond()%int(time.Millisecond) != 0 {
		return nil, ErrInvalidInput
	}
	tenantID, err := client.tenantOfScope(ctx, request.TenantScopeID)
	if err != nil {
		return nil, err
	}
	from := request.At.Add(-packageResourceNodeWindow)
	parameters := url.Values{
		"param_tenant_id":       {tenantID},
		"param_subscription_id": {request.SubscriptionID},
		"param_from":            {from.Format("2006-01-02 15:04:05.000")},
		"param_at":              {request.At.Format("2006-01-02 15:04:05.000")},
	}
	rows, err := queryRows[packageResourceNodeRow](client, ctx, packageResourceNodesSQL, parameters, 10001)
	if err != nil {
		return nil, err
	}
	if len(rows) > 10000 {
		return nil, ErrInvalidResponse
	}
	items := make([]PackageResourceNodeSnapshot, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		if !validUUID(row.NodeID) || nilUUID(row.NodeID) ||
			(row.BandwidthBPS == nil) != (row.BandwidthObservedAtMS == nil) ||
			(row.Connections == nil) != (row.ConnectionsObservedAtMS == nil) {
			return nil, ErrInvalidResponse
		}
		if _, duplicate := seen[row.NodeID]; duplicate {
			return nil, ErrInvalidResponse
		}
		seen[row.NodeID] = struct{}{}
		item := PackageResourceNodeSnapshot{NodeID: row.NodeID}
		if row.BandwidthBPS != nil && row.Connections != nil {
			bandwidthAt := time.UnixMilli(*row.BandwidthObservedAtMS).UTC()
			connectionsAt := time.UnixMilli(*row.ConnectionsObservedAtMS).UTC()
			if bandwidthAt.Before(from) || bandwidthAt.After(request.At) ||
				connectionsAt.Before(from) || connectionsAt.After(request.At) {
				return nil, ErrInvalidResponse
			}
			item.BandwidthBPS = row.BandwidthBPS
			item.Connections = row.Connections
			item.ObservedAt = bandwidthAt
			if connectionsAt.Before(item.ObservedAt) {
				item.ObservedAt = connectionsAt
			}
		}
		items[index] = item
	}
	return items, nil
}
