package analyticslog

import (
	"context"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// AttackSiteSummary is one site's WAF / CC attack decisions in a window
// (ge-waf S7, attack alert notifications): what blocked, challenged or banned
// clients, aggregated so an alert is one message per site and window, never
// one per request.
type AttackSiteSummary struct {
	TenantID     string
	SiteID       string
	Host         string
	Events       uint64
	Blocked      uint64
	Challenged   uint64
	Banned       uint64
	Clients      uint64
	TopDetector  string
	TopClientIP  string
	FirstEventAt time.Time
	LastEventAt  time.Time
}

// attackSummarySQL aggregates enforced WAF / CC decisions per site, in
// requests: an aggregated CC challenge / 429 line counts its event_count
// (sec-log-agg); log
// (observe mode, log rules) is not an attack that was stopped and is left
// out, like the global firewall that has its own hit log.
const attackSummarySQL = `SELECT
	toString(tenant_id) AS tenant_id,
	toString(site_id) AS site_id,
	any(host) AS host,
	toUInt64(sum(event_count)) AS events,
	toUInt64(sumIf(event_count, action = 'block')) AS blocked,
	toUInt64(sumIf(event_count, action = 'challenge')) AS challenged,
	toUInt64(sumIf(event_count, action = 'temporary_ban')) AS banned,
	toUInt64(uniqExact(client_ip)) AS clients,
	topKIf(1)(detector, detector != '')[1] AS top_detector,
	toString(topK(1)(client_ip)[1]) AS top_client_ip,
	toInt64(toUnixTimestamp64Milli(min(occurred_at))) AS first_ms,
	toInt64(toUnixTimestamp64Milli(max(occurred_at))) AS last_ms
FROM security_events FINAL
WHERE metric_version = 1
	AND event_type IN ('waf', 'cc') AND action IN ('block', 'challenge', 'temporary_ban')
	AND occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
	AND occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
GROUP BY tenant_id, site_id
HAVING events >= {minimum:UInt64}
ORDER BY events DESC, tenant_id, site_id
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

type attackSummaryRow struct {
	TenantID    string `json:"tenant_id"`
	SiteID      string `json:"site_id"`
	Host        string `json:"host"`
	Events      uint64 `json:"events"`
	Blocked     uint64 `json:"blocked"`
	Challenged  uint64 `json:"challenged"`
	Banned      uint64 `json:"banned"`
	Clients     uint64 `json:"clients"`
	TopDetector string `json:"top_detector"`
	TopClientIP string `json:"top_client_ip"`
	FirstMS     int64  `json:"first_ms"`
	LastMS      int64  `json:"last_ms"`
}

// MaxAttackSummarySites bounds one window's sites (the busiest first).
const MaxAttackSummarySites = 1000

// ListAttackSummaries returns the sites with at least minimum enforced WAF /
// CC decisions in [from, to), across every tenant (the alert worker's view;
// callers enforce tenant ownership when they act on a row).
func (client *Client) ListAttackSummaries(ctx context.Context, from, to time.Time, minimum uint64, limit uint16,
) ([]AttackSiteSummary, error) {
	if client == nil || ctx == nil || !from.Before(to) || minimum < 1 || limit < 1 || limit > MaxAttackSummarySites {
		return nil, ErrInvalidInput
	}
	parameters := url.Values{
		"param_from_ms":   {strconv.FormatInt(from.UTC().UnixMilli(), 10)},
		"param_to_ms":     {strconv.FormatInt(to.UTC().UnixMilli(), 10)},
		"param_minimum":   {strconv.FormatUint(minimum, 10)},
		"param_row_limit": {strconv.FormatUint(uint64(limit), 10)},
	}
	rows, err := queryRows[attackSummaryRow](client, ctx, attackSummarySQL, parameters, int(limit))
	if err != nil {
		return nil, err
	}
	result := make([]AttackSiteSummary, 0, len(rows))
	for _, row := range rows {
		first, last := time.UnixMilli(row.FirstMS).UTC(), time.UnixMilli(row.LastMS).UTC()
		if !validCanonicalUUID(row.TenantID) || !validCanonicalUUID(row.SiteID) || !validOutputText(row.Host, 253, false) ||
			!validOutputText(row.TopDetector, 64, false) || row.Events < minimum ||
			row.Blocked+row.Challenged+row.Banned != row.Events || first.After(last) || first.Before(from) || !last.Before(to) {
			return nil, ErrInvalidResponse
		}
		result = append(result, AttackSiteSummary{
			TenantID: row.TenantID, SiteID: row.SiteID, Host: row.Host, Events: row.Events, Blocked: row.Blocked,
			Challenged: row.Challenged, Banned: row.Banned, Clients: row.Clients, TopDetector: row.TopDetector,
			TopClientIP: unmappedIP(row.TopClientIP), FirstEventAt: first, LastEventAt: last,
		})
	}
	return result, nil
}

func unmappedIP(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	return address.Unmap().String()
}
