package analyticslog

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// TemporaryBanEvent is one node's automatic WAF / CC ban (security_events
// action temporary_ban), read in ingestion order by the ban list sync (ge-waf
// S5): the control plane folds it into security_ban_entries so the ban
// applies on every node serving the site.
type TemporaryBanEvent struct {
	EventID    string
	TenantID   string
	SiteID     string
	EventType  string // waf | cc
	ClientIP   string
	RuleID     string
	PolicyID   string
	OccurredAt time.Time
	IngestedAt time.Time
}

// temporaryBanSQL reads ingestion windows: ingested_at is the
// ReplacingMergeTree version, so a re-ingested event comes back with a later
// ingested_at and the sync folds it once (source_event_id is unique).
const temporaryBanSQL = `SELECT
	event_id,
	toString(tenant_id) AS tenant_id,
	toString(site_id) AS site_id,
	toString(event_type) AS event_type,
	toString(client_ip) AS client_ip,
	rule_id,
	policy_id,
	toInt64(toUnixTimestamp64Milli(occurred_at)) AS occurred_ms,
	toInt64(toUnixTimestamp64Milli(ingested_at)) AS ingested_ms
FROM security_events FINAL
WHERE metric_version = 1
	AND event_type IN ('waf', 'cc') AND action = 'temporary_ban'
	AND ingested_at > fromUnixTimestamp64Milli({after_ms:Int64}, 'UTC')
	AND ingested_at <= fromUnixTimestamp64Milli({through_ms:Int64}, 'UTC')
ORDER BY ingested_at, event_id
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

type temporaryBanRow struct {
	EventID    string `json:"event_id"`
	TenantID   string `json:"tenant_id"`
	SiteID     string `json:"site_id"`
	EventType  string `json:"event_type"`
	ClientIP   string `json:"client_ip"`
	RuleID     string `json:"rule_id"`
	PolicyID   string `json:"policy_id"`
	OccurredMS int64  `json:"occurred_ms"`
	IngestedMS int64  `json:"ingested_ms"`
}

// MaxTemporaryBanEvents bounds one read.
const MaxTemporaryBanEvents = 5000

// ListTemporaryBans returns automatic bans ingested in (after, through], in
// ingestion order, at most limit (the caller continues from the last
// IngestedAt when it got limit rows).
func (client *Client) ListTemporaryBans(ctx context.Context, after, through time.Time, limit uint16,
) ([]TemporaryBanEvent, error) {
	if client == nil || ctx == nil || !after.Before(through) || limit < 1 || limit > MaxTemporaryBanEvents {
		return nil, ErrInvalidInput
	}
	parameters := url.Values{
		"param_after_ms":   {strconv.FormatInt(after.UTC().UnixMilli(), 10)},
		"param_through_ms": {strconv.FormatInt(through.UTC().UnixMilli(), 10)},
		"param_row_limit":  {strconv.FormatUint(uint64(limit), 10)},
	}
	rows, err := queryRows[temporaryBanRow](client, ctx, temporaryBanSQL, parameters, int(limit))
	if err != nil {
		return nil, err
	}
	result := make([]TemporaryBanEvent, 0, len(rows))
	for _, row := range rows {
		ingested := time.UnixMilli(row.IngestedMS).UTC()
		if !validOutputText(row.EventID, 128, true) || !validCanonicalUUID(row.TenantID) || !validCanonicalUUID(row.SiteID) ||
			(row.EventType != "waf" && row.EventType != "cc") || !validOutputText(row.RuleID, 128, false) ||
			!validOutputText(row.PolicyID, 64, false) || !ingested.After(after) || ingested.After(through) {
			return nil, ErrInvalidResponse
		}
		result = append(result, TemporaryBanEvent{
			EventID: row.EventID, TenantID: row.TenantID, SiteID: row.SiteID, EventType: row.EventType,
			ClientIP: unmappedIP(row.ClientIP), RuleID: row.RuleID, PolicyID: row.PolicyID,
			OccurredAt: time.UnixMilli(row.OccurredMS).UTC(), IngestedAt: ingested,
		})
	}
	return result, nil
}
