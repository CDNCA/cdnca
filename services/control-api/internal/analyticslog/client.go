package analyticslog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	defaultQueryTimeout    = 5 * time.Second
	defaultMaxResponse     = int64(4 << 20)
	maxDatabaseBytes       = 64
	nilUUID                = "00000000-0000-0000-0000-000000000000"
	maxLogCursorBytes      = 2048
	logCursorDomain        = "cdnca.analyticslog.cursor.v1"
	maxCapturedHeaderValue = 16 << 10
	maxCapturedBodyBytes   = 1 << 20
	maxCapturedBodyDepth   = 8
	maxCapturedMapKeys     = 128
	redactedCaptureValue   = "[REDACTED]"
)

// hostEventIDsHead/Tail wrap a payload state table into the host_event_ids
// CTE shared by the access and security page queries (fix-waflogdetail/2):
// host is not in the filter state, the latest payload carries it (tuple
// element 15 in both payloads). The filter is one host or a space-separated
// list; nothing is scanned unless a host filter is set.
const hostEventIDsHead = `host_event_ids AS
(
	SELECT event_id
	FROM `

const hostEventIDsTail = `
	PREWHERE {has_host:UInt8} = 1
		AND metric_version = 1
		AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		AND event_id IN (SELECT event_id FROM candidate_event_ids)
	WHERE ingested_at <= snapshot_at
	GROUP BY event_id
	HAVING has(splitByChar(' ', {host:String}), lower(tupleElement(argMaxMerge(latest_payload_state), 15)))
),
`

const accessPageSQL = `WITH
if(
    {has_snapshot:UInt8} = 1,
    fromUnixTimestamp64Milli({snapshot_ms:Int64}, 'UTC'),
	    now64(3, 'UTC') - INTERVAL 1 MILLISECOND
) AS snapshot_at,
candidate_event_ids AS
(
	SELECT event_id
	FROM access_event_query_index_state_v1
	PREWHERE metric_version = 1
		AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		AND occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
		AND occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
	WHERE ingested_at <= snapshot_at
	GROUP BY event_id
),
` + hostEventIDsHead + "access_event_query_payload_state_v1" + hostEventIDsTail + `selected_rows AS
(
	SELECT
		access.event_id AS event_id,
		argMaxMerge(latest_filter_state) AS latest_filter,
		if(
			uniqExactMerge(version_pair_state) > uniqExactMerge(ingested_at_state),
			toUInt64(2),
			toUInt64(1)
		) AS durable_version_count
	FROM
	(
		SELECT event_id, latest_filter_state, version_pair_state, ingested_at_state
		FROM access_event_query_index_state_v1
		PREWHERE metric_version = 1
			AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		WHERE ingested_at <= snapshot_at
	) AS access
	INNER JOIN candidate_event_ids USING (event_id)
	GROUP BY access.event_id
	HAVING durable_version_count > 1 OR
		(tupleElement(latest_filter, 1) >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
		AND tupleElement(latest_filter, 1) < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
		AND ({has_host:UInt8} = 0 OR event_id IN (SELECT event_id FROM host_event_ids))
		AND ({has_site:UInt8} = 0 OR tupleElement(latest_filter, 2) = toUUID({site_id:String}))
		AND ({has_node:UInt8} = 0 OR tupleElement(latest_filter, 3) = toUUID({node_id:String}))
		AND ({has_ip:UInt8} = 0 OR tupleElement(latest_filter, 5) = toIPv6({client_ip:String}))
		AND ({has_uri_path:UInt8} = 0 OR if({uri_path_prefix:UInt8} = 1,
			startsWith(if(startsWith(tupleElement(latest_filter, 4), '/'), replaceRegexpOne(tupleElement(latest_filter, 4), '[?#].*$', ''), ''), {uri_path:String}),
			if(startsWith(tupleElement(latest_filter, 4), '/'), replaceRegexpOne(tupleElement(latest_filter, 4), '[?#].*$', ''), '') = {uri_path:String}))
		AND ({has_status:UInt8} = 0 OR tupleElement(latest_filter, 12) = {status_code:UInt16})
		AND ({has_method:UInt8} = 0 OR tupleElement(latest_filter, 8) = {method:String})
		AND ({has_protocol:UInt8} = 0 OR tupleElement(latest_filter, 9) = {protocol:String})
		AND ({has_cache:UInt8} = 0 OR tupleElement(latest_filter, 10) = {cache_status:String})
		AND ({has_upstream_result:UInt8} = 0 OR tupleElement(latest_filter, 11) = {upstream_result:String})
		AND ({has_content_type:UInt8} = 0 OR tupleElement(latest_filter, 19) = {content_type:String} OR startsWith(tupleElement(latest_filter, 19), concat({content_type:String}, ';')))
		AND ({has_user_agent:UInt8} = 0 OR tupleElement(latest_filter, 20) = {user_agent:String})
		AND ({has_request_bytes_min:UInt8} = 0 OR tupleElement(latest_filter, 13) >= {request_bytes_min:UInt64})
		AND ({has_request_bytes_max:UInt8} = 0 OR tupleElement(latest_filter, 13) <= {request_bytes_max:UInt64})
		AND ({has_response_bytes_min:UInt8} = 0 OR tupleElement(latest_filter, 14) >= {response_bytes_min:UInt64})
		AND ({has_response_bytes_max:UInt8} = 0 OR tupleElement(latest_filter, 14) <= {response_bytes_max:UInt64})
		AND ({has_country:UInt8} = 0 OR tupleElement(latest_filter, 6) = {country_code:String})
		AND ({has_carrier:UInt8} = 0 OR tupleElement(latest_filter, 7) = {carrier:String})
		AND ({has_ja4:UInt8} = 0 OR tupleElement(latest_filter, 15) = {ja4:String})
		AND ({has_origin_connect_min:UInt8} = 0 OR tupleElement(latest_filter, 16) >= {origin_connect_us_min:UInt64})
		AND ({has_origin_connect_max:UInt8} = 0 OR tupleElement(latest_filter, 16) <= {origin_connect_us_max:UInt64})
		AND ({has_origin_first_byte_min:UInt8} = 0 OR tupleElement(latest_filter, 17) >= {origin_first_byte_us_min:UInt64})
		AND ({has_origin_first_byte_max:UInt8} = 0 OR tupleElement(latest_filter, 17) <= {origin_first_byte_us_max:UInt64})
		AND ({has_origin_total_min:UInt8} = 0 OR tupleElement(latest_filter, 18) >= {origin_total_us_min:UInt64})
		AND ({has_origin_total_max:UInt8} = 0 OR tupleElement(latest_filter, 18) <= {origin_total_us_max:UInt64})
		AND ({has_cursor:UInt8} = 0
			OR tupleElement(latest_filter, 1) < fromUnixTimestamp64Milli({cursor_occurred_at_ms:Int64}, 'UTC')
			OR (tupleElement(latest_filter, 1) = fromUnixTimestamp64Milli({cursor_occurred_at_ms:Int64}, 'UTC')
				AND event_id < {cursor_event_id:String})))
	ORDER BY durable_version_count > 1 DESC, tupleElement(latest_filter, 1) DESC, event_id DESC
	LIMIT {row_limit:UInt16}
),
payload_rows AS
(
	SELECT
		event_id,
		argMaxMerge(latest_payload_state) AS latest,
		argMaxMerge(listen_port_state) AS listen_port,
		argMaxMerge(upstream_addr_state) AS upstream_addr,
		if(
			uniqExactMerge(version_pair_state) > uniqExactMerge(ingested_at_state),
			toUInt64(2),
			toUInt64(1)
		) AS durable_version_count
	FROM access_event_query_payload_state_v1
	PREWHERE metric_version = 1
		AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		AND event_id IN (SELECT event_id FROM selected_rows)
	WHERE ingested_at <= snapshot_at
	GROUP BY event_id
)
SELECT
    event_id,
	toInt64(toUnixTimestamp64Milli(tupleElement(latest, 2))) AS occurred_at_ms,
	toString(tupleElement(latest, 3)) AS site_id,
	toString(tupleElement(latest, 4)) AS node_id,
	tupleElement(latest, 5) AS request_id,
	tupleElement(latest, 6) AS trace_id,
	tupleElement(latest, 7) AS config_version_id,
	tupleElement(latest, 15) AS host,
	toUInt16(ifNull(listen_port, 0)) AS listen_port,
	if(startsWith(tupleElement(latest, 16), '/'), replaceRegexpOne(tupleElement(latest, 16), '[?#].*$', ''), '') AS uri_path,
	toString(tupleElement(latest, 17)) AS client_ip,
	tupleElement(latest, 18) AS country_code,
	tupleElement(latest, 19) AS carrier,
	tupleElement(latest, 20) AS method,
	tupleElement(latest, 21) AS protocol,
	tupleElement(latest, 22) AS cache_status,
	tupleElement(latest, 23) AS upstream_result,
	ifNull(upstream_addr, '') AS upstream_addr,
	toUInt16(tupleElement(latest, 24)) AS status_code,
	toUInt64(tupleElement(latest, 25)) AS request_bytes,
	toUInt64(tupleElement(latest, 26)) AS response_bytes,
	toUInt64(tupleElement(latest, 27)) AS duration_us,
	tupleElement(latest, 8) AS task_id,
	tupleElement(latest, 9) AS installation_id,
	tupleElement(latest, 10) AS request_headers,
	tupleElement(latest, 11) AS response_headers,
	tupleElement(latest, 12) AS request_body,
	tupleElement(latest, 13) AS response_body,
	tupleElement(latest, 14) AS ja4,
	tupleElement(latest, 28) AS origin_connect_us,
	tupleElement(latest, 29) AS origin_first_byte_us,
	tupleElement(latest, 30) AS origin_total_us,
	toUInt64(ifNull(durable_version_count, 1)) AS latest_version_count,
    toInt64(toUnixTimestamp64Milli(snapshot_at)) AS snapshot_ms
FROM
payload_rows
ORDER BY toUInt64(ifNull(durable_version_count, 1)) > 1 DESC, tupleElement(latest, 2) DESC, event_id DESC
SETTINGS max_threads = 2
FORMAT JSONEachRow`

const blockEventPageSQL = `WITH
if(
    {has_snapshot:UInt8} = 1,
    fromUnixTimestamp64Milli({snapshot_ms:Int64}, 'UTC'),
	    now64(3, 'UTC') - INTERVAL 1 MILLISECOND
) AS snapshot_at,
candidate_event_ids AS
(
	SELECT event_id
	FROM security_event_query_index_state_v1
	PREWHERE metric_version = 1
		AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		AND occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
		AND occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
	WHERE ingested_at <= snapshot_at
	GROUP BY event_id
),
` + hostEventIDsHead + "security_event_query_payload_state_v1" + hostEventIDsTail + `selected_rows AS
(
	SELECT
		security.event_id AS event_id,
		argMaxMerge(latest_filter_state) AS latest_filter,
		if(
			uniqExactMerge(version_pair_state) > uniqExactMerge(ingested_at_state),
			toUInt64(2),
			toUInt64(1)
		) AS durable_version_count
	FROM
	(
		SELECT event_id, latest_filter_state, version_pair_state, ingested_at_state
		FROM security_event_query_index_state_v1
		PREWHERE metric_version = 1
			AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		WHERE ingested_at <= snapshot_at
	) AS security
	INNER JOIN candidate_event_ids USING (event_id)
	GROUP BY security.event_id
	HAVING durable_version_count > 1 OR
		(tupleElement(latest_filter, 1) >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
		AND tupleElement(latest_filter, 1) < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
		AND tupleElement(latest_filter, 9) IN ('block', 'challenge', 'log', 'temporary_ban')
		AND ({has_action:UInt8} = 0 OR tupleElement(latest_filter, 9) = {action:String})
		AND ({has_event_type:UInt8} = 0 OR tupleElement(latest_filter, 8) = {event_type:String})
		AND ({has_host:UInt8} = 0 OR event_id IN (SELECT event_id FROM host_event_ids))
		AND ({has_site:UInt8} = 0 OR tupleElement(latest_filter, 2) = toUUID({site_id:String}))
		AND ({has_node:UInt8} = 0 OR tupleElement(latest_filter, 3) = toUUID({node_id:String}))
		AND ({has_ip:UInt8} = 0 OR tupleElement(latest_filter, 5) = toIPv6({client_ip:String}))
		AND ({has_uri_path:UInt8} = 0 OR if({uri_path_prefix:UInt8} = 1,
			startsWith(if(startsWith(tupleElement(latest_filter, 4), '/'), replaceRegexpOne(tupleElement(latest_filter, 4), '[?#].*$', ''), ''), {uri_path:String}),
			if(startsWith(tupleElement(latest_filter, 4), '/'), replaceRegexpOne(tupleElement(latest_filter, 4), '[?#].*$', ''), '') = {uri_path:String}))
		AND ({has_status:UInt8} = 0 OR tupleElement(latest_filter, 10) = {status_code:UInt16})
		AND ({has_country:UInt8} = 0 OR tupleElement(latest_filter, 6) = {country_code:String})
		AND ({has_carrier:UInt8} = 0 OR tupleElement(latest_filter, 7) = {carrier:String})
		AND ({has_ja4:UInt8} = 0 OR tupleElement(latest_filter, 11) = {ja4:String})
		AND ({has_origin_connect_min:UInt8} = 0 OR tupleElement(latest_filter, 12) >= {origin_connect_us_min:UInt64})
		AND ({has_origin_connect_max:UInt8} = 0 OR tupleElement(latest_filter, 12) <= {origin_connect_us_max:UInt64})
		AND ({has_origin_first_byte_min:UInt8} = 0 OR tupleElement(latest_filter, 13) >= {origin_first_byte_us_min:UInt64})
		AND ({has_origin_first_byte_max:UInt8} = 0 OR tupleElement(latest_filter, 13) <= {origin_first_byte_us_max:UInt64})
		AND ({has_origin_total_min:UInt8} = 0 OR tupleElement(latest_filter, 14) >= {origin_total_us_min:UInt64})
		AND ({has_origin_total_max:UInt8} = 0 OR tupleElement(latest_filter, 14) <= {origin_total_us_max:UInt64})
		AND ({has_cursor:UInt8} = 0
			OR tupleElement(latest_filter, 1) < fromUnixTimestamp64Milli({cursor_occurred_at_ms:Int64}, 'UTC')
			OR (tupleElement(latest_filter, 1) = fromUnixTimestamp64Milli({cursor_occurred_at_ms:Int64}, 'UTC')
				AND event_id < {cursor_event_id:String})))
	ORDER BY durable_version_count > 1 DESC, tupleElement(latest_filter, 1) DESC, event_id DESC
	LIMIT {row_limit:UInt16}
),
payload_rows AS
(
	SELECT
		event_id,
		argMaxMerge(latest_payload_state) AS latest,
		if(
			uniqExactMerge(version_pair_state) > uniqExactMerge(ingested_at_state),
			toUInt64(2),
			toUInt64(1)
		) AS durable_version_count
	FROM security_event_query_payload_state_v1
	PREWHERE metric_version = 1
		AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		AND event_id IN (SELECT event_id FROM selected_rows)
	WHERE ingested_at <= snapshot_at
	GROUP BY event_id
),
evidence_rows AS
(
	SELECT event_id, argMaxMerge(latest_evidence_state) AS evidence
	FROM security_event_evidence_state_v1
	PREWHERE metric_version = 1
		AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		AND event_id IN (SELECT event_id FROM selected_rows)
	WHERE ingested_at <= snapshot_at
	GROUP BY event_id
),
count_rows AS
(
	SELECT event_id, argMaxMerge(latest_count_state) AS event_count
	FROM security_event_count_state_v1
	PREWHERE metric_version = 1
		AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
		AND event_id IN (SELECT event_id FROM selected_rows)
	WHERE ingested_at <= snapshot_at
	GROUP BY event_id
)
SELECT
    event_id,
	toInt64(toUnixTimestamp64Milli(tupleElement(latest, 2))) AS occurred_at_ms,
	toString(tupleElement(latest, 3)) AS site_id,
	toString(tupleElement(latest, 4)) AS node_id,
	tupleElement(latest, 5) AS request_id,
	tupleElement(latest, 6) AS trace_id,
	tupleElement(latest, 7) AS config_version_id,
	tupleElement(latest, 15) AS host,
	if(startsWith(tupleElement(latest, 16), '/'), replaceRegexpOne(tupleElement(latest, 16), '[?#].*$', ''), '') AS uri_path,
	if(startsWith(tupleElement(latest, 16), '/') AND position(tupleElement(latest, 16), '?') > 0,
		replaceRegexpOne(replaceRegexpOne(tupleElement(latest, 16), '^[^?#]*[?]', ''), '#.*$', ''), '') AS uri_query,
	toString(tupleElement(latest, 17)) AS client_ip,
	tupleElement(latest, 18) AS country_code,
	tupleElement(latest, 19) AS carrier,
	tupleElement(latest, 20) AS event_type,
	tupleElement(latest, 21) AS action,
	tupleElement(latest, 22) AS severity,
	tupleElement(latest, 23) AS rule_id,
	toUInt16(tupleElement(latest, 24)) AS status_code,
	toUInt64(tupleElement(latest, 25)) AS request_bytes,
	toUInt64(tupleElement(latest, 26)) AS response_bytes,
	tupleElement(latest, 8) AS task_id,
	tupleElement(latest, 9) AS installation_id,
	tupleElement(latest, 10) AS request_headers,
	tupleElement(latest, 11) AS response_headers,
	tupleElement(latest, 12) AS request_body,
	tupleElement(latest, 13) AS response_body,
	tupleElement(latest, 14) AS ja4,
	tupleElement(latest, 27) AS origin_connect_us,
	tupleElement(latest, 28) AS origin_first_byte_us,
	tupleElement(latest, 29) AS origin_total_us,
	toString(tupleElement(evidence, 1)) AS policy_id,
	toString(tupleElement(evidence, 2)) AS detector,
	toString(tupleElement(evidence, 3)) AS matched,
	toString(tupleElement(evidence, 4)) AS user_agent,
	toString(tupleElement(evidence, 5)) AS request_body_excerpt,
	toUInt64(if(ifNull(event_count, 0) = 0, 1, event_count)) AS count,
	toUInt64(ifNull(durable_version_count, 1)) AS latest_version_count,
    toInt64(toUnixTimestamp64Milli(snapshot_at)) AS snapshot_ms
FROM
payload_rows
LEFT JOIN evidence_rows USING (event_id)
LEFT JOIN count_rows USING (event_id)
ORDER BY toUInt64(ifNull(durable_version_count, 1)) > 1 DESC, tupleElement(latest, 2) DESC, event_id DESC
SETTINGS max_threads = 2
FORMAT JSONEachRow`

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type ClientConfig struct {
	Endpoint         string
	Database         string
	Username         string
	Password         string
	QueryTimeout     time.Duration
	MaxResponseBytes int64
	CursorKeyring    CursorKeyring
}

type CursorKeyring struct {
	ActiveKID string
	Keys      map[string][]byte
}

// ccBanHistorySQL aggregates CC auto-bans (one cc/temporary_ban event per ban
// activation, see edge/openresty/ccv2/engine.lua) per site + IP + rule (NF34).
const ccBanHistorySQL = `SELECT
	site_id,
	any(host) AS host,
	client_ip,
	rule_id,
	toUInt64(count()) AS ban_count,
	toInt64(toUnixTimestamp64Milli(min(occurred_at))) AS first_banned_at_ms,
	toInt64(toUnixTimestamp64Milli(max(occurred_at))) AS last_banned_at_ms
FROM security_events FINAL
WHERE metric_version = 1
	AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
	AND event_type = 'cc' AND action = 'temporary_ban'
	AND occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
	AND occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
	AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:Int64}, 'UTC')
	AND ({has_site:UInt8} = 0 OR site_id = toUUID({site_id:String}))
	AND ({has_ip:UInt8} = 0 OR client_ip = toIPv6({client_ip:String}))
GROUP BY site_id, client_ip, rule_id
ORDER BY last_banned_at_ms DESC, site_id, client_ip, rule_id
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

type ccBanRow struct {
	SiteID          string `json:"site_id"`
	Host            string `json:"host"`
	ClientIP        string `json:"client_ip"`
	RuleID          string `json:"rule_id"`
	BanCount        uint64 `json:"ban_count"`
	FirstBannedAtMS int64  `json:"first_banned_at_ms"`
	LastBannedAtMS  int64  `json:"last_banned_at_ms"`
}

var _ ccBanStore = (*Client)(nil)

// ListCCBans returns at most limit aggregated CC auto-bans, newest first.
func (client *Client) ListCCBans(ctx context.Context, scope scope, filter Filter, limit uint16) (CCBanPage, error) {
	filter = normalizeFilter(filter)
	snapshot := time.Now().UTC().Truncate(time.Millisecond)
	parameters := filterParameters(scope, filter, limit)
	parameters.Set("param_snapshot_ms", strconv.FormatInt(snapshot.UnixMilli(), 10))
	rows, err := queryRows[ccBanRow](client, ctx, ccBanHistorySQL, parameters, int(limit)+1)
	if err != nil {
		return CCBanPage{}, err
	}
	page := CCBanPage{SnapshotAt: snapshot, Truncated: len(rows) > int(limit)}
	if page.Truncated {
		rows = rows[:limit]
	}
	page.Items = make([]CCBan, 0, len(rows))
	for index, row := range rows {
		address, parseErr := netip.ParseAddr(row.ClientIP)
		first, last := time.UnixMilli(row.FirstBannedAtMS).UTC(), time.UnixMilli(row.LastBannedAtMS).UTC()
		if parseErr != nil || !validCanonicalUUID(row.SiteID) || (filter.SiteID != "" && row.SiteID != filter.SiteID) ||
			!validOutputText(row.Host, 253, false) || !validOutputText(row.RuleID, 128, false) || row.BanCount == 0 ||
			first.After(last) || first.Before(filter.From) || !last.Before(filter.To) ||
			(index > 0 && last.After(page.Items[index-1].LastBannedAt)) {
			return CCBanPage{}, ErrInvalidResponse
		}
		address = address.Unmap()
		if filter.ClientIP != "" && !matchesIP(address, filter.ClientIP) {
			return CCBanPage{}, ErrInvalidResponse
		}
		page.Items = append(page.Items, CCBan{
			SiteID: row.SiteID, Host: row.Host, ClientIP: address.String(), RuleID: row.RuleID,
			BanCount: row.BanCount, FirstBannedAt: first, LastBannedAt: last,
		})
	}
	return page, nil
}

const redactedCursorKeyring = "analyticslog.CursorKeyring{keys:redacted}"

func (CursorKeyring) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedCursorKeyring))
}
func (CursorKeyring) String() string   { return redactedCursorKeyring }
func (CursorKeyring) GoString() string { return redactedCursorKeyring }
func (CursorKeyring) MarshalJSON() ([]byte, error) {
	return []byte(`"analyticslog.CursorKeyring{keys:redacted}"`), nil
}

type Client struct {
	endpoint         *url.URL
	database         string
	username         string
	password         string
	http             HTTPClient
	queryTimeout     time.Duration
	maxResponseBytes int64
	cursorKeys       CursorKeyring
}

type accessRow struct {
	EventID           string            `json:"event_id"`
	OccurredAtMS      int64             `json:"occurred_at_ms"`
	SiteID            string            `json:"site_id"`
	NodeID            string            `json:"node_id"`
	RequestID         requiredString    `json:"request_id"`
	TraceID           requiredString    `json:"trace_id"`
	ConfigVersion     requiredString    `json:"config_version_id"`
	Host              string            `json:"host"`
	ListenPort        uint16            `json:"listen_port"`
	URIPath           string            `json:"uri_path"`
	ClientIP          string            `json:"client_ip"`
	CountryCode       string            `json:"country_code"`
	Carrier           string            `json:"carrier"`
	Method            string            `json:"method"`
	Protocol          string            `json:"protocol"`
	CacheStatus       string            `json:"cache_status"`
	UpstreamResult    string            `json:"upstream_result"`
	UpstreamAddr      string            `json:"upstream_addr"`
	StatusCode        uint16            `json:"status_code"`
	RequestBytes      uint64            `json:"request_bytes"`
	ResponseBytes     uint64            `json:"response_bytes"`
	DurationUS        uint64            `json:"duration_us"`
	TaskID            *string           `json:"task_id"`
	InstallationID    string            `json:"installation_id"`
	RequestHeaders    map[string]string `json:"request_headers"`
	ResponseHeaders   map[string]string `json:"response_headers"`
	RequestBody       *string           `json:"request_body"`
	ResponseBody      *string           `json:"response_body"`
	JA4               *string           `json:"ja4"`
	OriginConnectUS   *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS     *uint64           `json:"origin_total_us"`
	VersionCount      uint64            `json:"latest_version_count"`
	SnapshotMS        int64             `json:"snapshot_ms"`
}

type blockEventRow struct {
	EventID            string            `json:"event_id"`
	OccurredAtMS       int64             `json:"occurred_at_ms"`
	SiteID             string            `json:"site_id"`
	NodeID             string            `json:"node_id"`
	RequestID          requiredString    `json:"request_id"`
	TraceID            requiredString    `json:"trace_id"`
	ConfigVersion      requiredString    `json:"config_version_id"`
	Host               string            `json:"host"`
	URIPath            string            `json:"uri_path"`
	URIQuery           string            `json:"uri_query"`
	ClientIP           string            `json:"client_ip"`
	CountryCode        string            `json:"country_code"`
	Carrier            string            `json:"carrier"`
	EventType          string            `json:"event_type"`
	Action             string            `json:"action"`
	Severity           string            `json:"severity"`
	RuleID             string            `json:"rule_id"`
	StatusCode         uint16            `json:"status_code"`
	RequestBytes       uint64            `json:"request_bytes"`
	ResponseBytes      uint64            `json:"response_bytes"`
	TaskID             *string           `json:"task_id"`
	InstallationID     string            `json:"installation_id"`
	RequestHeaders     map[string]string `json:"request_headers"`
	ResponseHeaders    map[string]string `json:"response_headers"`
	RequestBody        *string           `json:"request_body"`
	ResponseBody       *string           `json:"response_body"`
	JA4                *string           `json:"ja4"`
	OriginConnectUS    *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS  *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS      *uint64           `json:"origin_total_us"`
	PolicyID           string            `json:"policy_id"`
	Detector           string            `json:"detector"`
	Matched            string            `json:"matched"`
	UserAgent          string            `json:"user_agent"`
	RequestBodyExcerpt string            `json:"request_body_excerpt"`
	Count              uint64            `json:"count"`
	VersionCount       uint64            `json:"latest_version_count"`
	SnapshotMS         int64             `json:"snapshot_ms"`
}

type requiredString string

func (value *requiredString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return ErrInvalidResponse
	}
	var decoded string
	if err := json.Unmarshal(data, &decoded); err != nil {
		return ErrInvalidResponse
	}
	*value = requiredString(decoded)
	return nil
}

type logCursor struct {
	Version      uint8  `json:"v"`
	Query        string `json:"q"`
	SnapshotMS   int64  `json:"s"`
	OccurredAtMS int64  `json:"o"`
	EventID      string `json:"e"`
}

type logCursorEnvelope struct {
	Payload string `json:"p"`
	KID     string `json:"k"`
	Tag     string `json:"t"`
}

type logCursorPayload logCursor

func (cursor *logCursor) UnmarshalJSON(data []byte) error {
	payload, _, _, ok := decodeLogCursorEnvelope(data)
	if !ok {
		return ErrInvalidInput
	}
	decoded, ok := decodeLogCursorPayload(payload)
	if !ok {
		return ErrInvalidInput
	}
	*cursor = decoded
	return nil
}

func NewClient(config ClientConfig, httpClient HTTPClient) (*Client, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || !validDatabase(config.Database) ||
		(config.Username == "" && config.Password != "") ||
		(endpoint.Scheme == "http" && !loopback(endpoint.Hostname())) {
		return nil, ErrInvalidConfiguration
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponse
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > 30*time.Second || config.MaxResponseBytes <= 0 ||
		config.MaxResponseBytes > 16<<20 {
		return nil, ErrInvalidConfiguration
	}
	cursorKeys, ok := validatedLogCursorKeyring(config.CursorKeyring)
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       config.QueryTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	} else if standard, ok := httpClient.(*http.Client); ok {
		copy := *standard
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		httpClient = &copy
	}
	endpoint.Path = "/"
	return &Client{
		endpoint: endpoint, database: config.Database, username: config.Username, password: config.Password,
		http: httpClient, queryTimeout: config.QueryTimeout, maxResponseBytes: config.MaxResponseBytes,
		cursorKeys: cursorKeys,
	}, nil
}

func (client *Client) ListAccess(
	ctx context.Context,
	scope scope,
	filter Filter,
	limit uint16,
	cursor string,
) (AccessPage, error) {
	if filter.HasStatus && filter.StatusCode == 0 {
		return AccessPage{}, ErrInvalidInput
	}
	filter = normalizeFilter(filter)
	state, parameters, err := client.pageParameters(ctx, scope, filter, limit, cursor, "access.desc")
	if err != nil {
		return AccessPage{}, err
	}
	rows, err := queryRows[accessRow](client, ctx, accessPageSQL, parameters, int(limit)+1)
	if err != nil {
		return AccessPage{}, err
	}
	if len(rows) > int(limit)+1 {
		return AccessPage{}, ErrInvalidResponse
	}
	if err := validateAccessRows(rows, filter, state); err != nil {
		return AccessPage{}, err
	}
	pageRows := rows
	if len(pageRows) > int(limit) {
		pageRows = pageRows[:limit]
	}
	page := AccessPage{Items: make([]AccessLog, len(pageRows))}
	if len(rows) > 0 {
		page.SnapshotAt = time.UnixMilli(rows[0].SnapshotMS).UTC()
	} else if state.SnapshotMS > 0 {
		page.SnapshotAt = time.UnixMilli(state.SnapshotMS).UTC()
	}
	for index, row := range pageRows {
		clientIP := unmappedIP(row.ClientIP)
		requestBody, err := decodeCapturedBody(row.RequestBody)
		if err != nil {
			return AccessPage{}, err
		}
		responseBody, err := decodeCapturedBody(row.ResponseBody)
		if err != nil {
			return AccessPage{}, err
		}
		page.Items[index] = AccessLog{
			EventID: row.EventID, OccurredAt: time.UnixMilli(row.OccurredAtMS).UTC(), SiteID: row.SiteID,
			NodeID: row.NodeID, RequestID: string(row.RequestID), TraceID: string(row.TraceID), ConfigVersion: string(row.ConfigVersion),
			Host: row.Host, ListenPort: row.ListenPort, URIPath: safeURIPath(row.URIPath), ClientIP: clientIP,
			CountryCode: row.CountryCode, Carrier: row.Carrier, Method: row.Method, Protocol: row.Protocol,
			CacheStatus: row.CacheStatus, UpstreamResult: row.UpstreamResult, UpstreamAddr: row.UpstreamAddr, StatusCode: row.StatusCode,
			RequestBytes: row.RequestBytes, ResponseBytes: row.ResponseBytes, DurationUS: row.DurationUS,
			TaskID: row.TaskID, InstallationID: row.InstallationID,
			RequestHeaders: nonnilCapturedHeaders(row.RequestHeaders), ResponseHeaders: nonnilCapturedHeaders(row.ResponseHeaders),
			RequestBody: requestBody, ResponseBody: responseBody, JA4: row.JA4,
			OriginConnectUS: row.OriginConnectUS, OriginFirstByteUS: row.OriginFirstByteUS, OriginTotalUS: row.OriginTotalUS,
		}
	}
	if len(rows) > int(limit) {
		last := pageRows[len(pageRows)-1]
		state.SnapshotMS = rows[0].SnapshotMS
		if state.SnapshotMS <= 0 {
			return AccessPage{}, ErrCapabilityUnsupported
		}
		state.OccurredAtMS = last.OccurredAtMS
		state.EventID = last.EventID
		page.NextCursor, err = encodeLogCursor(client.cursorKeys, state)
		if err != nil {
			return AccessPage{}, err
		}
	}
	return page, nil
}

func (client *Client) ListBlockEvents(
	ctx context.Context,
	scope scope,
	filter Filter,
	limit uint16,
	cursor string,
) (BlockEventPage, error) {
	if filter.Method != "" || filter.Protocol != "" || filter.CacheStatus != "" {
		return BlockEventPage{}, ErrInvalidInput
	}
	filter = normalizeFilter(filter)
	state, parameters, err := client.pageParameters(ctx, scope, filter, limit, cursor, "security.desc")
	if err != nil {
		return BlockEventPage{}, err
	}
	rows, err := queryRows[blockEventRow](client, ctx, blockEventPageSQL, parameters, int(limit)+1)
	if err != nil {
		return BlockEventPage{}, err
	}
	if len(rows) > int(limit)+1 {
		return BlockEventPage{}, ErrInvalidResponse
	}
	if err := validateBlockEventRows(rows, filter, state); err != nil {
		return BlockEventPage{}, err
	}
	pageRows := rows
	if len(pageRows) > int(limit) {
		pageRows = pageRows[:limit]
	}
	page := BlockEventPage{Items: make([]BlockEvent, len(pageRows))}
	if len(rows) > 0 {
		page.SnapshotAt = time.UnixMilli(rows[0].SnapshotMS).UTC()
	} else if state.SnapshotMS > 0 {
		page.SnapshotAt = time.UnixMilli(state.SnapshotMS).UTC()
	}
	for index, row := range pageRows {
		clientIP := unmappedIP(row.ClientIP)
		requestBody, err := decodeCapturedBody(row.RequestBody)
		if err != nil {
			return BlockEventPage{}, err
		}
		responseBody, err := decodeCapturedBody(row.ResponseBody)
		if err != nil {
			return BlockEventPage{}, err
		}
		page.Items[index] = BlockEvent{
			EventID: row.EventID, OccurredAt: time.UnixMilli(row.OccurredAtMS).UTC(), SiteID: row.SiteID,
			NodeID: row.NodeID, RequestID: string(row.RequestID), TraceID: string(row.TraceID), ConfigVersion: string(row.ConfigVersion),
			Host: row.Host, URIPath: safeURIPath(row.URIPath), URIQuery: row.URIQuery, ClientIP: clientIP,
			CountryCode: row.CountryCode, Carrier: row.Carrier, EventType: row.EventType, Action: row.Action,
			Severity: row.Severity, RuleID: row.RuleID, StatusCode: row.StatusCode,
			RequestBytes: row.RequestBytes, ResponseBytes: row.ResponseBytes,
			TaskID: row.TaskID, InstallationID: row.InstallationID,
			RequestHeaders: nonnilCapturedHeaders(row.RequestHeaders), ResponseHeaders: nonnilCapturedHeaders(row.ResponseHeaders),
			RequestBody: requestBody, ResponseBody: responseBody, JA4: row.JA4,
			OriginConnectUS: row.OriginConnectUS, OriginFirstByteUS: row.OriginFirstByteUS, OriginTotalUS: row.OriginTotalUS,
			PolicyID: row.PolicyID, Detector: row.Detector, Matched: row.Matched, UserAgent: row.UserAgent,
			RequestBodyExcerpt: row.RequestBodyExcerpt, Count: max(row.Count, 1),
		}
	}
	if len(rows) > int(limit) {
		last := pageRows[len(pageRows)-1]
		state.SnapshotMS = rows[0].SnapshotMS
		if state.SnapshotMS <= 0 {
			return BlockEventPage{}, ErrCapabilityUnsupported
		}
		state.OccurredAtMS = last.OccurredAtMS
		state.EventID = last.EventID
		page.NextCursor, err = encodeLogCursor(client.cursorKeys, state)
		if err != nil {
			return BlockEventPage{}, err
		}
	}
	return page, nil
}

func (client *Client) pageParameters(
	ctx context.Context,
	scope scope,
	filter Filter,
	limit uint16,
	cursor string,
	kind string,
) (logCursor, url.Values, error) {
	if client == nil || ctx == nil || !validScope(scope) || limit == 0 || limit > MaxLimit ||
		validateFilter(filter) != nil {
		return logCursor{}, nil, ErrInvalidInput
	}
	filter = normalizeFilter(filter)
	fingerprint := logFingerprint(scope, filter, kind)
	state := logCursor{Version: 1, Query: fingerprint}
	if cursor != "" {
		var err error
		state, err = decodeLogCursor(client.cursorKeys, cursor, fingerprint)
		if err != nil {
			return logCursor{}, nil, err
		}
	}
	parameters := filterParameters(scope, filter, limit)
	parameters.Set("param_has_snapshot", boolParameter(cursor != ""))
	parameters.Set("param_snapshot_ms", strconv.FormatInt(state.SnapshotMS, 10))
	parameters.Set("param_has_cursor", boolParameter(cursor != ""))
	parameters.Set("param_cursor_occurred_at_ms", strconv.FormatInt(state.OccurredAtMS, 10))
	parameters.Set("param_cursor_event_id", state.EventID)
	return state, parameters, nil
}

func filterParameters(scope scope, filter Filter, limit uint16) url.Values {
	// A platform scope (tenantID "") reads every tenant; the time window and
	// row limit still bound the scan.
	tenantID, tenantScoped := scope.tenantID, "1"
	if scope.platform() {
		tenantID, tenantScoped = nilUUID, "0"
	}
	values := url.Values{
		"param_tenant_scoped": {tenantScoped},
		"param_tenant_id":     {tenantID},
		"param_from_ms":   {strconv.FormatInt(filter.From.UnixMilli(), 10)},
		"param_to_ms":     {strconv.FormatInt(filter.To.UnixMilli(), 10)},
		"param_row_limit": {strconv.FormatUint(uint64(limit+1), 10)},
	}
	setOptional(values, "site", "site_id", filter.SiteID)
	setOptional(values, "host", "host", filter.Host)
	setOptional(values, "node", "node_id", filter.NodeID)
	setOptional(values, "ip", "client_ip", filter.ClientIP)
	setOptional(values, "uri_path", "uri_path", filter.URIPath)
	values.Set("param_uri_path_prefix", boolParameter(filter.URIPathPrefix))
	setOptional(values, "method", "method", filter.Method)
	setOptional(values, "protocol", "protocol", filter.Protocol)
	setOptional(values, "cache", "cache_status", filter.CacheStatus)
	setOptional(values, "upstream_result", "upstream_result", filter.UpstreamResult)
	setOptional(values, "content_type", "content_type", filter.ContentType)
	setOptional(values, "user_agent", "user_agent", filter.UserAgent)
	setOptional(values, "country", "country_code", filter.CountryCode)
	setOptional(values, "carrier", "carrier", filter.Carrier)
	setOptional(values, "action", "action", filter.Action)
	setOptional(values, "event_type", "event_type", filter.EventType)
	setOptional(values, "ja4", "ja4", filter.JA4)
	setOptionalUint64(values, "origin_connect_min", "origin_connect_us_min", filter.OriginConnectUSMin)
	setOptionalUint64(values, "origin_connect_max", "origin_connect_us_max", filter.OriginConnectUSMax)
	setOptionalUint64(values, "origin_first_byte_min", "origin_first_byte_us_min", filter.OriginFirstByteUSMin)
	setOptionalUint64(values, "origin_first_byte_max", "origin_first_byte_us_max", filter.OriginFirstByteUSMax)
	setOptionalUint64(values, "origin_total_min", "origin_total_us_min", filter.OriginTotalUSMin)
	setOptionalUint64(values, "origin_total_max", "origin_total_us_max", filter.OriginTotalUSMax)
	setOptionalUint64(values, "request_bytes_min", "request_bytes_min", filter.RequestBytesMin)
	setOptionalUint64(values, "request_bytes_max", "request_bytes_max", filter.RequestBytesMax)
	setOptionalUint64(values, "response_bytes_min", "response_bytes_min", filter.ResponseBytesMin)
	setOptionalUint64(values, "response_bytes_max", "response_bytes_max", filter.ResponseBytesMax)
	if filter.SiteID == "" {
		values.Set("param_site_id", nilUUID)
	}
	if filter.NodeID == "" {
		values.Set("param_node_id", nilUUID)
	}
	if filter.ClientIP == "" {
		values.Set("param_client_ip", "::")
	}
	values.Set("param_has_status", boolParameter(filter.HasStatus))
	values.Set("param_status_code", strconv.FormatUint(uint64(filter.StatusCode), 10))
	return values
}

func setOptional(values url.Values, flagName, parameterName, value string) {
	values.Set("param_has_"+flagName, boolParameter(value != ""))
	values.Set("param_"+parameterName, value)
}

func setOptionalUint64(values url.Values, flagName, parameterName string, value *uint64) {
	values.Set("param_has_"+flagName, boolParameter(value != nil))
	if value == nil {
		values.Set("param_"+parameterName, "0")
		return
	}
	values.Set("param_"+parameterName, strconv.FormatUint(*value, 10))
}

func boolParameter(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func logFingerprint(scope scope, filter Filter, kind string) string {
	parameters := filterParameters(scope, normalizeFilter(filter), 1)
	parameters.Del("param_row_limit")
	canonical := "analytics-log-v1\x00" + kind + "\x00" + parameters.Encode()
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validatedLogCursorKeyring(keyring CursorKeyring) (CursorKeyring, bool) {
	if !validLogCursorKID(keyring.ActiveKID) || len(keyring.Keys) == 0 || len(keyring.Keys) > 8 {
		return CursorKeyring{}, false
	}
	result := CursorKeyring{ActiveKID: keyring.ActiveKID, Keys: make(map[string][]byte, len(keyring.Keys))}
	valid := false
	defer func() {
		if !valid {
			for kid, key := range result.Keys {
				clear(key)
				delete(result.Keys, kid)
			}
		}
	}()
	for kid, key := range keyring.Keys {
		if !validLogCursorKID(kid) || len(key) < 32 || len(key) > 64 {
			return CursorKeyring{}, false
		}
		result.Keys[kid] = append([]byte(nil), key...)
	}
	if _, ok := result.Keys[result.ActiveKID]; !ok {
		return CursorKeyring{}, false
	}
	valid = true
	return result, true
}

func validLogCursorKID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if !(alphaNumeric || character == '.' || character == '_' || character == '-') || index == 0 && !alphaNumeric {
			return false
		}
	}
	return true
}

func encodeLogCursor(keyring CursorKeyring, cursor logCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	key, ok := keyring.Keys[keyring.ActiveKID]
	if err != nil || !ok {
		return "", ErrInvalidResponse
	}
	tag := logCursorMAC(logCursorDomain, keyring.ActiveKID, payload, key)
	packet, err := json.Marshal(logCursorEnvelope{
		Payload: base64.RawURLEncoding.EncodeToString(payload),
		KID:     keyring.ActiveKID,
		Tag:     base64.RawURLEncoding.EncodeToString(tag),
	})
	if err != nil {
		return "", ErrInvalidResponse
	}
	encoded := base64.RawURLEncoding.EncodeToString(packet)
	if len(encoded) > maxLogCursorBytes {
		return "", ErrInvalidResponse
	}
	return encoded, nil
}

func decodeLogCursor(keyring CursorKeyring, encoded, fingerprint string) (logCursor, error) {
	if len(encoded) == 0 || len(encoded) > maxLogCursorBytes {
		return logCursor{}, ErrInvalidInput
	}
	packet, ok := decodeCanonicalRawURL(encoded, 1, maxLogCursorBytes)
	if !ok {
		return logCursor{}, ErrInvalidInput
	}
	payload, kid, tag, ok := decodeLogCursorEnvelope(packet)
	if !ok {
		return logCursor{}, ErrInvalidInput
	}
	key, ok := keyring.Keys[kid]
	if !ok || !hmac.Equal(tag, logCursorMAC(logCursorDomain, kid, payload, key)) {
		return logCursor{}, ErrInvalidInput
	}
	cursor, ok := decodeLogCursorPayload(payload)
	if !ok ||
		cursor.Version != 1 || cursor.Query != fingerprint || cursor.SnapshotMS <= 0 || cursor.OccurredAtMS <= 0 ||
		!validEventID(cursor.EventID) {
		return logCursor{}, ErrInvalidInput
	}
	return cursor, nil
}

func decodeLogCursorEnvelope(packet []byte) ([]byte, string, []byte, bool) {
	decoder := json.NewDecoder(bytes.NewReader(packet))
	decoder.DisallowUnknownFields()
	var envelope logCursorEnvelope
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validLogCursorKID(envelope.KID) {
		return nil, "", nil, false
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, packet) {
		return nil, "", nil, false
	}
	payload, ok := decodeCanonicalRawURL(envelope.Payload, 1, maxLogCursorBytes)
	if !ok {
		return nil, "", nil, false
	}
	tag, ok := decodeCanonicalRawURL(envelope.Tag, sha256.Size, sha256.Size)
	if !ok {
		return nil, "", nil, false
	}
	return payload, envelope.KID, tag, true
}

func decodeLogCursorPayload(payload []byte) (logCursor, bool) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded logCursorPayload
	if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return logCursor{}, false
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, payload) {
		return logCursor{}, false
	}
	return logCursor(decoded), true
}

func logCursorMAC(domain, kid string, payload, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(kid))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func decodeCanonicalRawURL(encoded string, minimum, maximum int) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, false
	}
	return decoded, true
}

func queryRows[T any](client *Client, ctx context.Context, query string, parameters url.Values, maximumRows int) ([]T, error) {
	if maximumRows <= 0 {
		return nil, ErrInvalidResponse
	}
	var rows []T
	err := client.execute(ctx, query, parameters, func(encoded []byte) error {
		if !utf8.Valid(encoded) {
			return ErrInvalidResponse
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		for {
			var row T
			if err := decoder.Decode(&row); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
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

func (client *Client) execute(ctx context.Context, query string, parameters url.Values, decode func([]byte) error) error {
	requestContext, cancel := context.WithTimeout(ctx, client.queryTimeout)
	defer cancel()
	if err := requestContext.Err(); err != nil {
		return err
	}
	deadline, _ := requestContext.Deadline()
	budgetMilliseconds := time.Until(deadline) / time.Millisecond
	if budgetMilliseconds <= 0 {
		return context.DeadlineExceeded
	}
	target := *client.endpoint
	values := target.Query()
	values.Set("database", client.database)
	values.Set("max_execution_time", strconv.FormatFloat(float64(budgetMilliseconds)/1000, 'f', 3, 64))
	values.Set("timeout_overflow_mode", "throw")
	values.Set("output_format_json_quote_64bit_integers", "0")
	for key, entries := range parameters {
		for _, entry := range entries {
			values.Add(key, entry)
		}
	}
	target.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, target.String(), strings.NewReader(query))
	if err != nil {
		return ErrInvalidInput
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	request.Header.Set("Accept-Encoding", "identity")
	if client.username != "" {
		request.SetBasicAuth(client.username, client.password)
	}
	response, err := client.http.Do(request)
	if err != nil {
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return ErrStorageUnavailable
	}
	if response == nil || response.Body == nil {
		return ErrInvalidResponse
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, min(client.maxResponseBytes, int64(64<<10))+1))
		return ErrStorageUnavailable
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, client.maxResponseBytes+1))
	if err != nil {
		if requestContext.Err() != nil {
			return requestContext.Err()
		}
		return ErrInvalidResponse
	}
	if int64(len(encoded)) > client.maxResponseBytes {
		return ErrResponseTooLarge
	}
	if decode == nil || decode(encoded) != nil {
		return ErrInvalidResponse
	}
	return nil
}

func validateAccessRows(rows []accessRow, filter Filter, cursor logCursor) error {
	if err := validatePageSnapshot(rows, cursor, func(row accessRow) int64 { return row.SnapshotMS }); err != nil {
		return err
	}
	for _, row := range rows {
		if row.VersionCount > 1 {
			return ErrCapabilityUnsupported
		}
		if row.VersionCount != 1 {
			return ErrInvalidResponse
		}
	}
	seen := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		occurredAt := time.UnixMilli(row.OccurredAtMS).UTC()
		clientIP, err := netip.ParseAddr(row.ClientIP)
		if err != nil || !validEventID(row.EventID) || !validUUID(row.SiteID) || !validUUID(row.NodeID) ||
			!validOutputText(string(row.RequestID), 128, false) || !validOutputText(string(row.TraceID), 128, false) ||
			!validCanonicalUUID(string(row.ConfigVersion)) ||
			!validOutputText(row.Host, 253, true) || !validOutputPath(row.URIPath) ||
			!validOutputText(row.CountryCode, 8, false) || !validOutputText(row.Carrier, 128, false) ||
			!validTokenFilter(row.Method, 32) || row.Method == "" || !validProtocolFilter(row.Protocol) || row.Protocol == "" ||
			!validTokenFilter(row.CacheStatus, 32) || row.CacheStatus == "" ||
			!validOutputText(row.UpstreamResult, 64, false) || !validOutputText(row.UpstreamAddr, 64, false) ||
			row.StatusCode < 100 || row.StatusCode > 599 ||
			!validStoredCapture(row.TaskID, row.InstallationID, row.RequestHeaders, row.ResponseHeaders, row.RequestBody, row.ResponseBody,
				row.JA4, row.OriginConnectUS, row.OriginFirstByteUS, row.OriginTotalUS) ||
			occurredAt.Before(filter.From) || !occurredAt.Before(filter.To) || !accessRowMatches(row, clientIP, filter) {
			return ErrInvalidResponse
		}
		if _, duplicate := seen[row.EventID]; duplicate {
			return ErrInvalidResponse
		}
		seen[row.EventID] = struct{}{}
		if index > 0 && !rowsOrdered(rows[index-1].OccurredAtMS, rows[index-1].EventID, row.OccurredAtMS, row.EventID) {
			return ErrInvalidResponse
		}
		if cursor.EventID != "" && !rowsOrdered(cursor.OccurredAtMS, cursor.EventID, row.OccurredAtMS, row.EventID) {
			return ErrInvalidResponse
		}
	}
	return nil
}

func validateBlockEventRows(rows []blockEventRow, filter Filter, cursor logCursor) error {
	if err := validatePageSnapshot(rows, cursor, func(row blockEventRow) int64 { return row.SnapshotMS }); err != nil {
		return err
	}
	for _, row := range rows {
		if row.VersionCount > 1 {
			return ErrCapabilityUnsupported
		}
		if row.VersionCount != 1 {
			return ErrInvalidResponse
		}
	}
	seen := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		occurredAt := time.UnixMilli(row.OccurredAtMS).UTC()
		clientIP, err := netip.ParseAddr(row.ClientIP)
		if err != nil || !validEventID(row.EventID) || !validUUID(row.SiteID) || !validUUID(row.NodeID) ||
			!validOutputText(string(row.RequestID), 128, false) || !validOutputText(string(row.TraceID), 128, false) ||
			!validCanonicalUUID(string(row.ConfigVersion)) ||
			!validOutputText(row.Host, 253, true) || !validOutputPath(row.URIPath) || !validOutputQuery(row.URIQuery) ||
			!validOutputText(row.CountryCode, 8, false) || !validOutputText(row.Carrier, 128, false) ||
			!validOutputText(row.EventType, 64, true) || !slices.Contains(SecurityLogActions, row.Action) ||
			!validOutputText(row.Severity, 32, true) || !validOutputText(row.RuleID, 128, false) ||
			(row.StatusCode != 0 && (row.StatusCode < 100 || row.StatusCode > 599)) ||
			!validStoredCapture(row.TaskID, row.InstallationID, row.RequestHeaders, row.ResponseHeaders, row.RequestBody, row.ResponseBody,
				row.JA4, row.OriginConnectUS, row.OriginFirstByteUS, row.OriginTotalUS) ||
			row.PolicyID != "" && !validUUID(row.PolicyID) || !validOutputText(row.Detector, 16, false) ||
			len(row.Matched) > 256 || !utf8.ValidString(row.Matched) || len(row.UserAgent) > 512 || !utf8.ValidString(row.UserAgent) ||
			len(row.RequestBodyExcerpt) > 1024 || !utf8.ValidString(row.RequestBodyExcerpt) ||
			row.Count > maxSecurityEventCount ||
			occurredAt.Before(filter.From) || !occurredAt.Before(filter.To) || !blockEventRowMatches(row, clientIP, filter) {
			return ErrInvalidResponse
		}
		if _, duplicate := seen[row.EventID]; duplicate {
			return ErrInvalidResponse
		}
		seen[row.EventID] = struct{}{}
		if index > 0 && !rowsOrdered(rows[index-1].OccurredAtMS, rows[index-1].EventID, row.OccurredAtMS, row.EventID) {
			return ErrInvalidResponse
		}
		if cursor.EventID != "" && !rowsOrdered(cursor.OccurredAtMS, cursor.EventID, row.OccurredAtMS, row.EventID) {
			return ErrInvalidResponse
		}
	}
	return nil
}

func validatePageSnapshot[T any](rows []T, cursor logCursor, snapshot func(T) int64) error {
	var expected int64
	if cursor.SnapshotMS > 0 {
		expected = cursor.SnapshotMS
	}
	for _, row := range rows {
		value := snapshot(row)
		if value < 0 || value == 0 && expected > 0 || value == 0 && cursor.SnapshotMS > 0 {
			return ErrInvalidResponse
		}
		if value == 0 {
			continue
		}
		if expected == 0 {
			expected = value
		}
		if value != expected {
			return ErrInvalidResponse
		}
	}
	return nil
}

func accessRowMatches(row accessRow, clientIP netip.Addr, filter Filter) bool {
	return (filter.SiteID == "" || row.SiteID == filter.SiteID) &&
		hostFilterMatches(row.Host, filter.Host) &&
		(filter.NodeID == "" || row.NodeID == filter.NodeID) && matchesIP(clientIP, filter.ClientIP) &&
		uriPathMatches(row.URIPath, filter) &&
		(!filter.HasStatus || row.StatusCode == filter.StatusCode) &&
		(filter.Method == "" || row.Method == filter.Method) &&
		(filter.Protocol == "" || row.Protocol == filter.Protocol) &&
		(filter.CacheStatus == "" || row.CacheStatus == filter.CacheStatus) &&
		(filter.UpstreamResult == "" || row.UpstreamResult == filter.UpstreamResult) &&
		(filter.ContentType == "" || accessRowContentType(row) == filter.ContentType) &&
		(filter.UserAgent == "" || capturedHeader(row.RequestHeaders, "User-Agent") == filter.UserAgent) &&
		valueRangeMatches(row.RequestBytes, filter.RequestBytesMin, filter.RequestBytesMax) &&
		valueRangeMatches(row.ResponseBytes, filter.ResponseBytesMin, filter.ResponseBytesMax) &&
		(filter.CountryCode == "" || row.CountryCode == filter.CountryCode) &&
		(filter.Carrier == "" || row.Carrier == filter.Carrier) && captureFilterMatches(row.JA4,
		row.OriginConnectUS, row.OriginFirstByteUS, row.OriginTotalUS, filter)
}

func accessRowContentType(row accessRow) string {
	value := capturedHeader(row.ResponseHeaders, "Content-Type")
	mediaType, _, _ := strings.Cut(value, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	if !validContentTypeFilter(mediaType) {
		return ""
	}
	return mediaType
}

func capturedHeader(headers map[string]string, wanted string) string {
	for name, value := range headers {
		if strings.EqualFold(name, wanted) {
			return value
		}
	}
	return ""
}

func valueRangeMatches(value uint64, minimum, maximum *uint64) bool {
	return (minimum == nil || value >= *minimum) && (maximum == nil || value <= *maximum)
}

func blockEventRowMatches(row blockEventRow, clientIP netip.Addr, filter Filter) bool {
	return (filter.SiteID == "" || row.SiteID == filter.SiteID) &&
		hostFilterMatches(row.Host, filter.Host) &&
		(filter.NodeID == "" || row.NodeID == filter.NodeID) && matchesIP(clientIP, filter.ClientIP) &&
		uriPathMatches(row.URIPath, filter) &&
		(!filter.HasStatus || row.StatusCode == filter.StatusCode) &&
		(filter.CountryCode == "" || row.CountryCode == filter.CountryCode) &&
		(filter.Carrier == "" || row.Carrier == filter.Carrier) &&
		slices.Contains(SecurityLogActions, row.Action) && (filter.Action == "" || row.Action == filter.Action) &&
		(filter.EventType == "" || row.EventType == filter.EventType) &&
		captureFilterMatches(row.JA4, row.OriginConnectUS, row.OriginFirstByteUS, row.OriginTotalUS, filter)
}

func captureFilterMatches(ja4 *string, connect, firstByte, total *uint64, filter Filter) bool {
	return (filter.JA4 == "" || ja4 != nil && *ja4 == filter.JA4) &&
		uint64FilterMatches(connect, filter.OriginConnectUSMin, filter.OriginConnectUSMax) &&
		uint64FilterMatches(firstByte, filter.OriginFirstByteUSMin, filter.OriginFirstByteUSMax) &&
		uint64FilterMatches(total, filter.OriginTotalUSMin, filter.OriginTotalUSMax)
}

func uint64FilterMatches(value, minimum, maximum *uint64) bool {
	if minimum == nil && maximum == nil {
		return true
	}
	return value != nil && (minimum == nil || *value >= *minimum) && (maximum == nil || *value <= *maximum)
}

func matchesIP(actual netip.Addr, expected string) bool {
	if expected == "" {
		return true
	}
	parsed, err := netip.ParseAddr(expected)
	return err == nil && actual.Unmap() == parsed.Unmap()
}

func validStoredCapture(
	taskID *string,
	installationID string,
	requestHeaders, responseHeaders map[string]string,
	requestBody, responseBody *string,
	ja4 *string,
	connect, firstByte, total *uint64,
) bool {
	if taskID != nil && !validOutputText(*taskID, 128, true) ||
		installationID != "" && !validOutputIdentifier(installationID, 128) ||
		ja4 != nil && !validOutputText(*ja4, 128, true) ||
		!validCapturedHeaders(requestHeaders) || !validCapturedHeaders(responseHeaders) ||
		(connect != nil && firstByte != nil && *connect > *firstByte) ||
		(firstByte != nil && total != nil && *firstByte > *total) ||
		(connect != nil && total != nil && *connect > *total) {
		return false
	}
	_, requestErr := decodeCapturedBody(requestBody)
	_, responseErr := decodeCapturedBody(responseBody)
	return requestErr == nil && responseErr == nil
}

func validOutputIdentifier(value string, limit int) bool {
	if !validOutputText(value, limit, true) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validCapturedHeaders(headers map[string]string) bool {
	if len(headers) > maxCapturedMapKeys {
		return false
	}
	for name, value := range headers {
		if http.CanonicalHeaderKey(name) != name || !validHeaderName(name) || !utf8.ValidString(value) ||
			len(value) > maxCapturedHeaderValue || captureSensitiveName(name) && value != redactedCaptureValue {
			return false
		}
	}
	return true
}

func nonnilCapturedHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return map[string]string{}
	}
	return headers
}

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func decodeCapturedBody(encoded *string) (map[string]any, error) {
	if encoded == nil {
		return nil, nil
	}
	data := []byte(*encoded)
	if len(data) == 0 || len(data) > maxCapturedBodyBytes || validateUniqueCapturedJSON(data) != nil {
		return nil, ErrInvalidResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var body map[string]any
	if decoder.Decode(&body) != nil || body == nil || decoder.Decode(&struct{}{}) != io.EOF || !validCapturedBody(body) {
		return nil, ErrInvalidResponse
	}
	canonical, err := json.Marshal(body)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, ErrInvalidResponse
	}
	return body, nil
}

func validCapturedBody(body map[string]any) bool {
	remaining := maxCapturedMapKeys
	if len(body) > remaining {
		return false
	}
	remaining -= len(body)
	for name, value := range body {
		if !validCapturedBodyKey(name) || captureSensitiveName(name) && value != redactedCaptureValue ||
			!validCapturedValue(value, 0, &remaining) {
			return false
		}
	}
	return true
}

func validCapturedValue(value any, depth int, remaining *int) bool {
	if depth > maxCapturedBodyDepth {
		return false
	}
	switch typed := value.(type) {
	case nil, bool, json.Number:
		return true
	case string:
		return utf8.ValidString(typed)
	case []any:
		for _, item := range typed {
			if !validCapturedValue(item, depth+1, remaining) {
				return false
			}
		}
		return true
	case map[string]any:
		if len(typed) > *remaining {
			return false
		}
		*remaining -= len(typed)
		for name, item := range typed {
			if !validCapturedBodyKey(name) || captureSensitiveName(name) && item != redactedCaptureValue ||
				!validCapturedValue(item, depth+1, remaining) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validCapturedBodyKey(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func captureSensitiveName(value string) bool {
	runes := []rune(value)
	var tokenized strings.Builder
	tokenized.Grow(len(value))
	for index, character := range runes {
		if index > 0 && unicode.IsUpper(character) &&
			(unicode.IsLower(runes[index-1]) || unicode.IsDigit(runes[index-1]) ||
				unicode.IsUpper(runes[index-1]) && index+1 < len(runes) && unicode.IsLower(runes[index+1])) {
			tokenized.WriteByte(' ')
		}
		tokenized.WriteRune(unicode.ToLower(character))
	}
	lower := tokenized.String()
	replacer := strings.NewReplacer("-", " ", "_", " ", ".", " ", "[", " ", "]", " ")
	for _, part := range strings.Fields(replacer.Replace(lower)) {
		switch part {
		case "authorization", "cookie", "password", "passwd", "token", "key", "apikey", "secret", "certificate", "cert", "privatekey", "setcookie":
			return true
		}
	}
	return lower == "set-cookie" || strings.Contains(lower, "authorization")
}

func validateUniqueCapturedJSON(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeCapturedJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalidResponse
	}
	return nil
}

func consumeCapturedJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return ErrInvalidResponse
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidResponse
			}
			seen[key] = struct{}{}
			if err := consumeCapturedJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidResponse
		}
	case '[':
		for decoder.More() {
			if err := consumeCapturedJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidResponse
		}
	default:
		return ErrInvalidResponse
	}
	return nil
}

func rowsOrdered(previousMS int64, previousID string, currentMS int64, currentID string) bool {
	return previousMS > currentMS || (previousMS == currentMS && previousID > currentID)
}

func validEventID(value string) bool {
	if !validOutputText(value, 128, true) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validCanonicalUUID(value string) bool {
	return value == strings.ToLower(value) && validUUID(value)
}

func validOutputPath(value string) bool {
	return value == "" || (len(value) <= 4096 && safeURIPath(value) == value && validOutputText(value, 4096, true))
}

// validOutputQuery: a security event's query as the node logs it (P14,
// cdnca_telemetry.security_path: sensitive values masked, at most 512
// printable ASCII bytes; older rows have none).
func validOutputQuery(value string) bool {
	if len(value) > maxSecurityQueryBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == '#' {
			return false
		}
	}
	return true
}

func validOutputText(value string, limit int, required bool) bool {
	if len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value || (required && value == "") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validDatabase(value string) bool {
	if value == "" || len(value) > maxDatabaseBytes || !identifierStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !identifierPart(value[index]) {
			return false
		}
	}
	return true
}

func identifierStart(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || value == '_'
}

func identifierPart(value byte) bool {
	return identifierStart(value) || (value >= '0' && value <= '9')
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
