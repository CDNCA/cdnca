package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxRankLimit = uint16(100)
	// A URL key is host:port/path: host (253) + ":65535" + path (4096).
	maxRankKeyBytes = 253 + 6 + 4096
	maxCursorSize   = 8192
)

var ErrDimensionUnsupported = errors.New("analytics dimension unsupported")

type RankDimension string

const (
	RankByURL      RankDimension = "url"
	RankByIP       RankDimension = "ip"
	RankByDomain   RankDimension = "domain"
	RankByRegion   RankDimension = "region"
	RankByCarrier  RankDimension = "carrier"
	RankByJA4      RankDimension = "ja4"
	RankByReferer  RankDimension = "referer"
	RankByProvince RankDimension = "province"
	RankByBrowser  RankDimension = "browser"
	RankByOS       RankDimension = "os"
)

// historyRankDimensions read access_hourly_facts_v1 (one row per request,
// TTL bandwidth_history_days) instead of raw access_events (TTL
// access_logs_days, default 7 days), so their range is the whole history the
// summary and trend show. URL, JA4 and Referer stay on the access log: they
// are high cardinality and only kept as long as the logs (HistoryRankable).
var historyRankDimensions = map[RankDimension]string{
	RankByIP:       clientIPTextSQL("tupleElement(latest, 5)"),
	RankByDomain:   rankHostPortSQL("tupleElement(latest, 6)", "tupleElement(latest, 10)"),
	RankByRegion:   "if(empty(tupleElement(latest, 7)), '__unknown__', tupleElement(latest, 7))",
	RankByCarrier:  "if(empty(tupleElement(latest, 8)), '__unknown__', tupleElement(latest, 8))",
	RankByProvince: "if(empty(tupleElement(latest, 11)), '__unknown__', tupleElement(latest, 11))",
	RankByBrowser:  "if(empty(tupleElement(latest, 12)), '__unknown__', tupleElement(latest, 12))",
	RankByOS:       "if(empty(tupleElement(latest, 13)), '__unknown__', tupleElement(latest, 13))",
}

// HistoryRankable: the dimension's range follows the history retention, not
// the access log retention.
func HistoryRankable(dimension RankDimension) bool {
	_, ok := historyRankDimensions[dimension]
	return ok
}

// clientIPTextSQL renders an IPv6 client_ip column as text: an IPv4 client
// (stored as ::ffff:a.b.c.d) as dotted IPv4, a real IPv6 address as is.
func clientIPTextSQL(column string) string {
	return `replaceRegexpOne(toString(` + column + `), '^::ffff:([0-9.]+)$', '\\1')`
}

// rankHostPortSQL is a ranking key host:port (host alone when the listen
// port is unknown, 0 on events from before it was recorded).
func rankHostPortSQL(host, port string) string {
	return `if(` + port + ` = 0, ` + host + `, concat(` + host + `, ':', toString(` + port + `)))`
}

// rankHostPortColumns: the host and port of a host:port key, so the page
// shows and filters by them instead of parsing the key.
const rankHostPortColumns = `,
        any(tupleElement(latest, 6)) AS host, any(tupleElement(latest, 10)) AS port`

func historyRankSQL(key string) string {
	extra := ""
	if key == historyRankDimensions[RankByDomain] {
		extra = rankHostPortColumns
	}
	return `SELECT *
FROM
(
    SELECT ` + key + ` AS key, count() AS request_count,
        toUInt64(sum(tupleElement(latest, 9))) AS response_bytes` + extra + `
    FROM
    (
        SELECT
            argMax(
                tuple(occurred_at, site_id, node_id, '', client_ip, host, country_code, carrier, response_bytes, listen_port,
                      province, client_browser, client_os),
                tuple(ingested_at, occurred_at, site_id, node_id, '', client_ip, host, country_code, carrier, response_bytes, listen_port,
                      province, client_browser, client_os)
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
        AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(tupleElement(latest, 6))))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
        AND ({has_listen_port:UInt8} = 0 OR tupleElement(latest, 10) = {listen_port:UInt16})
    GROUP BY key
)
WHERE {has_cursor:UInt8} = 0
    OR response_bytes < {cursor_response_bytes:UInt64}
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count < {cursor_request_count:UInt64})
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count = {cursor_request_count:UInt64} AND key > {cursor_key:String})
ORDER BY response_bytes DESC, request_count DESC, key ASC
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`
}

type RankPage struct {
	Items      []RankItem
	NextCursor string
	SnapshotAt time.Time
	// RetainedFrom is set when the requested range starts before the oldest
	// data the dimension's source keeps (access log or history retention):
	// the ranking covers [RetainedFrom, to) only.
	RetainedFrom time.Time
}

type RankItem struct {
	Key           string `json:"key"`
	RequestCount  uint64 `json:"request_count"`
	ResponseBytes uint64 `json:"response_bytes"`
	// Domain and URL rankings: the address parts of the key (host:port,
	// host:port/path). Port 0 is unknown (events from before listen_port).
	Host string `json:"host,omitempty"`
	Port uint16 `json:"port,omitempty"`
	Path string `json:"path,omitempty"`
	// Scheme (URL ranking): https when the site serves HTTPS on Port, http
	// otherwise; empty when unknown. Derived by Service from SiteID.
	Scheme string `json:"scheme,omitempty"`
	SiteID string `json:"-"`
}

// rankRow is a ClickHouse ranking row (site_id is internal to the service).
type rankRow struct {
	Key           string `json:"key"`
	RequestCount  uint64 `json:"request_count"`
	ResponseBytes uint64 `json:"response_bytes"`
	Host          string `json:"host"`
	Port          uint16 `json:"port"`
	Path          string `json:"path"`
	SiteID        string `json:"site_id"`
}

type rankCursor struct {
	Version       uint8  `json:"v"`
	Query         string `json:"q"`
	SnapshotMilli int64  `json:"s"`
	ResponseBytes uint64 `json:"b"`
	RequestCount  uint64 `json:"r"`
	Key           string `json:"k"`
}

// rankByURLSQL groups by host, port and path (the same path on two domains
// or ports is two rows), the full address the page shows.
var rankByURLSQL = `SELECT *
FROM
(
    SELECT concat(` + rankHostPortSQL("tupleElement(latest, 6)", "tupleElement(latest, 10)") + `, tupleElement(latest, 4)) AS key,
        count() AS request_count, toUInt64(sum(tupleElement(latest, 9))) AS response_bytes` + rankHostPortColumns + `,
        any(tupleElement(latest, 4)) AS path, toString(any(tupleElement(latest, 2))) AS site_id
    FROM
    (
        SELECT
            argMax(
                tuple(occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, response_bytes, listen_port),
                tuple(ingested_at, occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, response_bytes, listen_port)
            ) AS latest
        FROM access_events
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(tupleElement(latest, 6))))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
        AND ({has_listen_port:UInt8} = 0 OR tupleElement(latest, 10) = {listen_port:UInt16})
    GROUP BY key
)
WHERE {has_cursor:UInt8} = 0
    OR response_bytes < {cursor_response_bytes:UInt64}
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count < {cursor_request_count:UInt64})
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count = {cursor_request_count:UInt64} AND key > {cursor_key:String})
ORDER BY response_bytes DESC, request_count DESC, key ASC
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

const rankByJA4SQL = `SELECT key, request_count, response_bytes
FROM
(
    SELECT ifNull(nullIf(tupleElement(latest, 9), ''), '__unknown__') AS key,
        count() AS request_count, toUInt64(sum(tupleElement(latest, 10))) AS response_bytes
    FROM
    (
        SELECT
            argMax(
                tuple(occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, ja4, response_bytes, listen_port),
                tuple(ingested_at, occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, ifNull(ja4, ''), response_bytes, listen_port)
            ) AS latest
        FROM access_events
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(tupleElement(latest, 6))))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
        AND ({has_listen_port:UInt8} = 0 OR tupleElement(latest, 11) = {listen_port:UInt16})
    GROUP BY key
)
WHERE {has_cursor:UInt8} = 0
    OR response_bytes < {cursor_response_bytes:UInt64}
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count < {cursor_request_count:UInt64})
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count = {cursor_request_count:UInt64} AND key > {cursor_key:String})
ORDER BY response_bytes DESC, request_count DESC, key ASC
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

const rankByRefererSQL = `SELECT key, request_count, response_bytes
FROM
(
    SELECT if(
            empty(arrayFirst(
                (header_value, header_name) -> lower(header_name) = 'referer',
                mapValues(tupleElement(latest, 11)), mapKeys(tupleElement(latest, 11))
            )),
            '__unknown__',
            if(
                length(arrayFirst(
                    (header_value, header_name) -> lower(header_name) = 'referer',
                    mapValues(tupleElement(latest, 11)), mapKeys(tupleElement(latest, 11))
                )) > 4096,
                '__unknown__',
                arrayFirst(
                    (header_value, header_name) -> lower(header_name) = 'referer',
                    mapValues(tupleElement(latest, 11)), mapKeys(tupleElement(latest, 11))
                )
            )
        ) AS key,
        count() AS request_count, toUInt64(sum(tupleElement(latest, 9))) AS response_bytes
    FROM
    (
        SELECT
            argMax(
                tuple(occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, response_bytes, listen_port, request_headers),
                tuple(ingested_at, occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, response_bytes, listen_port, toJSONString(request_headers))
            ) AS latest
        FROM access_events
        WHERE metric_version = 1
            AND ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')
            AND ({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))
        GROUP BY tenant_id, event_id
    )
    WHERE tupleElement(latest, 1) >= fromUnixTimestamp64Milli({from_ms:UInt64}, 'UTC')
        AND tupleElement(latest, 1) < fromUnixTimestamp64Milli({to_ms:UInt64}, 'UTC')
        AND ({has_site:UInt8} = 0 OR tupleElement(latest, 2) = toUUID({site_id:String}))
        AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(tupleElement(latest, 6))))
        AND ({has_node:UInt8} = 0 OR tupleElement(latest, 3) = toUUID({node_id:String}))
        AND ({has_listen_port:UInt8} = 0 OR tupleElement(latest, 10) = {listen_port:UInt16})
    GROUP BY key
)
WHERE {has_cursor:UInt8} = 0
    OR response_bytes < {cursor_response_bytes:UInt64}
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count < {cursor_request_count:UInt64})
    OR (response_bytes = {cursor_response_bytes:UInt64} AND request_count = {cursor_request_count:UInt64} AND key > {cursor_key:String})
ORDER BY response_bytes DESC, request_count DESC, key ASC
LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

func (client *Client) Rank(
	ctx context.Context,
	scope Scope,
	filter Filter,
	dimension RankDimension,
	limit uint16,
	cursor string,
) (RankPage, error) {
	if limit == 0 || limit > maxRankLimit {
		return RankPage{}, ErrInvalidInput
	}
	query, ok := rankQuery(dimension)
	if !ok {
		return RankPage{}, ErrDimensionUnsupported
	}
	parameters, err := rankQueryParameters(scope, filter)
	if err != nil {
		return RankPage{}, err
	}

	fingerprint := rankFingerprint(scope, filter, dimension)
	now := time.Now().UTC()
	snapshot := filter.SnapshotAt
	if snapshot.IsZero() {
		snapshot = now.Truncate(time.Millisecond)
	}
	state := rankCursor{Version: 1, Query: fingerprint, SnapshotMilli: snapshot.UnixMilli()}
	if cursor != "" {
		state, err = decodeRankCursor(cursor, fingerprint)
		if err != nil {
			return RankPage{}, err
		}
		if state.SnapshotMilli > now.Add(time.Minute).UnixMilli() ||
			!filter.SnapshotAt.IsZero() && state.SnapshotMilli != filter.SnapshotAt.UnixMilli() {
			return RankPage{}, ErrInvalidInput
		}
	}
	parameters.Set("param_snapshot_ms", strconv.FormatInt(state.SnapshotMilli, 10))
	parameters.Set("param_row_limit", strconv.FormatUint(uint64(limit+1), 10))
	parameters.Set("param_has_cursor", "0")
	parameters.Set("param_cursor_response_bytes", "0")
	parameters.Set("param_cursor_request_count", "0")
	parameters.Set("param_cursor_key", "")
	if cursor != "" {
		parameters.Set("param_has_cursor", "1")
		parameters.Set("param_cursor_response_bytes", strconv.FormatUint(state.ResponseBytes, 10))
		parameters.Set("param_cursor_request_count", strconv.FormatUint(state.RequestCount, 10))
		parameters.Set("param_cursor_key", state.Key)
	}

	rows, err := queryRankRows(client, ctx, query, parameters, int(limit)+1)
	if err != nil {
		return RankPage{}, err
	}
	if len(rows) > int(limit)+1 {
		return RankPage{}, ErrInvalidResponse
	}
	if !validRankRows(rows, state, cursor != "") {
		return RankPage{}, ErrInvalidResponse
	}
	page := RankPage{Items: rows, SnapshotAt: time.UnixMilli(state.SnapshotMilli).UTC()}
	if len(rows) > int(limit) {
		page.Items = rows[:limit]
		last := page.Items[len(page.Items)-1]
		state.ResponseBytes = last.ResponseBytes
		state.RequestCount = last.RequestCount
		state.Key = last.Key
		page.NextCursor, err = encodeRankCursor(state)
		if err != nil {
			return RankPage{}, err
		}
	}
	return page, nil
}

func queryRankRows(
	client *Client,
	ctx context.Context,
	query string,
	parameters url.Values,
	maximumRows int,
) ([]RankItem, error) {
	if maximumRows <= 0 {
		return nil, ErrInvalidResponse
	}
	var rows []RankItem
	err := client.execute(ctx, client.queryTimeout, []byte(query), parameters, true, func(encoded []byte) error {
		if !utf8.Valid(encoded) {
			return ErrInvalidResponse
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		for {
			var row rankRow
			if err := decoder.Decode(&row); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			if len(rows) >= maximumRows {
				return ErrInvalidResponse
			}
			rows = append(rows, RankItem{
				Key: row.Key, RequestCount: row.RequestCount, ResponseBytes: row.ResponseBytes,
				Host: row.Host, Port: row.Port, Path: row.Path, SiteID: row.SiteID,
			})
		}
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func validRankRows(rows []RankItem, cursor rankCursor, hasCursor bool) bool {
	seen := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		if !validRankKey(row.Key) || row.RequestCount == 0 {
			return false
		}
		if _, exists := seen[row.Key]; exists {
			return false
		}
		seen[row.Key] = struct{}{}
		if index > 0 && !rankItemBefore(rows[index-1], row) {
			return false
		}
		if hasCursor && !rankItemAfterCursor(row, cursor) {
			return false
		}
	}
	return true
}

func validRankKey(key string) bool {
	if len(key) == 0 || len(key) > maxRankKeyBytes || !utf8.ValidString(key) {
		return false
	}
	for _, character := range key {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func rankItemBefore(previous, current RankItem) bool {
	if previous.ResponseBytes != current.ResponseBytes {
		return previous.ResponseBytes > current.ResponseBytes
	}
	if previous.RequestCount != current.RequestCount {
		return previous.RequestCount > current.RequestCount
	}
	return previous.Key < current.Key
}

func rankItemAfterCursor(item RankItem, cursor rankCursor) bool {
	if item.ResponseBytes != cursor.ResponseBytes {
		return item.ResponseBytes < cursor.ResponseBytes
	}
	if item.RequestCount != cursor.RequestCount {
		return item.RequestCount < cursor.RequestCount
	}
	return item.Key > cursor.Key
}

func rankQuery(dimension RankDimension) (string, bool) {
	if key, ok := historyRankDimensions[dimension]; ok {
		return historyRankSQL(key), true
	}
	switch dimension {
	case RankByURL:
		return rankByURLSQL, true
	case RankByJA4:
		return rankByJA4SQL, true
	case RankByReferer:
		return rankByRefererSQL, true
	default:
		return "", false
	}
}

func rankFingerprint(scope Scope, filter Filter, dimension RankDimension) string {
	tenant := "platform"
	if scope.kind == scopeTenant {
		tenant = scope.tenantID
	}
	parts := []string{
		"v1", tenant, filter.From.UTC().Format(time.RFC3339Nano), filter.To.UTC().Format(time.RFC3339Nano),
		strings.ToLower(filter.SiteID), normalizedRankDomains(filter.Domain), strings.ToLower(filter.NodeID),
		strconv.FormatUint(uint64(filter.ListenPort), 10), string(dimension),
	}
	if !filter.SnapshotAt.IsZero() {
		parts[0] = "v2"
		parts = append(parts, filter.Timezone, strconv.FormatInt(filter.SnapshotAt.UnixMilli(), 10))
	}
	canonical := strings.Join(parts, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func normalizedRankDomains(value string) string {
	domains, _ := normalizeRankDomainFilter(value)
	return domains
}

func encodeRankCursor(cursor rankCursor) (string, error) {
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", ErrInvalidResponse
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeRankCursor(encoded, fingerprint string) (rankCursor, error) {
	if len(encoded) > maxCursorSize {
		return rankCursor{}, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxCursorSize {
		return rankCursor{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor rankCursor
	if err := decoder.Decode(&cursor); err != nil {
		return rankCursor{}, ErrInvalidInput
	}
	canonical, canonicalErr := encodeRankCursor(cursor)
	if err := ensureCursorEOF(decoder); err != nil || cursor.Version != 1 || cursor.Query != fingerprint ||
		cursor.SnapshotMilli <= 0 || cursor.RequestCount == 0 || !validRankKey(cursor.Key) ||
		canonicalErr != nil || canonical != encoded {
		return rankCursor{}, ErrInvalidInput
	}
	return cursor, nil
}

func ensureCursorEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidInput
	}
	return nil
}
