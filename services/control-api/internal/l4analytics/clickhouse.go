package l4analytics

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type ClickHouseConfig struct {
	Endpoint         string
	Database         string
	Username         string
	Password         string
	QueryTimeout     time.Duration
	MaxResponseBytes int64
	HTTPClient       HTTPDoer
}

type ClickHouseSource struct {
	endpoint    *url.URL
	database    string
	username    string
	password    string
	timeout     time.Duration
	maxResponse int64
	httpClient  HTTPDoer
}

type snapshotRow struct {
	AtMilliseconds               int64  `json:"at_ms"`
	SourceWatermark              uint64 `json:"source_watermark"`
	FinalizedThroughMilliseconds int64  `json:"finalized_through_ms"`
}

type aggregateRow struct {
	BucketMS   int64  `json:"bucket_ms"`
	NodeID     string `json:"node_id"`
	SiteID     string `json:"site_id"`
	StreamID   string `json:"stream_id"`
	ListenerID string `json:"listener_id"`
	Protocol   string `json:"protocol"`
	ListenPort uint16 `json:"listen_port"`
	Sessions   uint64 `json:"sessions"`
	BytesUp    uint64 `json:"bytes_up"`
	BytesDown  uint64 `json:"bytes_down"`
	Errors     uint64 `json:"errors"`
}

func NewClickHouseSource(config ClickHouseConfig) (*ClickHouseSource, error) {
	if config.Endpoint == "" || config.Database == "" {
		return nil, ErrInvalidConfig
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, ErrInvalidConfig
	}
	if config.QueryTimeout <= 0 {
		config.QueryTimeout = 5 * time.Second
	}
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = 4 << 20
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: config.QueryTimeout}
	}
	return &ClickHouseSource{endpoint: parsed, database: config.Database, username: config.Username, password: config.Password,
		timeout: config.QueryTimeout, maxResponse: config.MaxResponseBytes, httpClient: config.HTTPClient}, nil
}

func (source *ClickHouseSource) Read(ctx context.Context, scope Scope, filter Filter) (Page, error) {
	if source == nil || ctx == nil {
		return Page{}, ErrInvalidConfig
	}
	if filter.Snapshot.SourceWatermark == 0 {
		snapshot, err := source.readSnapshot(ctx, scope, filter)
		if err != nil {
			return Page{}, err
		}
		filter.Snapshot = snapshot
	}
	rows, err := source.readAggregates(ctx, scope, filter)
	if err != nil {
		return Page{}, err
	}
	return Page{Snapshot: filter.Snapshot, Rows: rows, HasMore: len(rows) >= int(filter.Limit)}, nil
}

func (source *ClickHouseSource) readSnapshot(ctx context.Context, scope Scope, filter Filter) (Snapshot, error) {
	conditions := []string{"finalized_at >= {from:DateTime64(3)}", "finalized_at < {to:DateTime64(3)}"}
	params := url.Values{"from": {filter.From.UTC().Format("2006-01-02 15:04:05.000")}, "to": {filter.To.UTC().Format("2006-01-02 15:04:05.000")}}
	if scope.TenantID != "" {
		conditions = append([]string{"tenant_id = {tenant_id:UUID}"}, conditions...)
		params.Set("tenant_id", scope.TenantID)
	}
	query := `SELECT toInt64(toUnixTimestamp64Milli(now64(3))) AS at_ms, max(source_watermark) AS source_watermark,
toInt64(toUnixTimestamp64Milli(max(finalized_at))) AS finalized_through_ms
FROM l4_session_facts_v1
WHERE ` + strings.Join(conditions, " AND ") + `
FORMAT JSONEachRow`
	var row snapshotRow
	if err := source.doJSON(ctx, query, params, &row); err != nil {
		return Snapshot{}, err
	}
	if row.AtMilliseconds <= 0 {
		return Snapshot{}, ErrInvalidResponse
	}
	if row.SourceWatermark == 0 {
		return Snapshot{At: time.UnixMilli(row.AtMilliseconds).UTC(), FinalizedThrough: filter.To.UTC()}, nil
	}
	if row.FinalizedThroughMilliseconds <= 0 {
		return Snapshot{}, ErrInvalidResponse
	}
	return Snapshot{At: time.UnixMilli(row.AtMilliseconds).UTC(), SourceWatermark: row.SourceWatermark, FinalizedThrough: time.UnixMilli(row.FinalizedThroughMilliseconds).UTC()}, nil
}

func (source *ClickHouseSource) readAggregates(ctx context.Context, scope Scope, filter Filter) ([]Row, error) {
	conditions := []string{"finalized_at >= {from:DateTime64(3)}", "finalized_at < {to:DateTime64(3)}", "source_watermark <= {watermark:UInt64}"}
	params := url.Values{"from": {filter.From.UTC().Format("2006-01-02 15:04:05.000")}, "to": {filter.To.UTC().Format("2006-01-02 15:04:05.000")}, "watermark": {strconv.FormatUint(filter.Snapshot.SourceWatermark, 10)}}
	if scope.TenantID != "" {
		conditions = append([]string{"tenant_id = {tenant_id:UUID}"}, conditions...)
		params.Set("tenant_id", scope.TenantID)
	}
	if filter.SiteID != "" {
		conditions = append(conditions, "site_id = {site_id:UUID}")
		params.Set("site_id", filter.SiteID)
	}
	if filter.StreamID != "" {
		conditions = append(conditions, "stream_id = {stream_id:UUID}")
		params.Set("stream_id", filter.StreamID)
	}
	if filter.NodeID != "" {
		conditions = append(conditions, "node_id = {node_id:UUID}")
		params.Set("node_id", filter.NodeID)
	}
	if filter.Protocol != "" {
		conditions = append(conditions, "protocol = {protocol:String}")
		params.Set("protocol", filter.Protocol)
	}
	if filter.ListenPort != 0 {
		conditions = append(conditions, "listen_port = {listen_port:UInt16}")
		params.Set("listen_port", strconv.Itoa(int(filter.ListenPort)))
	}
	if filter.After != nil {
		conditions = append(conditions, `(toStartOfMinute(finalized_at), node_id, site_id, stream_id, listener_id) > ({after_bucket:DateTime64(3)}, {after_node:UUID}, {after_site:UUID}, {after_stream:UUID}, {after_listener:UUID})`)
		params.Set("after_bucket", filter.After.Bucket.UTC().Format("2006-01-02 15:04:05.000"))
		params.Set("after_node", filter.After.NodeID)
		params.Set("after_site", filter.After.SiteID)
		params.Set("after_stream", filter.After.StreamID)
		params.Set("after_listener", filter.After.ListenerID)
	}
	query := `SELECT toInt64(toUnixTimestamp(toStartOfMinute(finalized_at))) * 1000 AS bucket_ms, node_id, site_id, stream_id, listener_id, any(protocol) AS protocol,
any(listen_port) AS listen_port, count() AS sessions, sum(bytes_up) AS bytes_up, sum(bytes_down) AS bytes_down,
countIf(status_code >= 500 OR error_code != '') AS errors FROM l4_session_facts_v1 FINAL WHERE ` + strings.Join(conditions, " AND ") +
		` GROUP BY bucket_ms, node_id, site_id, stream_id, listener_id ORDER BY bucket_ms, node_id, site_id, stream_id, listener_id LIMIT {limit:UInt16} FORMAT JSONEachRow`
	params.Set("limit", strconv.Itoa(int(filter.Limit)))
	var rows []aggregateRow
	if err := source.doJSONLines(ctx, query, params, &rows); err != nil {
		return nil, err
	}
	result := make([]Row, 0, len(rows))
	for _, row := range rows {
		if row.BucketMS <= 0 {
			return nil, ErrInvalidResponse
		}
		result = append(result, Row{Bucket: time.UnixMilli(row.BucketMS).UTC(), NodeID: row.NodeID, SiteID: row.SiteID, StreamID: row.StreamID, ListenerID: row.ListenerID, Protocol: row.Protocol, ListenPort: row.ListenPort, Sessions: row.Sessions, BytesUp: row.BytesUp, BytesDown: row.BytesDown, Errors: row.Errors})
	}
	return result, nil
}

func (source *ClickHouseSource) doJSON(ctx context.Context, query string, params url.Values, target any) error {
	var rows []json.RawMessage
	if err := source.doJSONLines(ctx, query, params, &rows); err != nil {
		return err
	}
	if len(rows) != 1 {
		return ErrInvalidResponse
	}
	return json.Unmarshal(rows[0], target)
}

func (source *ClickHouseSource) doJSONLines(ctx context.Context, query string, params url.Values, target any) error {
	operationCtx, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	endpoint := *source.endpoint
	values := endpoint.Query()
	values.Set("database", source.database)
	values.Set("output_format_json_quote_64bit_integers", "0")
	for key, list := range params {
		if len(list) == 1 {
			values.Set("param_"+key, list[0])
		}
	}
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(operationCtx, http.MethodPost, endpoint.String(), bytes.NewReader([]byte(query)))
	if err != nil {
		return ErrDependencyUnavailable
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if source.username != "" {
		request.SetBasicAuth(source.username, source.password)
	}
	response, err := source.httpClient.Do(request)
	if err != nil {
		return ErrDependencyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ErrDependencyUnavailable
	}
	reader := bufio.NewReader(io.LimitReader(response.Body, source.maxResponse+1))
	var raw []json.RawMessage
	for {
		line, readErr := reader.ReadBytes('\n')
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			if int64(len(line)) > source.maxResponse {
				return ErrInvalidResponse
			}
			raw = append(raw, append([]byte(nil), line...))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return ErrDependencyUnavailable
		}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return ErrInvalidResponse
	}
	return json.Unmarshal(encoded, target)
}

var _ Source = (*ClickHouseSource)(nil)
