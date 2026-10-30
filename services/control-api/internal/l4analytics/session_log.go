package l4analytics

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Session logs (session_log, tcp/udp v7): one row per L4 session of a
// logging stream, with the client and upstream addresses the session facts
// never hold (infra/clickhouse/migrations/018_l4_session_logs.up.sql).

const SessionLogVersion = "l4-session-logs/v1"

// ErrSessionLogUnavailable: the l4_session_logs_v1 table is not installed.
var ErrSessionLogUnavailable = errors.New("L4 session log table unavailable")

var sessionEndReasons = map[string]bool{"closed": true, "killed": true, "geo_blocked": true, "rate_limited": true,
	"banned": true, "conn_limited": true, "bad_request": true, "forbidden": true, "upstream_failed": true,
	"internal_error": true, "config_error": true, "guard_blocked": true}

type SessionLogQuery struct {
	Query
	// ClientIP is an address or CIDR.
	ClientIP  string
	EndReason string
}

type SessionLogRow struct {
	EventID           string    `json:"event_id"`
	StartedAt         time.Time `json:"started_at"`
	FinalizedAt       time.Time `json:"finalized_at"`
	NodeID            string    `json:"node_id"`
	SiteID            string    `json:"site_id"`
	StreamID          string    `json:"stream_id"`
	ListenerID        string    `json:"listener_id"`
	Protocol          string    `json:"protocol"`
	ListenPort        uint16    `json:"listen_port"`
	ClientIP          string    `json:"client_ip"`
	ClientPort        uint16    `json:"client_port"`
	PeerIP            string    `json:"peer_ip,omitempty"`
	UpstreamAddr      string    `json:"upstream_addr,omitempty"`
	UpstreamConnectMS *uint32   `json:"upstream_connect_ms,omitempty"`
	BytesUp           uint64    `json:"bytes_up"`
	BytesDown         uint64    `json:"bytes_down"`
	StatusCode        uint16    `json:"status_code"`
	EndReason         string    `json:"end_reason"`
}

type SessionLogResponse struct {
	Version    string          `json:"version"`
	From       time.Time       `json:"from"`
	To         time.Time       `json:"to"`
	Rows       []SessionLogRow `json:"rows"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type SessionLogReader interface {
	ReadSessionLogs(context.Context, Actor, SessionLogQuery) (SessionLogResponse, error)
}

type sessionLogFilter struct {
	Filter
	ClientCIDR string `json:"client_cidr"`
	EndReason  string `json:"end_reason"`
}

type sessionLogAfter struct {
	FinalizedAt time.Time `json:"finalized_at"`
	EventID     string    `json:"event_id"`
}

type sessionLogCursor struct {
	Version  uint8           `json:"version"`
	TenantID string          `json:"tenant_id"`
	Filter   [32]byte        `json:"filter"`
	From     time.Time       `json:"from"`
	To       time.Time       `json:"to"`
	After    sessionLogAfter `json:"after"`
}

type sessionLogSource interface {
	readSessionLogs(context.Context, Scope, sessionLogFilter, *sessionLogAfter) ([]SessionLogRow, error)
}

func (service *Service) ReadSessionLogs(ctx context.Context, actor Actor, query SessionLogQuery) (SessionLogResponse, error) {
	if service == nil || service.source == nil || ctx == nil {
		return SessionLogResponse{}, ErrInvalidConfig
	}
	source, ok := service.source.(sessionLogSource)
	if !ok {
		return SessionLogResponse{}, ErrSessionLogUnavailable
	}
	scope, base, err := normalize(actor, query.Query, service.now().UTC())
	if err != nil {
		return SessionLogResponse{}, err
	}
	filter := sessionLogFilter{Filter: base}
	if query.ClientIP != "" {
		prefix, err := netip.ParsePrefix(query.ClientIP)
		if err != nil {
			address, addressErr := netip.ParseAddr(query.ClientIP)
			if addressErr != nil || address.Zone() != "" {
				return SessionLogResponse{}, ErrInvalidRequest
			}
			prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
		}
		filter.ClientCIDR = prefix.Masked().String()
	}
	if query.EndReason != "" && !sessionEndReasons[query.EndReason] {
		return SessionLogResponse{}, ErrInvalidRequest
	}
	filter.EndReason = query.EndReason
	var after *sessionLogAfter
	if query.Cursor != "" {
		cursor, err := service.decodeSessionLogCursor(query.Cursor, scope, filter)
		if err != nil {
			return SessionLogResponse{}, err
		}
		filter.From, filter.To, after = cursor.From, cursor.To, &cursor.After
	}
	rows, err := source.readSessionLogs(ctx, scope, filter, after)
	if err != nil {
		if errors.Is(err, ErrSessionLogUnavailable) {
			return SessionLogResponse{}, err
		}
		if ctx.Err() != nil {
			return SessionLogResponse{}, ctx.Err()
		}
		return SessionLogResponse{}, ErrDependencyUnavailable
	}
	response := SessionLogResponse{Version: SessionLogVersion, From: filter.From, To: filter.To, Rows: []SessionLogRow{}}
	more := len(rows) > int(filter.Limit)
	if more {
		rows = rows[:filter.Limit]
	}
	for _, row := range rows {
		if !requiredUUID(row.NodeID) || !requiredUUID(row.StreamID) || row.EventID == "" || row.FinalizedAt.IsZero() {
			return SessionLogResponse{}, ErrInvalidResponse
		}
		response.Rows = append(response.Rows, row)
	}
	if more {
		last := rows[len(rows)-1]
		response.NextCursor, err = service.encodeSessionLogCursor(scope, filter, sessionLogAfter{FinalizedAt: last.FinalizedAt, EventID: last.EventID})
		if err != nil {
			return SessionLogResponse{}, err
		}
	}
	return response, nil
}

func sessionLogDigest(filter sessionLogFilter) [32]byte {
	filter.From, filter.To, filter.Limit, filter.Snapshot, filter.After = time.Time{}, time.Time{}, 0, Snapshot{}, nil
	payload, _ := json.Marshal(filter)
	return sha256.Sum256(append([]byte("l4-session-logs\x00"), payload...))
}

func (service *Service) encodeSessionLogCursor(scope Scope, filter sessionLogFilter, after sessionLogAfter) (string, error) {
	payload, err := json.Marshal(sessionLogCursor{Version: 1, TenantID: scope.TenantID, Filter: sessionLogDigest(filter),
		From: filter.From, To: filter.To, After: after})
	if err != nil {
		return "", ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write([]byte("l4-session-logs\x00"))
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...)), nil
}

func (service *Service) decodeSessionLogCursor(raw string, scope Scope, filter sessionLogFilter) (sessionLogCursor, error) {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(payload) <= sha256.Size || len(payload) > maximumCursorBytes {
		return sessionLogCursor{}, ErrInvalidCursor
	}
	body, signature := payload[:len(payload)-sha256.Size], payload[len(payload)-sha256.Size:]
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write([]byte("l4-session-logs\x00"))
	_, _ = mac.Write(body)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return sessionLogCursor{}, ErrInvalidCursor
	}
	var cursor sessionLogCursor
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.TenantID != scope.TenantID ||
		cursor.Filter != sessionLogDigest(filter) || cursor.After.EventID == "" || !cursor.From.Before(cursor.To) {
		return sessionLogCursor{}, ErrInvalidCursor
	}
	return cursor, nil
}

type sessionLogRow struct {
	FinalizedMS       int64   `json:"finalized_ms"`
	StartedMS         int64   `json:"started_ms"`
	EventID           string  `json:"event_id"`
	NodeID            string  `json:"node_id"`
	SiteID            string  `json:"site_id"`
	StreamID          string  `json:"stream_id"`
	ListenerID        string  `json:"listener_id"`
	Protocol          string  `json:"protocol"`
	ListenPort        uint16  `json:"listen_port"`
	ClientIP          string  `json:"client_ip"`
	ClientPort        uint16  `json:"client_port"`
	PeerIP            string  `json:"peer_ip"`
	UpstreamAddr      string  `json:"upstream_addr"`
	UpstreamConnectMS *uint32 `json:"upstream_connect_ms"`
	BytesUp           uint64  `json:"bytes_up"`
	BytesDown         uint64  `json:"bytes_down"`
	StatusCode        uint16  `json:"status_code"`
	EndReason         string  `json:"end_reason"`
}

const sessionLogTable = "l4_session_logs_v1"

// sessionLogTableExists asks ClickHouse whether the session log table is
// installed (a control plane installed before migration 017 lacks it).
func (source *ClickHouseSource) sessionLogTableExists(ctx context.Context) (bool, error) {
	var row struct {
		Result int `json:"result"`
	}
	if err := source.doJSON(ctx, "EXISTS TABLE "+sessionLogTable+" FORMAT JSONEachRow", url.Values{}, &row); err != nil {
		return false, err
	}
	return row.Result == 1, nil
}

func (source *ClickHouseSource) readSessionLogs(ctx context.Context, scope Scope, filter sessionLogFilter, after *sessionLogAfter) ([]SessionLogRow, error) {
	exists, err := source.sessionLogTableExists(ctx)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrSessionLogUnavailable
	}
	const layout = "2006-01-02 15:04:05.000"
	conditions := []string{"finalized_at >= {from:DateTime64(3)}", "finalized_at < {to:DateTime64(3)}"}
	params := url.Values{"from": {filter.From.UTC().Format(layout)}, "to": {filter.To.UTC().Format(layout)},
		"limit": {strconv.Itoa(int(filter.Limit) + 1)}}
	add := func(condition, key, value string) {
		conditions = append(conditions, condition)
		params.Set(key, value)
	}
	if scope.TenantID != "" {
		add("tenant_id = {tenant_id:UUID}", "tenant_id", scope.TenantID)
	}
	if filter.SiteID != "" {
		add("site_id = {site_id:UUID}", "site_id", filter.SiteID)
	}
	if filter.StreamID != "" {
		add("stream_id = {stream_id:UUID}", "stream_id", filter.StreamID)
	}
	if filter.NodeID != "" {
		add("node_id = {node_id:UUID}", "node_id", filter.NodeID)
	}
	if filter.Protocol != "" {
		add("protocol = {protocol:String}", "protocol", filter.Protocol)
	}
	if filter.ListenPort != 0 {
		add("listen_port = {listen_port:UInt16}", "listen_port", strconv.Itoa(int(filter.ListenPort)))
	}
	if filter.ClientCIDR != "" {
		prefix := netip.MustParsePrefix(filter.ClientCIDR)
		if prefix.Addr().Is4() {
			// A dual-stack listener stores IPv4 peers as ::ffff:a.b.c.d.
			mapped := netip.PrefixFrom(netip.AddrFrom16(prefix.Addr().As16()), prefix.Bits()+96)
			add("(isIPAddressInRange(client_ip, {client_cidr:String}) OR isIPAddressInRange(client_ip, {client_cidr_mapped:String}))",
				"client_cidr", filter.ClientCIDR)
			params.Set("client_cidr_mapped", mapped.String())
		} else {
			add("isIPAddressInRange(client_ip, {client_cidr:String})", "client_cidr", filter.ClientCIDR)
		}
	}
	if filter.EndReason != "" {
		add("end_reason = {end_reason:String}", "end_reason", filter.EndReason)
	}
	if after != nil {
		conditions = append(conditions, "(finalized_at, event_id) < ({after_finalized:DateTime64(3)}, {after_event:String})")
		params.Set("after_finalized", after.FinalizedAt.UTC().Format(layout))
		params.Set("after_event", after.EventID)
	}
	query := `SELECT toUnixTimestamp64Milli(finalized_at) AS finalized_ms, toUnixTimestamp64Milli(started_at) AS started_ms,
event_id, node_id, site_id, stream_id, listener_id, protocol, listen_port, client_ip, client_port, peer_ip, upstream_addr,
upstream_connect_ms, bytes_up, bytes_down, status_code, end_reason FROM ` + sessionLogTable + ` FINAL WHERE ` +
		strings.Join(conditions, " AND ") + ` ORDER BY finalized_at DESC, event_id DESC LIMIT {limit:UInt32} FORMAT JSONEachRow`
	var rows []sessionLogRow
	if err := source.doJSONLines(ctx, query, params, &rows); err != nil {
		return nil, err
	}
	result := make([]SessionLogRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, SessionLogRow{EventID: row.EventID, StartedAt: time.UnixMilli(row.StartedMS).UTC(),
			FinalizedAt: time.UnixMilli(row.FinalizedMS).UTC(), NodeID: row.NodeID, SiteID: row.SiteID, StreamID: row.StreamID,
			ListenerID: row.ListenerID, Protocol: row.Protocol, ListenPort: row.ListenPort, ClientIP: unmappedIP(row.ClientIP),
			ClientPort: row.ClientPort, PeerIP: row.PeerIP, UpstreamAddr: row.UpstreamAddr, UpstreamConnectMS: row.UpstreamConnectMS,
			BytesUp: row.BytesUp, BytesDown: row.BytesDown, StatusCode: row.StatusCode, EndReason: row.EndReason})
	}
	return result, nil
}

type l4SessionLogInsertRow struct {
	TenantID          string  `json:"tenant_id"`
	NodeID            string  `json:"node_id"`
	SiteID            string  `json:"site_id"`
	StreamID          string  `json:"stream_id"`
	ListenerID        string  `json:"listener_id"`
	SessionID         string  `json:"session_id"`
	StartedAt         string  `json:"started_at"`
	FinalizedAt       string  `json:"finalized_at"`
	Protocol          string  `json:"protocol"`
	ListenPort        uint32  `json:"listen_port"`
	ClientIP          string  `json:"client_ip"`
	ClientPort        uint32  `json:"client_port"`
	PeerIP            string  `json:"peer_ip"`
	UpstreamAddr      string  `json:"upstream_addr"`
	UpstreamConnectMS *uint32 `json:"upstream_connect_ms"`
	BytesUp           uint64  `json:"bytes_up"`
	BytesDown         uint64  `json:"bytes_down"`
	StatusCode        uint32  `json:"status_code"`
	EndReason         string  `json:"end_reason"`
	EventID           string  `json:"event_id"`
	SourceWatermark   uint64  `json:"source_watermark"`
}

// NewClickHouseFactWriterWithSessionLogs is NewClickHouseFactWriter that
// also writes the session logs of logging streams, when the table exists.
func NewClickHouseFactWriterWithSessionLogs(ctx context.Context, source *ClickHouseSource) (*ClickHouseFactWriter, error) {
	writer, err := NewClickHouseFactWriter(source)
	if err != nil {
		return nil, err
	}
	exists, err := source.sessionLogTableExists(ctx)
	if err != nil {
		return nil, ErrDependencyUnavailable
	}
	writer.sessionLogs = exists
	return writer, nil
}

func (writer *ClickHouseFactWriter) writeSessionLogs(ctx context.Context, events []*agentv1.L4SessionEventV1, watermark uint64) error {
	if !writer.sessionLogs {
		return nil
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, event := range events {
		log := event.GetSessionLog()
		if log == nil {
			continue
		}
		row := l4SessionLogInsertRow{TenantID: event.GetTenantId(), NodeID: event.GetNodeId(), SiteID: event.GetSiteId(),
			StreamID: event.GetStreamId(), ListenerID: event.GetListenerId(), SessionID: event.GetSessionId(),
			StartedAt: event.GetStartedAt().AsTime().UTC().Format(clickHouseDateTime64), FinalizedAt: event.GetFinalizedAt().AsTime().UTC().Format(clickHouseDateTime64),
			Protocol: event.GetProtocol(), ListenPort: event.GetListenPort(), ClientIP: log.GetClientIp(), ClientPort: log.GetClientPort(),
			PeerIP: log.GetPeerIp(), UpstreamAddr: log.GetUpstreamAddr(), BytesUp: event.GetBytesUp(), BytesDown: event.GetBytesDown(),
			StatusCode: event.GetStatusCode(), EndReason: log.GetEndReason(), EventID: event.GetEvent().GetEventId(), SourceWatermark: watermark}
		if log.UpstreamConnectMs != nil {
			value := log.GetUpstreamConnectMs()
			row.UpstreamConnectMS = &value
		}
		if err := encoder.Encode(row); err != nil {
			return ErrInvalidRequest
		}
	}
	if body.Len() == 0 {
		return nil
	}
	return writer.source.insertRows(ctx, sessionLogTable, body.Bytes())
}

// unmappedIP returns an IPv4-mapped address (::ffff:a.b.c.d, as a dual-stack
// listener reports IPv4 peers) as dotted IPv4 and any other value as is.
func unmappedIP(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	return address.Unmap().String()
}
