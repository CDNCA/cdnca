package securityanalytics

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/google/uuid"
)

// Market attack digests (ADR 0012 §19.1, ML-20/21). The leaf reads one market
// site's security logs and verdicts of a window (SiteSecurityWindow); the
// subscriber stores what it received in MarketSecurityTable (CH 026) and
// reads the per site sums back for attack alerts (MarketAttackSummaries).

// MarketSecurityTable is the subscriber's copy of relayed market security
// data, one row per summary, mitigation or log line.
const MarketSecurityTable = "market_security_events_v1"

// SiteSecurityWindow returns up to limit of the newest enforced WAF / CC log
// lines of one site in [from, to) and how many there were in total, and
// every automatic defence verdict of the site in the window (newest first,
// at most limit + 1, enough for secdigest.Truncate to count drops).
func (ch *ClickHouse) SiteSecurityWindow(ctx context.Context, tenant, site uuid.UUID, from, to time.Time, limit int,
) (logs []secdigest.Log, totalLogs int64, actions []secdigest.Action, err error) {
	params := map[string]string{"tenant": tenant.String(), "site": site.String(),
		"from": strconv.FormatInt(from.UnixMilli(), 10), "to": strconv.FormatInt(to.UnixMilli(), 10), "limit": strconv.Itoa(limit)}
	window := ` AND occurred_at >= fromUnixTimestamp64Milli({from:Int64}, 'UTC') AND occurred_at < fromUnixTimestamp64Milli({to:Int64}, 'UTC')`
	security := `FROM security_events FINAL WHERE metric_version = 1 AND tenant_id = {tenant:UUID} AND site_id = {site:UUID}
		AND event_type IN ('waf', 'cc') AND action IN ('block', 'challenge', 'temporary_ban')` + window
	var total struct {
		N int64 `json:"n"`
	}
	if err := ch.rows(ctx, `SELECT toInt64(count()) AS n `+security, params, func(line []byte) error {
		return json.Unmarshal(line, &total)
	}); err != nil {
		return nil, 0, nil, err
	}
	err = ch.rows(ctx, `SELECT toInt64(toUnixTimestamp64Milli(occurred_at)) AS at_ms, IPv6NumToString(client_ip) AS client_ip,
		host, path, toString(action) AS action, toString(detector) AS detector, rule_id `+security+`
		ORDER BY occurred_at DESC, event_id DESC LIMIT {limit:UInt32}`, params, func(line []byte) error {
		var row secdigest.Log
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		row.ClientIP = unmapClientIP(row.ClientIP)
		logs = append(logs, row)
		return nil
	})
	if err != nil {
		return nil, 0, nil, err
	}
	params["limit"] = strconv.Itoa(limit + 1)
	err = ch.rows(ctx, `SELECT toInt64(toUnixTimestamp(occurred_at)) AS at, toString(target_kind) AS kind, target,
		toInt64(level) AS level, toInt64(toUnixTimestamp(until)) AS until, reason
		FROM `+VerdictTable+` FINAL WHERE tenant_id = {tenant:UUID} AND site_id = {site:UUID}`+window+`
		ORDER BY occurred_at DESC, verdict_id LIMIT {limit:UInt32}`, params, func(line []byte) error {
		var row secdigest.Action
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		row.Source = "autodefense"
		actions = append(actions, row)
		return nil
	})
	if err != nil {
		return nil, 0, nil, err
	}
	return logs, total.N, actions, nil
}

func (ch *ClickHouse) rows(ctx context.Context, query string, params map[string]string, each func([]byte) error) error {
	// 64-bit integers unquoted, as the row structs decode them as numbers.
	data, err := ch.do(ctx, query+" SETTINGS output_format_json_quote_64bit_integers = 0 FORMAT JSONEachRow", params, nil)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		if err := each(scanner.Bytes()); err != nil {
			return fmt.Errorf("%w: row: %v", ErrClickHouse, err)
		}
	}
	return scanner.Err()
}

// MarketSecurity is one relayed digest bound to a local site.
type MarketSecurity struct {
	TenantID, SiteID, SupplyID, LeafMemberID uuid.UUID
	// LeafRef is the subscriber's display number of the leaf (leaf member ID
	// prefix); the subscriber already knows its leaves by member ID.
	LeafRef    string
	ReceivedAt time.Time
	Digest     secdigest.Digest
}

type marketSecurityRow struct {
	TenantID     string `json:"tenant_id"`
	SiteID       string `json:"site_id"`
	SupplyID     string `json:"supply_id"`
	LeafMemberID string `json:"leaf_member_id"`
	LeafRef      string `json:"leaf_ref"`
	LeafSiteID   string `json:"leaf_site_id"`
	WindowStart  string `json:"window_start"`
	RowKind      string `json:"row_kind"`
	RowIndex     uint32 `json:"row_index"`
	OccurredAt   string `json:"occurred_at"`
	Source       string `json:"source"`
	Action       string `json:"action"`
	Detector     string `json:"detector"`
	RuleID       string `json:"rule_id"`
	ClientIP     string `json:"client_ip"`
	Host         string `json:"host"`
	Path         string `json:"path"`
	TargetKind   string `json:"target_kind"`
	Target       string `json:"target"`
	Level        uint8  `json:"level"`
	Until        string `json:"until"`
	Reason       string `json:"reason"`
	Events       uint64 `json:"events"`
	Blocked      uint64 `json:"blocked"`
	Challenged   uint64 `json:"challenged"`
	Banned       uint64 `json:"banned"`
	Clients      uint64 `json:"clients"`
	DroppedLogs  uint64 `json:"dropped_logs"`
	ReceivedAt   string `json:"received_at"`
}

// WriteMarketSecurity stores one digest: a summary row, then its actions
// and logs. Rows are keyed by (site, leaf, window, kind, index), so a
// redelivered digest replaces its own rows (read with FINAL).
func (ch *ClickHouse) WriteMarketSecurity(ctx context.Context, m MarketSecurity) error {
	d := m.Digest
	base := marketSecurityRow{TenantID: m.TenantID.String(), SiteID: m.SiteID.String(), SupplyID: m.SupplyID.String(),
		LeafMemberID: m.LeafMemberID.String(), LeafRef: m.LeafRef, LeafSiteID: d.LeafSiteID.String(),
		WindowStart: chTime(time.Unix(d.WindowStart, 0)), ReceivedAt: chTime(m.ReceivedAt), Until: chTime(time.Unix(0, 0))}
	summary := base
	summary.RowKind, summary.OccurredAt = "summary", chTime(time.Unix(d.WindowStart, 0))
	if d.Summary.LastMS > 0 {
		summary.OccurredAt = chTime(time.UnixMilli(d.Summary.LastMS))
	}
	summary.Events, summary.Blocked, summary.Challenged = uint64(d.Summary.Events), uint64(d.Summary.Blocked), uint64(d.Summary.Challenged)
	summary.Banned, summary.Clients, summary.DroppedLogs = uint64(d.Summary.Banned), uint64(d.Summary.Clients), uint64(d.Dropped.Logs)
	summary.Detector, summary.ClientIP = d.Summary.TopDetector, d.Summary.TopClientIP
	rows := []any{summary}
	for i, a := range d.Actions {
		row := base
		row.RowKind, row.RowIndex, row.OccurredAt, row.Source = "action", uint32(i), chTime(time.Unix(a.At, 0)), a.Source
		row.TargetKind, row.Target, row.Level, row.Reason = a.Kind, a.Target, uint8(a.Level), a.Reason
		if a.Until > 0 {
			row.Until = chTime(time.Unix(a.Until, 0))
		}
		rows = append(rows, row)
	}
	for i, l := range d.Logs {
		row := base
		row.RowKind, row.RowIndex, row.OccurredAt, row.Source = "log", uint32(i), chTime(time.UnixMilli(l.AtMS)), "market"
		row.ClientIP, row.Host, row.Path, row.Action, row.Detector, row.RuleID = l.ClientIP, l.Host, l.Path, l.Action, l.Detector, l.RuleID
		rows = append(rows, row)
	}
	return ch.insert(ctx, MarketSecurityTable, rows)
}

// MarketAttackSummary is the sum of relayed summaries of one local site
// received in a window (attackalert merges it with the local summary).
type MarketAttackSummary struct {
	TenantID, SiteID                             string
	Events, Blocked, Challenged, Banned, Clients uint64
	TopDetector, TopClientIP                     string
	FirstEventAt, LastEventAt                    time.Time
}

// MarketAttackSummaries sums the relayed summaries received in [from, to)
// per local site. Received time, not the leaf window, decides the window:
// a digest arrives after its leaf window closed, and alerts must not miss
// it because the local window was already evaluated.
func (ch *ClickHouse) MarketAttackSummaries(ctx context.Context, from, to time.Time, limit int) ([]MarketAttackSummary, error) {
	params := map[string]string{"from": strconv.FormatInt(from.UnixMilli(), 10), "to": strconv.FormatInt(to.UnixMilli(), 10),
		"limit": strconv.Itoa(limit)}
	var out []MarketAttackSummary
	// Output aliases differ from the column names: ClickHouse resolves an
	// alias before a column, so "AS events" would nest sum() in argMax().
	err := ch.rows(ctx, `SELECT toString(m.tenant_id) AS tenant, toString(m.site_id) AS site,
		toUInt64(sum(m.events)) AS total_events, toUInt64(sum(m.blocked)) AS total_blocked, toUInt64(sum(m.challenged)) AS total_challenged,
		toUInt64(sum(m.banned)) AS total_banned, toUInt64(max(m.clients)) AS max_clients,
		argMax(m.detector, m.events) AS top_detector, argMax(m.client_ip, m.events) AS top_client_ip,
		toInt64(toUnixTimestamp64Milli(min(m.window_start))) AS first_ms, toInt64(toUnixTimestamp64Milli(max(m.occurred_at))) AS last_ms
		FROM `+MarketSecurityTable+` AS m FINAL WHERE m.row_kind = 'summary'
		AND m.received_at >= fromUnixTimestamp64Milli({from:Int64}, 'UTC') AND m.received_at < fromUnixTimestamp64Milli({to:Int64}, 'UTC')
		GROUP BY m.tenant_id, m.site_id ORDER BY total_events DESC, tenant, site LIMIT {limit:UInt32}`, params, func(line []byte) error {
		var row struct {
			TenantID    string `json:"tenant"`
			SiteID      string `json:"site"`
			Events      uint64 `json:"total_events"`
			Blocked     uint64 `json:"total_blocked"`
			Challenged  uint64 `json:"total_challenged"`
			Banned      uint64 `json:"total_banned"`
			Clients     uint64 `json:"max_clients"`
			TopDetector string `json:"top_detector"`
			TopClientIP string `json:"top_client_ip"`
			FirstMS     int64  `json:"first_ms"`
			LastMS      int64  `json:"last_ms"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		out = append(out, MarketAttackSummary{TenantID: row.TenantID, SiteID: row.SiteID, Events: row.Events, Blocked: row.Blocked,
			Challenged: row.Challenged, Banned: row.Banned, Clients: row.Clients, TopDetector: row.TopDetector,
			TopClientIP: row.TopClientIP, FirstEventAt: time.UnixMilli(row.FirstMS).UTC(), LastEventAt: time.UnixMilli(row.LastMS).UTC()})
		return nil
	})
	return out, err
}

// MarketSecurityLog is one relayed attack log line of a local site, for the
// subscriber's attack log page (source "market supply · leaf_ref").
type MarketSecurityLog struct {
	SiteID     uuid.UUID `json:"site_id"`
	SupplyID   uuid.UUID `json:"supply_id"`
	LeafRef    string    `json:"leaf_ref"`
	OccurredAt time.Time `json:"occurred_at"`
	ClientIP   string    `json:"client_ip"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Action     string    `json:"action"`
	Detector   string    `json:"detector"`
	RuleID     string    `json:"rule_id"`
	// Cursor is this row's keyset position; pass the last one as after.
	Cursor string `json:"cursor"`
}

// MarketSecurityFilter narrows ListMarketSecurityLogs; zero values match all.
type MarketSecurityFilter struct {
	Site     uuid.UUID
	ClientIP string
	Host     string
}

// ListMarketSecurityLogs returns up to limit relayed log lines of the
// tenant in [from, to), newest first, after the keyset cursor (empty for
// the first page). The cursor is opaque to callers.
func (ch *ClickHouse) ListMarketSecurityLogs(ctx context.Context, tenant uuid.UUID, filter MarketSecurityFilter,
	from, to time.Time, after string, limit int) ([]MarketSecurityLog, error) {
	params := map[string]string{"tenant": tenant.String(), "from": strconv.FormatInt(from.UnixMilli(), 10),
		"to": strconv.FormatInt(to.UnixMilli(), 10), "limit": strconv.Itoa(limit)}
	where := `tenant_id = {tenant:UUID} AND row_kind = 'log'
		AND occurred_at >= fromUnixTimestamp64Milli({from:Int64}, 'UTC') AND occurred_at < fromUnixTimestamp64Milli({to:Int64}, 'UTC')`
	if filter.Site != uuid.Nil {
		params["site"] = filter.Site.String()
		where += ` AND site_id = {site:UUID}`
	}
	if filter.ClientIP != "" {
		params["client_ip"] = filter.ClientIP
		where += ` AND client_ip = {client_ip:String}`
	}
	if filter.Host != "" {
		params["host"] = filter.Host
		where += ` AND host = {host:String}`
	}
	if after != "" {
		c, err := parseMarketCursor(after)
		if err != nil {
			return nil, err
		}
		params["c_at"], params["c_site"], params["c_leaf"] = strconv.FormatInt(c.at, 10), c.site.String(), c.leaf.String()
		params["c_window"], params["c_index"] = strconv.FormatInt(c.window, 10), strconv.FormatUint(uint64(c.index), 10)
		where += ` AND (toUnixTimestamp64Milli(occurred_at), site_id, leaf_member_id, toUnixTimestamp64Milli(window_start), row_index) <
			({c_at:Int64}, {c_site:UUID}, {c_leaf:UUID}, {c_window:Int64}, {c_index:UInt32})`
	}
	var out []MarketSecurityLog
	// Output names differ from the columns (an alias would shadow the
	// column in WHERE / ORDER BY, see MarketAttackSummaries).
	err := ch.rows(ctx, `SELECT toString(site_id) AS out_site, toString(supply_id) AS out_supply, toString(leaf_member_id) AS out_leaf,
		leaf_ref, toInt64(toUnixTimestamp64Milli(occurred_at)) AS at_ms, toInt64(toUnixTimestamp64Milli(window_start)) AS window_ms,
		row_index, client_ip, host, path, toString(action) AS out_action, toString(detector) AS out_detector, rule_id
		FROM `+MarketSecurityTable+` FINAL WHERE `+where+`
		ORDER BY occurred_at DESC, site_id DESC, leaf_member_id DESC, window_start DESC, row_index DESC LIMIT {limit:UInt32}`,
		params, func(line []byte) error {
			var row struct {
				SiteID   uuid.UUID `json:"out_site"`
				SupplyID uuid.UUID `json:"out_supply"`
				Leaf     uuid.UUID `json:"out_leaf"`
				LeafRef  string    `json:"leaf_ref"`
				AtMS     int64     `json:"at_ms"`
				WindowMS int64     `json:"window_ms"`
				RowIndex uint32    `json:"row_index"`
				ClientIP string    `json:"client_ip"`
				Host     string    `json:"host"`
				Path     string    `json:"path"`
				Action   string    `json:"out_action"`
				Detector string    `json:"out_detector"`
				RuleID   string    `json:"rule_id"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				return err
			}
			out = append(out, MarketSecurityLog{SiteID: row.SiteID, SupplyID: row.SupplyID, LeafRef: row.LeafRef,
				OccurredAt: time.UnixMilli(row.AtMS).UTC(), ClientIP: unmapClientIP(row.ClientIP), Host: row.Host, Path: row.Path,
				Action: row.Action, Detector: row.Detector, RuleID: row.RuleID,
				Cursor: marketCursor{row.AtMS, row.SiteID, row.Leaf, row.WindowMS, row.RowIndex}.String()})
			return nil
		})
	return out, err
}

// ErrMarketCursor is a malformed ListMarketSecurityLogs cursor.
var ErrMarketCursor = fmt.Errorf("%w: invalid market security cursor", ErrClickHouse)

type marketCursor struct {
	at         int64
	site, leaf uuid.UUID
	window     int64
	index      uint32
}

func (c marketCursor) String() string {
	return fmt.Sprintf("%d.%s.%s.%d.%d", c.at, c.site, c.leaf, c.window, c.index)
}

func parseMarketCursor(s string) (marketCursor, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 5 {
		return marketCursor{}, ErrMarketCursor
	}
	var c marketCursor
	var err1, err2, err3, err4, err5 error
	c.at, err1 = strconv.ParseInt(parts[0], 10, 64)
	c.site, err2 = uuid.Parse(parts[1])
	c.leaf, err3 = uuid.Parse(parts[2])
	c.window, err4 = strconv.ParseInt(parts[3], 10, 64)
	index, err5 := strconv.ParseUint(parts[4], 10, 32)
	c.index = uint32(index)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil || c.String() != s {
		return marketCursor{}, ErrMarketCursor
	}
	return c, nil
}

// unmapClientIP returns an IPv4-mapped address (::ffff:a.b.c.d) as dotted
// IPv4 and any other value as is.
func unmapClientIP(value string) string {
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap().String()
	}
	return value
}
