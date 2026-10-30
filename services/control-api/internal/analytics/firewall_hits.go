package analytics

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
)

const firewallHitSnapshotSQL = `SELECT
    toInt64(toUnixTimestamp64Milli(occurred_at)) AS occurred_at_ms,event_id
FROM security_events FINAL
WHERE event_type='global_firewall' AND tenant_id={tenant_id:UUID}
  AND ({has_site:UInt8}=0 OR site_id={site_id:UUID})
ORDER BY occurred_at DESC,event_id DESC LIMIT 1
FORMAT JSONEachRow`

// The String aliases tenant_id/site_id shadow the UUID columns in WHERE
// (ClickHouse resolves an alias first): the filters name the table columns.
const firewallHitPageSQL = `SELECT
    event_id,toInt64(toUnixTimestamp64Milli(occurred_at)) AS occurred_at_ms,
    toString(tenant_id) AS tenant_id,toString(site_id) AS site_id,toString(node_id) AS node_id,
    rule_id,client_ip,protocol,destination_port,action
FROM security_events FINAL
WHERE event_type='global_firewall' AND security_events.tenant_id={tenant_id:UUID}
  AND ({has_site:UInt8}=0 OR security_events.site_id={site_id:UUID})
  AND tuple(toUnixTimestamp64Milli(occurred_at),event_id)<=tuple({snapshot_ms:Int64},{snapshot_id:String})
  AND ({has_position:UInt8}=0 OR tuple(toUnixTimestamp64Milli(occurred_at),event_id)<tuple({position_ms:Int64},{position_id:String}))
ORDER BY occurred_at DESC,event_id DESC LIMIT {row_limit:UInt16}
FORMAT JSONEachRow`

type firewallHitCursor struct {
	TenantID   string `json:"tenant_id"`
	SiteID     string `json:"site_id,omitempty"`
	SnapshotMS int64  `json:"snapshot_ms"`
	SnapshotID string `json:"snapshot_id"`
	PositionMS int64  `json:"position_ms"`
	PositionID string `json:"position_id"`
}

type firewallHitSnapshotRow struct {
	OccurredAtMS int64  `json:"occurred_at_ms"`
	EventID      string `json:"event_id"`
}

type firewallHitRow struct {
	EventID         string `json:"event_id"`
	OccurredAtMS    int64  `json:"occurred_at_ms"`
	TenantID        string `json:"tenant_id"`
	SiteID          string `json:"site_id"`
	NodeID          string `json:"node_id"`
	RuleID          string `json:"rule_id"`
	ClientIP        string `json:"client_ip"`
	Protocol        string `json:"protocol"`
	DestinationPort uint16 `json:"destination_port"`
	Action          string `json:"action"`
}

func (client *Client) ListFirewallHits(ctx context.Context, filter firewallcontrol.HitFilter) (firewallcontrol.HitPage, error) {
	if client == nil || ctx == nil || filter.TargetScopeID == uuid.Nil || filter.Limit < 1 || filter.Limit > 100 {
		return firewallcontrol.HitPage{}, firewallcontrol.ErrInvalidInput
	}
	cursor, err := decodeFirewallHitCursor(filter)
	if err != nil {
		return firewallcontrol.HitPage{}, firewallcontrol.ErrInvalidInput
	}
	// The events carry the site's tenant (tenants.id, the gateway's
	// authority), not the scope the policy and the request name. A scope
	// without a tenant (the platform scope) has no telemetry identity, so no
	// hit of it reaches ClickHouse.
	resolved, err := client.tenantOfScope(ctx, filter.TargetScopeID.String())
	if errors.Is(err, ErrInvalidInput) {
		return firewallcontrol.HitPage{Items: []firewallcontrol.Hit{}}, nil
	}
	if err != nil {
		return firewallcontrol.HitPage{}, firewallcontrol.ErrUnavailable
	}
	tenantID := uuid.MustParse(resolved)
	parameters := url.Values{
		"param_tenant_id": {resolved}, "param_site_id": {filter.SiteID.String()},
		"param_has_site": {boolParameter(filter.SiteID != uuid.Nil)},
	}
	if filter.SiteID == uuid.Nil {
		parameters.Set("param_site_id", nilUUIDValue)
	}
	if cursor.SnapshotID == "" {
		snapshot, queryErr := queryRows[firewallHitSnapshotRow](client, ctx, firewallHitSnapshotSQL, parameters, 1)
		if queryErr != nil {
			return firewallcontrol.HitPage{}, firewallcontrol.ErrUnavailable
		}
		if len(snapshot) == 0 {
			return firewallcontrol.HitPage{Items: []firewallcontrol.Hit{}}, nil
		}
		cursor = firewallHitCursor{TenantID: filter.TargetScopeID.String(), SiteID: filter.SiteID.String(),
			SnapshotMS: snapshot[0].OccurredAtMS, SnapshotID: snapshot[0].EventID}
		if filter.SiteID == uuid.Nil {
			cursor.SiteID = ""
		}
	}
	parameters.Set("param_snapshot_ms", strconv.FormatInt(cursor.SnapshotMS, 10))
	parameters.Set("param_snapshot_id", cursor.SnapshotID)
	parameters.Set("param_position_ms", strconv.FormatInt(cursor.PositionMS, 10))
	parameters.Set("param_position_id", cursor.PositionID)
	parameters.Set("param_has_position", boolParameter(cursor.PositionID != ""))
	parameters.Set("param_row_limit", strconv.Itoa(filter.Limit+1))
	rows, err := queryRows[firewallHitRow](client, ctx, firewallHitPageSQL, parameters, filter.Limit+1)
	if err != nil {
		return firewallcontrol.HitPage{}, firewallcontrol.ErrUnavailable
	}
	page := firewallcontrol.HitPage{Items: make([]firewallcontrol.Hit, 0, min(len(rows), filter.Limit))}
	for index, row := range rows {
		if index == filter.Limit {
			break
		}
		hit, ok := firewallHitFromRow(row, tenantID, filter.TargetScopeID, filter.SiteID)
		if !ok {
			return firewallcontrol.HitPage{}, firewallcontrol.ErrUnavailable
		}
		page.Items = append(page.Items, hit)
	}
	if len(rows) > filter.Limit && len(page.Items) > 0 {
		last := page.Items[len(page.Items)-1]
		cursor.PositionMS, cursor.PositionID = last.OccurredAt.UnixMilli(), last.ID
		encoded, encodeErr := json.Marshal(cursor)
		if encodeErr != nil {
			return firewallcontrol.HitPage{}, firewallcontrol.ErrUnavailable
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	return page, nil
}

func decodeFirewallHitCursor(filter firewallcontrol.HitFilter) (firewallHitCursor, error) {
	if filter.Cursor == "" {
		return firewallHitCursor{}, nil
	}
	encoded, err := base64.RawURLEncoding.DecodeString(filter.Cursor)
	if err != nil || len(encoded) == 0 || len(encoded) > 1024 {
		return firewallHitCursor{}, errors.New("invalid cursor")
	}
	var cursor firewallHitCursor
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		cursor.TenantID != filter.TargetScopeID.String() || cursor.SiteID != optionalFirewallHitSiteID(filter.SiteID) ||
		cursor.SnapshotMS <= 0 || cursor.PositionMS <= 0 || cursor.SnapshotID == "" || cursor.PositionID == "" ||
		cursor.PositionMS > cursor.SnapshotMS || len(cursor.SnapshotID) > 128 || len(cursor.PositionID) > 128 {
		return firewallHitCursor{}, errors.New("invalid cursor")
	}
	return cursor, nil
}

// firewallHitFromRow checks the row belongs to tenantID (tenants.id) and
// reports it under scopeID, the scope the hit API is keyed by.
func firewallHitFromRow(row firewallHitRow, tenantID, scopeID, siteFilter uuid.UUID) (firewallcontrol.Hit, bool) {
	rowTenant, tenantErr := uuid.Parse(row.TenantID)
	rowSite, siteErr := uuid.Parse(row.SiteID)
	rowNode, nodeErr := uuid.Parse(row.NodeID)
	// client_ip is an IPv6 column: an IPv4 client reads back as ::ffff:a.b.c.d.
	clientIP, clientErr := netip.ParseAddr(row.ClientIP)
	clientIP = clientIP.Unmap()
	if tenantErr != nil || siteErr != nil || nodeErr != nil || rowTenant != tenantID ||
		siteFilter != uuid.Nil && rowSite != siteFilter || row.EventID == "" || row.OccurredAtMS <= 0 ||
		clientErr != nil ||
		(row.Protocol != "tcp" && row.Protocol != "udp" && row.Protocol != "icmp") ||
		(row.Protocol == "icmp" && row.DestinationPort != 0) ||
		(row.Protocol != "icmp" && row.DestinationPort == 0) || row.Action != "block" {
		return firewallcontrol.Hit{}, false
	}
	hit := firewallcontrol.Hit{ID: row.EventID, OccurredAt: time.UnixMilli(row.OccurredAtMS).UTC(), TenantScopeID: scopeID,
		SiteID: rowSite, NodeID: rowNode, ClientIP: clientIP.String(), Protocol: row.Protocol,
		DestinationPort: row.DestinationPort, Action: firewallcontrol.ActionDeny, ReasonCode: "default-deny"}
	if row.RuleID != "" {
		ruleID, err := uuid.Parse(row.RuleID)
		if err != nil || ruleID == uuid.Nil || ruleID.String() != row.RuleID {
			return firewallcontrol.Hit{}, false
		}
		hit.RuleID, hit.ReasonCode = ruleID, "rule:"+row.RuleID
	}
	return hit, true
}

func boolParameter(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func optionalFirewallHitSiteID(value uuid.UUID) string {
	if value == uuid.Nil {
		return ""
	}
	return value.String()
}
