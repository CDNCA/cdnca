package securityanalytics

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node security event alerts: a kernel
// ban a node made on its own (ddos rate_ban / empty_connection_ban, l4guard
// kernel_ban) is announced in the notification center to the platform
// members who manage nodes, like node availability alerts. Nodes already
// report only new bans (bounded per step, with a summary row); the control
// plane merges them further: one message per (node, source, kind, hour),
// carrying the first event of the hour. Every event stays in ClickHouse.
const (
	EventTypeNodeSecurity       = notification.EventTypeNodeSecurityEvent
	nodeSecurityTemplate        = "node.security.event.zh-cn"
	nodeSecurityTemplateVersion = 1
	nodeSecurityPermission      = "nodes.manage"
	// NodeSecurityAlertBucket is the merge window of one (node, source, kind).
	NodeSecurityAlertBucket = time.Hour
)

// nodeSecurityXDPTemplate: XDP filter transitions (source xdp: fallback /
// reattached; migration 422) carry no client or ban.
const nodeSecurityXDPTemplate = "node.security.xdp.zh-cn"

// AlertEnqueuer is notification.Store's transactional enqueue.
type AlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// EnableNodeEventAlerts makes Ingest announce node security events. Call
// before the consumer starts.
func (ingestor *Ingestor) EnableNodeEventAlerts(enqueuer AlertEnqueuer) {
	ingestor.alerts = enqueuer
}

// NodeSecuritySourceEventID is the merge key of one alert message.
func NodeSecuritySourceEventID(event NodeEvent) string {
	bucket := event.OccurredAt.UTC().Unix() / int64(NodeSecurityAlertBucket/time.Second)
	return "node-security/" + event.NodeID.String() + "/" + event.Source + "/" + event.Kind + "/" + strconv.FormatInt(bucket, 10)
}

// alertNodeEvent runs in the ingest transaction under a savepoint: a failed
// notification is logged and never undoes the ingest.
func (ingestor *Ingestor) alertNodeEvent(ctx context.Context, tx pgx.Tx, event NodeEvent) {
	if ingestor.alerts == nil {
		return
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		slog.Warn("node security alert not enqueued", "node_id", event.NodeID, "error", err)
		return
	}
	if err := ingestor.enqueueNodeEventAlert(ctx, savepoint, event); err != nil {
		_ = savepoint.Rollback(ctx)
		slog.Warn("node security alert not enqueued", "node_id", event.NodeID, "kind", event.Kind, "error", err)
		return
	}
	if err := savepoint.Commit(ctx); err != nil {
		slog.Warn("node security alert not enqueued", "node_id", event.NodeID, "error", err)
	}
}

func (ingestor *Ingestor) enqueueNodeEventAlert(ctx context.Context, tx pgx.Tx, event NodeEvent) error {
	var scope uuid.UUID
	var name, address string
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT node.scope_id,node.name,COALESCE(host(node.ipv4),host(node.ipv6),''),
			scope.kind='platform' AND scope.tenant_id IS NULL
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id WHERE node.id=$1`, event.NodeID).
		Scan(&scope, &name, &address, &platform); err != nil {
		return err
	}
	if !platform {
		// Tenant-owned (marketplace seller) nodes are not alerted, like availability.
		return nil
	}
	source := NodeSecuritySourceEventID(event)
	// Merge: the hour's message already exists (it shows the first event; a
	// later one with other values would be an enqueue digest conflict).
	var merged bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_events WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3)`,
		scope, source, EventTypeNodeSecurity).Scan(&merged); err != nil || merged {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, scope, nodeSecurityPermission)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	values, template := nodeSecurityValues(event, name, address), nodeSecurityTemplate
	// The SMS template leaves the time out (length); contexts match exactly.
	smsOmits := map[string]bool{"occurred_at": true}
	if event.Source == "xdp" {
		values, template = nodeSecurityXDPValues(event, name, address), nodeSecurityXDPTemplate
		smsOmits["xdp_event"], smsOmits["xdp_reason"] = true, true
	}
	sms := notification.TemplateContext{}
	for key, value := range values {
		if !smsOmits[key] {
			sms[key] = value
		}
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: template, Version: nodeSecurityTemplateVersion, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: template, Version: nodeSecurityTemplateVersion, Channel: notification.ChannelEmail},
	}
	for _, recipient := range recipients {
		if _, err := ingestor.alerts.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: scope, RecipientID: recipient,
			SourceEventID: source, EventType: EventTypeNodeSecurity, Policy: notification.DeliverySystemRequired,
			Templates: templates, AuditRequestID: source,
			Contexts: map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: sms, notification.ChannelEmail: values},
		}); err != nil {
			return err
		}
	}
	return nil
}

// nodeSecurityKindTexts: the known node_event kinds (autodefense-contract §5).
var nodeSecurityKindTexts = map[string]string{
	"ddos/rate_ban":             "新建连接速率超限内核封禁",
	"ddos/empty_connection_ban": "空连接内核封禁",
	"l4guard/kernel_ban":        "四层防护规则内核拉黑",
	"xdp/fallback":              "XDP 过滤器回落到 nftables",
	"xdp/reattached":            "XDP 过滤器已重新挂载",
}

// nodeXDPReasonTexts: the agent internal/xdp Reason* codes (fallback) and
// modes (reattached).
var nodeXDPReasonTexts = map[string]string{
	"verify_failed": "运行中校验失败", "update_failed": "规则写入失败", "attach_failed": "网卡挂载失败",
	"load_failed": "程序加载失败", "self_test_failed": "自检失败", "no_interface": "无可用网卡",
	"bpf_unavailable": "BPF 不可用", "kernel_too_old": "内核版本过低",
	"native": "原生模式", "generic": "通用模式",
}

// nodeSecurityXDPValues: an XDP filter transition (source xdp). xdp_event
// and xdp_reason are codes (the console renders them per language); the
// email shows them next to the Chinese text.
func nodeSecurityXDPValues(event NodeEvent, name, address string) notification.TemplateContext {
	if address == "" {
		address = "-"
	}
	reason := nodeXDPReasonTexts[event.Reason]
	if reason == "" {
		reason = event.Reason
	}
	kind := nodeSecurityKindTexts[event.Source+"/"+event.Kind]
	if kind == "" {
		kind = event.Source + "/" + event.Kind
	}
	return notification.TemplateContext{
		"node_name": notification.PublicValue(name), "node_ip": notification.PublicValue(address),
		"event_kind": notification.PublicValue(kind), "xdp_event": notification.PublicValue(event.Kind),
		"xdp_reason": notification.PublicValue(event.Reason), "xdp_reason_text": notification.PublicValue(reason),
		"occurred_at": notification.PublicValue(event.OccurredAt.UTC().Format(time.RFC3339)),
	}
}

func nodeSecurityValues(event NodeEvent, name, address string) notification.TemplateContext {
	if address == "" {
		address = "-"
	}
	kind := nodeSecurityKindTexts[event.Source+"/"+event.Kind]
	if kind == "" {
		kind = event.Source + "/" + event.Kind
	}
	client := event.ClientIP
	if client == "" {
		// The node's summary row: count bans beyond its per-step budget.
		client = "多个"
	}
	duration := "-"
	if event.DurationSeconds > 0 {
		duration = strconv.FormatInt(event.DurationSeconds, 10)
	}
	return notification.TemplateContext{
		"node_name": notification.PublicValue(name), "node_ip": notification.PublicValue(address),
		"event_kind": notification.PublicValue(kind), "client_ip": notification.PublicValue(client),
		"count":            notification.PublicValue(strconv.FormatInt(max(event.Count, 1), 10)),
		"duration_seconds": notification.PublicValue(duration),
		"occurred_at":      notification.PublicValue(event.OccurredAt.UTC().Format(time.RFC3339)),
	}
}
