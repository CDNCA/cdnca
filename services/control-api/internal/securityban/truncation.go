package securityban

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// List truncation (migration 461): a node whose list is
// over the contract limit (one list must fit a 1 MiB gRPC message) is not
// refused — that would freeze every ban on the node — but cut by priority and
// signed as usual. The node state records warning_code=list_truncated with the
// count, and the platform members holding nodes.manage are told through the
// notification center, once per (list kind, node, hour). The write side has no
// per-node limit: sites and nodes are many-to-many, so a write cannot tell
// which node will overflow.
const (
	WarningListTruncated            = "list_truncated"
	EventTypeListTruncated          = notification.EventTypeNodeSecurityListTruncated
	listTruncatedTemplate           = "node.security.list_truncated.zh-cn"
	listTruncatedTemplateVersion    = 1
	listTruncatedPermission         = "nodes.manage"
	ListTruncatedAlertBucket        = time.Hour
	ListKindSecurityBan             = "security_ban"
	ListKindSiteDrop                = "site_drop"
	listKindSecurityBanDisplay      = "封禁名单"
	listKindSiteDropDisplay         = "站点丢弃名单"
	listTruncatedAlertSourcePrefix  = "list-truncated/"
	listTruncatedAlertSourceVersion = "v1"
)

// Truncate keeps every release and the bans that run longest (then the most
// recently created), so that bans+releases <= contract.MaxEntries; it returns
// the number of bans cut. created maps (site, client) to the newest creation.
func Truncate(bans []contract.Ban, releases []contract.Release, created map[[2]string]time.Time) ([]contract.Ban, int) {
	room := max(contract.MaxEntries-len(releases), 0)
	if len(bans) <= room {
		return bans, 0
	}
	kept := append([]contract.Ban(nil), bans...)
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].Until != kept[j].Until {
			return kept[i].Until > kept[j].Until
		}
		a, b := created[[2]string{kept[i].SiteID, kept[i].Client}], created[[2]string{kept[j].SiteID, kept[j].Client}]
		if !a.Equal(b) {
			return a.After(b)
		}
		if kept[i].SiteID != kept[j].SiteID {
			return kept[i].SiteID < kept[j].SiteID
		}
		return kept[i].Client < kept[j].Client
	})
	return kept[:room], len(bans) - room
}

// TruncationAlert describes one cut list.
type TruncationAlert struct {
	Kind   string // ListKindSecurityBan | ListKindSiteDrop
	NodeID uuid.UUID
	Total  int
	Limit  int
	Cut    int
	At     time.Time
}

// ListTruncatedSourceEventID is the merge key: one message per (kind, node, hour).
func ListTruncatedSourceEventID(kind string, nodeID uuid.UUID, at time.Time) string {
	bucket := at.UTC().Unix() / int64(ListTruncatedAlertBucket/time.Second)
	return listTruncatedAlertSourcePrefix + listTruncatedAlertSourceVersion + "/" + kind + "/" + nodeID.String() + "/" +
		strconv.FormatInt(bucket, 10)
}

// AlertListTruncated enqueues the alert in its own transaction; a failure is
// logged and never stops the list from being published.
func AlertListTruncated(ctx context.Context, pool *pgxpool.Pool, enqueuer AlertEnqueuer, alert TruncationAlert) {
	slog.Warn("list truncated to the contract limit", "warning_code", WarningListTruncated, "kind", alert.Kind,
		"node_id", alert.NodeID, "total", alert.Total, "limit", alert.Limit, "truncated", alert.Cut)
	if enqueuer == nil || pool == nil {
		return
	}
	if err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return enqueueListTruncated(ctx, tx, enqueuer, alert)
	}); err != nil {
		slog.Warn("list truncation alert not enqueued", "kind", alert.Kind, "node_id", alert.NodeID, "error", err)
	}
}

func enqueueListTruncated(ctx context.Context, tx pgx.Tx, enqueuer AlertEnqueuer, alert TruncationAlert) error {
	var platform uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).
		Scan(&platform); err != nil {
		return err
	}
	source := ListTruncatedSourceEventID(alert.Kind, alert.NodeID, alert.At)
	// Serialize the check-then-enqueue of one source across distributor runs.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 461))`, source); err != nil {
		return err
	}
	var merged bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_events WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3)`,
		platform, source, EventTypeListTruncated).Scan(&merged); err != nil || merged {
		return err
	}
	var name, address string
	if err := tx.QueryRow(ctx, `SELECT name,COALESCE(host(ipv4),host(ipv6),'') FROM nodes WHERE id=$1`, alert.NodeID).
		Scan(&name, &address); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, platform, listTruncatedPermission)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	kind := listKindSecurityBanDisplay
	if alert.Kind == ListKindSiteDrop {
		kind = listKindSiteDropDisplay
	}
	email := notification.TemplateContext{
		"node_name": notification.PublicValue(name), "node_ip": notification.PublicValue(address),
		"list_kind": notification.PublicValue(kind), "total": notification.PublicValue(strconv.Itoa(alert.Total)),
		"limit": notification.PublicValue(strconv.Itoa(alert.Limit)), "truncated": notification.PublicValue(strconv.Itoa(alert.Cut)),
		"occurred_at": notification.PublicValue(alert.At.UTC().Format(time.RFC3339)),
	}
	sms := notification.TemplateContext{"node_name": email["node_name"], "list_kind": email["list_kind"], "truncated": email["truncated"]}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: listTruncatedTemplate, Version: listTruncatedTemplateVersion, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: listTruncatedTemplate, Version: listTruncatedTemplateVersion, Channel: notification.ChannelEmail},
	}
	for _, recipient := range recipients {
		if _, err := enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: platform, RecipientID: recipient,
			SourceEventID: source, EventType: EventTypeListTruncated, Policy: notification.DeliverySystemRequired,
			Templates: templates, AuditRequestID: source,
			Contexts: map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: sms, notification.ChannelEmail: email},
		}); err != nil {
			return err
		}
	}
	return nil
}
