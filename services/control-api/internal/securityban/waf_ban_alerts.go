package securityban

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WAF automatic ban alerts: a node's WAF temporary_ban
// (同 IP 超阈值自动拉黑, waf_settings.auto_block, or a WAF ban rule) folded
// into the ban list is announced in the notification center to the platform
// members who manage nodes, like the node kernel bans (autodefense
// node_event_alerts.go). One message per (site, client, hour): the first ban
// of the hour; every ban stays in the ban list and ClickHouse.
const (
	EventTypeWAFBan        = notification.EventTypeNodeSecurityWAFBan
	wafBanTemplate         = "node.security.waf_ban.zh-cn"
	wafBanTemplateVersion  = 1
	wafBanPermission       = "nodes.manage"
	WAFBanAlertBucket      = time.Hour
	wafBanAlertEventSource = "waf"
)

// AlertEnqueuer is notification.Store's transactional enqueue.
type AlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// EnableWAFBanAlerts makes RunOnce announce folded WAF bans. Call before Run.
func (syncer *Syncer) EnableWAFBanAlerts(enqueuer AlertEnqueuer) { syncer.alerts = enqueuer }

// WAFBanSourceEventID is the merge key of one alert message.
func WAFBanSourceEventID(siteID uuid.UUID, client string, occurred time.Time) string {
	bucket := occurred.UTC().Unix() / int64(WAFBanAlertBucket/time.Second)
	return "waf-ban/" + siteID.String() + "/" + client + "/" + strconv.FormatInt(bucket, 10)
}

// alertWAFBan runs in the fold transaction under a savepoint: a failed
// notification is logged and never undoes the fold.
func (syncer *Syncer) alertWAFBan(ctx context.Context, tx pgx.Tx, event analyticslog.TemporaryBanEvent, seconds int) {
	if syncer.alerts == nil || event.EventType != wafBanAlertEventSource {
		return
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		slog.Warn("WAF ban alert not enqueued", "site_id", event.SiteID, "error", err)
		return
	}
	if err := syncer.enqueueWAFBanAlert(ctx, savepoint, event, seconds); err != nil {
		_ = savepoint.Rollback(ctx)
		slog.Warn("WAF ban alert not enqueued", "site_id", event.SiteID, "error", err)
		return
	}
	if err := savepoint.Commit(ctx); err != nil {
		slog.Warn("WAF ban alert not enqueued", "site_id", event.SiteID, "error", err)
	}
}

func (syncer *Syncer) enqueueWAFBanAlert(ctx context.Context, tx pgx.Tx, event analyticslog.TemporaryBanEvent, seconds int) error {
	siteID := uuid.MustParse(event.SiteID)
	prefix, _ := canonicalClient(event.ClientIP)
	client := clientText(prefix)
	var platform uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).
		Scan(&platform); err != nil {
		return err
	}
	var domain string
	if err := tx.QueryRow(ctx, `SELECT domain FROM sites WHERE id=$1`, siteID).Scan(&domain); err != nil {
		return err
	}
	source := WAFBanSourceEventID(siteID, client, event.OccurredAt)
	var merged bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_events WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3)`,
		platform, source, EventTypeWAFBan).Scan(&merged); err != nil || merged {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, platform, wafBanPermission)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	email := notification.TemplateContext{
		"site_domain": notification.PublicValue(domain), "client_ip": notification.PublicValue(client),
		"duration_seconds": notification.PublicValue(strconv.Itoa(seconds)),
		"occurred_at":      notification.PublicValue(event.OccurredAt.UTC().Format(time.RFC3339)),
	}
	// The SMS template leaves the time out (length); contexts match exactly.
	sms := notification.TemplateContext{}
	for key, value := range email {
		if key != "occurred_at" {
			sms[key] = value
		}
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: wafBanTemplate, Version: wafBanTemplateVersion, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: wafBanTemplate, Version: wafBanTemplateVersion, Channel: notification.ChannelEmail},
	}
	for _, recipient := range recipients {
		if _, err := syncer.alerts.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: platform, RecipientID: recipient,
			SourceEventID: source, EventType: EventTypeWAFBan, Policy: notification.DeliverySystemRequired,
			Templates: templates, AuditRequestID: source, SubjectSiteID: &siteID,
			Contexts: map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: sms, notification.ChannelEmail: email},
		}); err != nil {
			return err
		}
	}
	return nil
}
