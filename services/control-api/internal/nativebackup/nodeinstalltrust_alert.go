package nativebackup

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-btenv5: the NodeInstallTrustWatcher hooks of control-api serve. A
// republication writes a system audit event; a failure streak notifies the
// platform members holding nodes.manage through the notification center,
// once per streak (source = streak start) even across control-api restarts
// of the same streak start and replicas.
const (
	EventTypeNodeInstallTrustFailed   = notification.EventTypeNodeInstallTrustFailed
	ActionNodeInstallTrustRepublish   = "system.node_install_trust.republish"
	nodeInstallTrustFailedTemplate    = "node.install_trust.failed.zh-cn"
	nodeInstallTrustFailedPermission  = "nodes.manage"
	nodeInstallTrustFailedSource      = "node-install-trust-failed/v1/"
	nodeInstallTrustAdvisoryLockClass = 575
)

// NodeInstallTrustAlertEnqueuer is notification.Store's transactional enqueue.
type NodeInstallTrustAlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// NodeInstallTrustFailedSourceEventID is the merge key of one failure streak.
func NodeInstallTrustFailedSourceEventID(since time.Time) string {
	return nodeInstallTrustFailedSource + strconv.FormatInt(since.UTC().Unix(), 10)
}

// nodeInstallTrustFailedContexts are the SMS and email template variables.
func nodeInstallTrustFailedContexts(alert NodeInstallTrustAlert) map[notification.Channel]notification.TemplateContext {
	reason := alert.Reason
	if len(reason) > 300 {
		reason = reason[:300]
	}
	email := notification.TemplateContext{
		"download":    notification.PublicValue(downloadEndpoint(alert.Host, alert.Port)),
		"failures":    notification.PublicValue(strconv.Itoa(alert.Failures)),
		"reason":      notification.PublicValue(reason),
		"since":       notification.PublicValue(alert.Since.UTC().Format(time.RFC3339)),
		"occurred_at": notification.PublicValue(alert.At.UTC().Format(time.RFC3339)),
	}
	sms := notification.TemplateContext{"download": email["download"], "failures": email["failures"]}
	return map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: sms, notification.ChannelEmail: email}
}

func downloadEndpoint(host string, port int) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// AlertNodeInstallTrustFailed queues the failure notification in its own
// transaction. Without a platform scope (not bootstrapped) it does nothing.
func AlertNodeInstallTrustFailed(ctx context.Context, pool *pgxpool.Pool, enqueuer NodeInstallTrustAlertEnqueuer, alert NodeInstallTrustAlert) error {
	if pool == nil || enqueuer == nil {
		return nil
	}
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return enqueueNodeInstallTrustFailed(ctx, tx, enqueuer, alert)
	})
}

func platformScopeTx(ctx context.Context, tx pgx.Tx) (uuid.UUID, error) {
	var platform uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).Scan(&platform)
	return platform, err
}

func enqueueNodeInstallTrustFailed(ctx context.Context, tx pgx.Tx, enqueuer NodeInstallTrustAlertEnqueuer, alert NodeInstallTrustAlert) error {
	platform, err := platformScopeTx(ctx, tx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	source := NodeInstallTrustFailedSourceEventID(alert.Since)
	// Serialize check-then-enqueue of one streak across control-api replicas.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, $2))`, source, nodeInstallTrustAdvisoryLockClass); err != nil {
		return err
	}
	var merged bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_events WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3)`,
		platform, source, EventTypeNodeInstallTrustFailed).Scan(&merged); err != nil || merged {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, platform, nodeInstallTrustFailedPermission)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: nodeInstallTrustFailedTemplate, Version: 1, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: nodeInstallTrustFailedTemplate, Version: 1, Channel: notification.ChannelEmail},
	}
	contexts := nodeInstallTrustFailedContexts(alert)
	for _, recipient := range recipients {
		if _, err := enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: platform, RecipientID: recipient,
			SourceEventID: source, EventType: EventTypeNodeInstallTrustFailed, Policy: notification.DeliverySystemRequired,
			Templates: templates, AuditRequestID: source, Contexts: contexts,
		}); err != nil {
			return err
		}
	}
	return nil
}

// nodeInstallTrustRepublishEvent is the system audit event of a republication.
func nodeInstallTrustRepublishEvent(platform uuid.UUID, change NodeInstallTrustChange) audit.Event {
	endpoint := func(host string, port uint16, addresses []string, root string) string {
		if root != "system" {
			root = "private"
		}
		return downloadEndpoint(host, int(port)) + " → " + strings.Join(addresses, ",") + " (root " + root + ")"
	}
	after := endpoint(change.After.Host, change.After.Port, change.After.Addresses, change.After.RootCA)
	var before any
	if change.Before != nil {
		before = endpoint(change.Before.Host, change.Before.Port, change.Before.Addresses, change.Before.RootCA)
	}
	return audit.Event{ScopeID: platform, Action: ActionNodeInstallTrustRepublish, ResourceType: "node_install_trust",
		ResourceID: "upgrade-trust.json", RequestID: ActionNodeInstallTrustRepublish + "." + change.SHA256[:16], Result: "success",
		ActorKind: "system", ActorRef: "job:node_install_trust_watch",
		Payload: map[string]any{"download": after, "sha256": change.SHA256, "previous_sha256": change.PreviousSHA256},
		Changes: []audit.Change{{Field: "download", Before: before, After: after}}}
}

// AuditNodeInstallTrustRepublish writes the republication audit event.
func AuditNodeInstallTrustRepublish(ctx context.Context, pool *pgxpool.Pool, change NodeInstallTrustChange) error {
	if pool == nil {
		return nil
	}
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		platform, err := platformScopeTx(ctx, tx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, nodeInstallTrustRepublishEvent(platform, change))
		return err
	})
}
