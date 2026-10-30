package installationban

import (
	"context"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Permanent refusal alert (fz-x13, migration 530): a node that refuses an
// installation ban revision for a reason the same bytes would hit again is
// never sent that revision again (deliveryDue), so it stays on its old state
// until a new revision. The platform members holding nodes.manage are told
// through the notification center, once per (node, revision).
const (
	EventTypeRejected           = notification.EventTypeInstallationBanRejected
	rejectedTemplate            = "installation_ban.rejected.zh-cn"
	rejectedTemplateVersion     = 1
	rejectedPermission          = "nodes.manage"
	rejectedSourcePrefix        = "installation-ban-rejected/v1/"
	rejectedAdvisoryLockClassID = 530
)

// AlertEnqueuer is notification.Store's transactional enqueue.
type AlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// RejectedAlert is one permanent refusal of a revision by a node.
type RejectedAlert struct {
	NodeID   uuid.UUID
	Revision uint64
	Reason   string
	At       time.Time
}

// RejectedSourceEventID is the merge key: one message per (node, revision).
func RejectedSourceEventID(nodeID uuid.UUID, revision uint64) string {
	return rejectedSourcePrefix + nodeID.String() + "/" + strconv.FormatUint(revision, 10)
}

// rejectedContexts are the template variables of the SMS and email bodies.
func rejectedContexts(alert RejectedAlert, name, address string) map[notification.Channel]notification.TemplateContext {
	email := notification.TemplateContext{
		"node_name": notification.PublicValue(name), "node_ip": notification.PublicValue(address),
		"revision":    notification.PublicValue(strconv.FormatUint(alert.Revision, 10)),
		"reason":      notification.PublicValue(alert.Reason),
		"occurred_at": notification.PublicValue(alert.At.UTC().Format(time.RFC3339)),
	}
	sms := notification.TemplateContext{"node_name": email["node_name"], "revision": email["revision"]}
	return map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: sms, notification.ChannelEmail: email}
}

// AlertRejected enqueues the alert in its own transaction; a failure is only
// logged by the caller and never blocks the receipt.
func AlertRejected(ctx context.Context, pool *pgxpool.Pool, enqueuer AlertEnqueuer, alert RejectedAlert) error {
	if pool == nil || enqueuer == nil {
		return nil
	}
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return enqueueRejected(ctx, tx, enqueuer, alert)
	})
}

func enqueueRejected(ctx context.Context, tx pgx.Tx, enqueuer AlertEnqueuer, alert RejectedAlert) error {
	var platform uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).
		Scan(&platform); err != nil {
		return err
	}
	source := RejectedSourceEventID(alert.NodeID, alert.Revision)
	// Serialize check-then-enqueue of one source across control-api replicas.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, $2))`, source, rejectedAdvisoryLockClassID); err != nil {
		return err
	}
	var merged bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_events WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3)`,
		platform, source, EventTypeRejected).Scan(&merged); err != nil || merged {
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
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, platform, rejectedPermission)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: rejectedTemplate, Version: rejectedTemplateVersion, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: rejectedTemplate, Version: rejectedTemplateVersion, Channel: notification.ChannelEmail},
	}
	contexts := rejectedContexts(alert, name, address)
	for _, recipient := range recipients {
		if _, err := enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: platform, RecipientID: recipient,
			SourceEventID: source, EventType: EventTypeRejected, Policy: notification.DeliverySystemRequired,
			Templates: templates, AuditRequestID: source, Contexts: contexts,
		}); err != nil {
			return err
		}
	}
	return nil
}
