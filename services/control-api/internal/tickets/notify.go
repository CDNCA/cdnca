package tickets

import (
	"context"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type notice struct {
	scopeID, recipient, ticketID, actor uuid.UUID
	// siteID is the ticket's linked site, read in the same transaction as the
	// event (notification_events.subject_site_id, 502); nil when none.
	siteID                    *uuid.UUID
	ticketNo                  int64
	subject, status, sourceID string
	username                  string
	requestID                 string
}

// notify enqueues a customer notification for the event under the existing
// event policy, channel switches and the customer's own subscription. It runs
// in a savepoint and never fails the ticket write: a broken template is
// logged, not allowed to block support work.
func (service *Service) notify(ctx context.Context, tx pgx.Tx, eventType string, value notice) {
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		service.logf("ticket notification %s savepoint: %v", eventType, err)
		return
	}
	defer func() { _ = savepoint.Rollback(context.WithoutCancel(ctx)) }()
	templates, contexts, err := activeTemplates(ctx, savepoint, strings.ReplaceAll(eventType, ".", "_"), map[string]string{
		"ticket_no": strconv.FormatInt(value.ticketNo, 10), "subject": value.subject,
		"status": value.status, "status_label": statusLabels[value.status], "username": value.username,
	})
	if err == nil {
		// The overdue reminder job has no acting user.
		var actor *uuid.UUID
		if value.actor != uuid.Nil {
			actor = &value.actor
		}
		_, err = service.notifier.EnqueueTx(ctx, savepoint, notification.EnqueueRequest{
			ScopeID: value.scopeID, RecipientID: value.recipient, SourceEventID: value.sourceID, EventType: eventType,
			Policy: notification.DeliveryTenantSubscribed, Templates: templates, Contexts: contexts,
			ActorUserID: actor, AuditRequestID: value.requestID, SubjectSiteID: value.siteID,
		})
	}
	if err == nil {
		err = savepoint.Commit(ctx)
	}
	if err != nil {
		service.logf("ticket notification %s for ticket %s not enqueued: %v", eventType, value.ticketID, err)
	}
}

// activeTemplates picks the newest version of each channel's template and
// fills exactly the variables that version declares (unknown ones render
// empty), so an operator editing a template cannot break enqueueing.
func activeTemplates(ctx context.Context, tx pgx.Tx, templateID string, values map[string]string) (
	map[notification.Channel]notification.TemplateRef, map[notification.Channel]notification.TemplateContext, error,
) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (channel) version,channel,variables FROM notification_templates
		WHERE template_id=$1 ORDER BY channel,version DESC`, templateID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	templates := map[notification.Channel]notification.TemplateRef{}
	contexts := map[notification.Channel]notification.TemplateContext{}
	for rows.Next() {
		var version int64
		var channel string
		var variables []string
		if err := rows.Scan(&version, &channel, &variables); err != nil {
			return nil, nil, err
		}
		ref := notification.TemplateRef{ID: templateID, Version: uint64(version), Channel: notification.Channel(channel)}
		context := notification.TemplateContext{}
		for _, name := range variables {
			context[name] = notification.PublicValue(values[name])
		}
		templates[ref.Channel], contexts[ref.Channel] = ref, context
	}
	return templates, contexts, rows.Err()
}

// notifyStaff tells every active platform member holding tickets.manage (or
// platform.admin) about a customer action, each under their own subscription.
func (service *Service) notifyStaff(ctx context.Context, tx pgx.Tx, customerScopeID uuid.UUID, eventType string, value notice) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.scope_id, membership.user_id
		FROM access_scopes scope
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.status='active'
		JOIN users account ON account.id=membership.user_id AND account.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
		WHERE scope.kind='platform' AND scope.tenant_id IS NULL AND grant_row.permission_name IN ($1,'platform.admin')
		ORDER BY membership.scope_id, membership.user_id`, PermissionManage)
	if err != nil {
		service.logf("ticket staff notification %s recipients: %v", eventType, err)
		return
	}
	type recipient struct{ scope, user uuid.UUID }
	var recipients []recipient
	for rows.Next() {
		var item recipient
		if err := rows.Scan(&item.scope, &item.user); err != nil {
			rows.Close()
			service.logf("ticket staff notification %s recipients: %v", eventType, err)
			return
		}
		recipients = append(recipients, item)
	}
	rows.Close()
	for _, item := range recipients {
		staff := value
		staff.scopeID, staff.recipient = item.scope, item.user
		service.notify(ctx, tx, eventType, staff)
	}
}
