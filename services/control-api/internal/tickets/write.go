package tickets

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func validSubject(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxSubjectRunes {
		return "", false
	}
	return value, strings.IndexFunc(value, unicode.IsControl) < 0
}

func validBody(value string) (string, bool) {
	value = strings.TrimRight(value, " \t\r\n")
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxBodyRunes ||
		strings.ContainsRune(value, 0) {
		return "", false
	}
	return value, true
}

func parseAttachmentIDs(raw []string) ([]uuid.UUID, error) {
	if len(raw) > MaxAttachments {
		return nil, ErrInvalidInput
	}
	ids := make([]uuid.UUID, 0, len(raw))
	seen := map[uuid.UUID]bool{}
	for _, value := range raw {
		id, err := parseID(value)
		if err != nil || seen[id] {
			return nil, ErrInvalidInput
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

func optionalID(raw string) (*uuid.UUID, error) {
	if raw == "" {
		return nil, nil
	}
	id, err := parseID(raw)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return &id, nil
}

func writeKeys(key, requestID string) error {
	if !keyPattern.MatchString(key) || !keyPattern.MatchString(requestID) {
		return ErrInvalidInput
	}
	return nil
}

// bindAttachments attaches the caller's own pending uploads to a message.
func bindAttachments(ctx context.Context, tx pgx.Tx, actor Actor, ticketID, messageID uuid.UUID, ids []uuid.UUID,
	now time.Time,
) error {
	if len(ids) == 0 {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE ticket_attachments SET ticket_id=$1,message_id=$2,bound_at=$3
		WHERE id = ANY($4::uuid[]) AND owner_user_id=$5 AND owner_scope_id=$6 AND message_id IS NULL`,
		ticketID, messageID, now, ids, actor.UserID, actor.ScopeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(ids)) {
		return ErrInvalidInput
	}
	return nil
}

func insertMessage(ctx context.Context, tx pgx.Tx, ticketID, author uuid.UUID, kind, body string, internal bool,
	now time.Time,
) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ticket_messages(id,ticket_id,author_user_id,author_kind,body,internal,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, id, ticketID, author, kind, body, internal, now)
	return id, err
}

// recordChanges appends the ticket's events (migration 543) for a write that
// moved status from → to, priority and assignee; closed / reopened are the
// customer's own transitions.
func recordChanges(ctx context.Context, tx pgx.Tx, ticketID, actor uuid.UUID, actorKind string, now time.Time,
	statusKind, statusFrom, statusTo, priorityFrom, priorityTo string, assigneeFrom, assigneeTo *uuid.UUID,
) error {
	insert := func(kind string, fromValue, toValue *string, fromUser, toUser *uuid.UUID) error {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ticket_events(id,ticket_id,kind,from_value,to_value,from_user_id,to_user_id,
			actor_user_id,actor_kind,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			id, ticketID, kind, fromValue, toValue, fromUser, toUser, actor, actorKind, now)
		return err
	}
	if statusFrom != statusTo {
		if err := insert(statusKind, &statusFrom, &statusTo, nil, nil); err != nil {
			return err
		}
	}
	if priorityFrom != priorityTo {
		if err := insert(EventKindPriority, &priorityFrom, &priorityTo, nil, nil); err != nil {
			return err
		}
	}
	if idString(assigneeFrom) != idString(assigneeTo) {
		return insert(EventKindAssignee, nil, nil, assigneeFrom, assigneeTo)
	}
	return nil
}

func (service *Service) audit(ctx context.Context, tx pgx.Tx, actor Actor, action string, ticketID uuid.UUID,
	requestID string, payload map[string]any,
) error {
	return service.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
		Action: action, ResourceType: "ticket", ResourceID: ticketID.String(), RequestID: requestID, Result: "success",
		Payload: payload})
}

// Create files a ticket for the calling tenant member.
func (service *Service) Create(ctx context.Context, actor Actor, key, requestID string, input CreateInput) (Detail, error) {
	if err := writeKeys(key, requestID); err != nil {
		return Detail{}, err
	}
	subject, okSubject := validSubject(input.Subject)
	body, okBody := validBody(input.Body)
	if input.Priority == "" {
		input.Priority = "normal"
	}
	if !okSubject || !okBody || !contains(Categories, input.Category) || !contains(Priorities, input.Priority) {
		return Detail{}, ErrInvalidInput
	}
	siteID, err := optionalID(input.SiteID)
	if err != nil {
		return Detail{}, err
	}
	orderID, err := optionalID(input.OrderID)
	if err != nil {
		return Detail{}, err
	}
	attachments, err := parseAttachmentIDs(input.AttachmentIDs)
	if err != nil {
		return Detail{}, err
	}
	const operation = "ticket.create"
	digest := requestDigest(operation, input.Category, subject, body, input.Priority, siteID, orderID, attachments)
	var ticketID uuid.UUID
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		now := service.clock()
		if err := authCustomer(ctx, tx, actor, now); err != nil {
			return err
		}
		replayed, found, err := replay(ctx, tx, actor, operation, key, digest)
		if err != nil || found {
			ticketID = replayed
			return err
		}
		var related bool
		if siteID != nil {
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1 AND scope_id=$2 AND deleted_at IS NULL)`,
				*siteID, actor.ScopeID).Scan(&related); err != nil {
				return err
			}
			if !related {
				return ErrInvalidInput
			}
		}
		if orderID != nil {
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM package_orders WHERE id=$1 AND tenant_scope_id=$2)`,
				*orderID, actor.ScopeID).Scan(&related); err != nil {
				return err
			}
			if !related {
				return ErrInvalidInput
			}
		}
		if ticketID, err = uuid.NewV7(); err != nil {
			return err
		}
		var ticketNo int64
		if err := tx.QueryRow(ctx, `INSERT INTO tickets(id,tenant_scope_id,user_id,category,subject,priority,status,
			site_id,order_id,customer_unread,staff_unread,last_message_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,'open',$7,$8,false,true,$9,$9,$9) RETURNING ticket_no`,
			ticketID, actor.ScopeID, actor.UserID, input.Category, subject, input.Priority, siteID, orderID, now).
			Scan(&ticketNo); err != nil {
			return err
		}
		messageID, err := insertMessage(ctx, tx, ticketID, actor.UserID, AuthorCustomer, body, false, now)
		if err != nil {
			return err
		}
		if err := bindAttachments(ctx, tx, actor, ticketID, messageID, attachments, now); err != nil {
			return err
		}
		if err := service.audit(ctx, tx, actor, "ticket.create", ticketID, requestID, map[string]any{
			"ticket_no": ticketNo, "category": input.Category, "priority": input.Priority,
			"attachments": len(attachments), "site_linked": siteID != nil, "order_linked": orderID != nil}); err != nil {
			return err
		}
		service.notify(ctx, tx, EventCreated, notice{scopeID: actor.ScopeID, recipient: actor.UserID, ticketID: ticketID, siteID: siteID,
			ticketNo: ticketNo, subject: subject, status: StatusOpen, sourceID: ticketID.String(), actor: actor.UserID,
			requestID: requestID})
		service.notifyStaff(ctx, tx, actor.ScopeID, EventStaffCreated, notice{ticketID: ticketID, siteID: siteID, ticketNo: ticketNo, subject: subject,
			status: StatusOpen, sourceID: ticketID.String(), actor: actor.UserID, requestID: requestID,
			username: customerName(ctx, tx, actor.UserID)})
		return recordWrite(ctx, tx, actor, operation, key, digest, ticketID, now)
	})
	if err != nil {
		return Detail{}, err
	}
	return service.Get(ctx, actor, false, ticketID.String())
}

// StaffCreate opens a ticket on a user's behalf:
// the first message is the staff member's, so the ticket waits for the
// customer (pending_customer, first response recorded) and shows up unread in
// the customer's list. The customer is told as for a staff reply; the audit
// names the staff member as the actor.
func (service *Service) StaffCreate(ctx context.Context, actor Actor, key, requestID string, input StaffCreateInput) (Detail, error) {
	if err := writeKeys(key, requestID); err != nil {
		return Detail{}, err
	}
	subject, okSubject := validSubject(input.Subject)
	body, okBody := validBody(input.Body)
	if input.Priority == "" {
		input.Priority = "normal"
	}
	customer, err := parseID(input.UserID)
	if err != nil || !okSubject || !okBody || !contains(Categories, input.Category) || !contains(Priorities, input.Priority) {
		return Detail{}, ErrInvalidInput
	}
	assignee, err := optionalID(input.AssigneeUserID)
	if err != nil {
		return Detail{}, err
	}
	if assignee == nil {
		assignee = &actor.UserID
	}
	const operation = "ticket.staff_create"
	digest := requestDigest(operation, customer, input.Category, subject, body, input.Priority, assignee)
	var ticketID uuid.UUID
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		now := service.clock()
		if err := authStaff(ctx, tx, actor, now, PermissionManage); err != nil {
			return err
		}
		replayed, found, err := replay(ctx, tx, actor, operation, key, digest)
		if err != nil || found {
			ticketID = replayed
			return err
		}
		if err := requireAssignable(ctx, tx, actor.ScopeID, *assignee); err != nil {
			return err
		}
		// The user's one active tenant membership is the ticket's owner scope.
		scopes, err := tx.Query(ctx, `SELECT membership.scope_id FROM memberships membership
			JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='tenant' AND scope.tenant_id IS NOT NULL
			JOIN users account ON account.id=membership.user_id AND account.status='active'
			WHERE membership.user_id=$1 AND membership.status='active' ORDER BY membership.scope_id LIMIT 2`, customer)
		if err != nil {
			return err
		}
		var owners []uuid.UUID
		for scopes.Next() {
			var scope uuid.UUID
			if err := scopes.Scan(&scope); err != nil {
				scopes.Close()
				return err
			}
			owners = append(owners, scope)
		}
		scopes.Close()
		if err := scopes.Err(); err != nil {
			return err
		}
		if len(owners) != 1 {
			return ErrInvalidInput
		}
		if ticketID, err = uuid.NewV7(); err != nil {
			return err
		}
		var ticketNo int64
		if err := tx.QueryRow(ctx, `INSERT INTO tickets(id,tenant_scope_id,user_id,category,subject,priority,status,
			assignee_user_id,customer_unread,staff_unread,last_message_at,first_response_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,'pending_customer',$7,true,false,$8,$8,$8,$8) RETURNING ticket_no`,
			ticketID, owners[0], customer, input.Category, subject, input.Priority, *assignee, now).Scan(&ticketNo); err != nil {
			return err
		}
		messageID, err := insertMessage(ctx, tx, ticketID, actor.UserID, AuthorStaff, body, false, now)
		if err != nil {
			return err
		}
		if err := service.audit(ctx, tx, actor, "ticket.staff_create", ticketID, requestID, map[string]any{
			"ticket_no": ticketNo, "category": input.Category, "priority": input.Priority,
			"customer_scope_id": owners[0].String(), "customer_user_id": customer.String(),
			"assignee": assignee.String()}); err != nil {
			return err
		}
		service.notify(ctx, tx, EventReplied, notice{scopeID: owners[0], recipient: customer, ticketID: ticketID,
			ticketNo: ticketNo, subject: subject, status: StatusPendingCustomer, sourceID: messageID.String(),
			actor: actor.UserID, requestID: requestID})
		return recordWrite(ctx, tx, actor, operation, key, digest, ticketID, now)
	})
	if err != nil {
		return Detail{}, err
	}
	return service.Get(ctx, actor, true, ticketID.String())
}

// Reply adds a message. Customers reply to their own active tickets (a
// resolved or closed ticket must be reopened first); staff reply to any
// ticket that is not closed, or record an internal note on any ticket.
func (service *Service) Reply(ctx context.Context, actor Actor, staff bool, key, requestID, rawID string,
	input ReplyInput,
) (Detail, error) {
	id, err := parseID(rawID)
	if err != nil {
		return Detail{}, err
	}
	if err := writeKeys(key, requestID); err != nil {
		return Detail{}, err
	}
	body, ok := validBody(input.Body)
	if !ok || (input.Internal && !staff) {
		return Detail{}, ErrInvalidInput
	}
	attachments, err := parseAttachmentIDs(input.AttachmentIDs)
	if err != nil {
		return Detail{}, err
	}
	operation := "ticket.reply"
	if staff {
		operation = "ticket.staff_reply"
	}
	digest := requestDigest(operation, id, body, input.Internal, attachments)
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		now := service.clock()
		if err := service.authorize(ctx, tx, actor, staff, now, PermissionManage); err != nil {
			return err
		}
		if _, found, err := replay(ctx, tx, actor, operation, key, digest); err != nil || found {
			return err
		}
		var row ticketRow
		if staff {
			row, err = loadStaffTicket(ctx, tx, actor, id, true)
		} else {
			row, err = loadCustomerTicket(ctx, tx, actor, id, true)
		}
		if err != nil {
			return err
		}
		switch {
		case staff && input.Internal:
		case staff && row.Status == StatusClosed:
			return ErrInvalidState
		case !staff && (row.Status == StatusResolved || row.Status == StatusClosed):
			return ErrInvalidState
		}
		kind := AuthorCustomer
		if staff {
			kind = AuthorStaff
		}
		messageID, err := insertMessage(ctx, tx, id, actor.UserID, kind, body, input.Internal, now)
		if err != nil {
			return err
		}
		if err := bindAttachments(ctx, tx, actor, id, messageID, attachments, now); err != nil {
			return err
		}
		action := "ticket.reply"
		// status is the ticket's state after this write; notices below render
		// it, not the pre-update row.Status (p1-tickets TKT-02).
		status := row.Status
		switch {
		case input.Internal:
			action = "ticket.note"
			_, err = tx.Exec(ctx, `UPDATE tickets SET revision=revision+1,updated_at=$2 WHERE id=$1`, id, now)
		case staff:
			// A staff answer waits for the customer; an unassigned ticket is
			// claimed by whoever answers it.
			status = replyStatus(row.Status, true, row.AssigneeID != nil)
			claim := &actor.UserID
			_, err = tx.Exec(ctx, `UPDATE tickets SET status=$2,customer_unread=true,last_message_at=$3,
				first_response_at=COALESCE(first_response_at,$3),assignee_user_id=COALESCE(assignee_user_id,$4),
				revision=revision+1,updated_at=$3 WHERE id=$1`, id, status, now, claim)
			if err == nil {
				assignee := row.AssigneeID
				if assignee == nil {
					assignee = claim
				}
				err = recordChanges(ctx, tx, id, actor.UserID, AuthorStaff, now, EventKindStatus, row.Status, status,
					row.Priority, row.Priority, row.AssigneeID, assignee)
			}
		default:
			status = replyStatus(row.Status, false, row.AssigneeID != nil)
			_, err = tx.Exec(ctx, `UPDATE tickets SET status=$2,staff_unread=true,last_message_at=$3,
				revision=revision+1,updated_at=$3 WHERE id=$1`, id, status, now)
			if err == nil {
				err = recordChanges(ctx, tx, id, actor.UserID, AuthorCustomer, now, EventKindStatus, row.Status, status,
					row.Priority, row.Priority, row.AssigneeID, row.AssigneeID)
			}
		}
		if err != nil {
			return err
		}
		payload := map[string]any{"ticket_no": row.TicketNo, "message_id": messageID.String(), "attachments": len(attachments)}
		if err := service.audit(ctx, tx, actor, action, id, requestID, payload); err != nil {
			return err
		}
		if staff && !input.Internal {
			service.notify(ctx, tx, EventReplied, notice{scopeID: row.TenantScopeID, recipient: row.UserID, ticketID: id, siteID: row.SiteID,
				ticketNo: row.TicketNo, subject: row.Subject, status: status, sourceID: messageID.String(),
				actor: actor.UserID, requestID: requestID})
		}
		if !staff {
			service.notifyStaff(ctx, tx, row.TenantScopeID, EventStaffReplied, notice{ticketID: id, siteID: row.SiteID, ticketNo: row.TicketNo, subject: row.Subject,
				status: status, sourceID: messageID.String(), actor: actor.UserID, requestID: requestID,
				username: row.Username})
		}
		return recordWrite(ctx, tx, actor, operation, key, digest, id, now)
	})
	if err != nil {
		return Detail{}, err
	}
	return service.Get(ctx, actor, staff, id.String())
}

// replyStatus is the status a public reply moves the ticket to: a staff answer
// waits for the customer; a customer answer to a waiting ticket goes back to
// the queue (processing when someone already holds it).
func replyStatus(current string, staff, assigned bool) string {
	switch {
	case staff && (current == StatusOpen || current == StatusProcessing):
		return StatusPendingCustomer
	case !staff && current == StatusPendingCustomer && assigned:
		return StatusProcessing
	case !staff && current == StatusPendingCustomer:
		return StatusOpen
	}
	return current
}

// Close is the customer closing their own ticket (idempotent).
func (service *Service) Close(ctx context.Context, actor Actor, requestID, rawID string) (Detail, error) {
	return service.customerTransition(ctx, actor, requestID, rawID, false)
}

// Reopen brings back a resolved or closed ticket within ReopenWindow.
func (service *Service) Reopen(ctx context.Context, actor Actor, requestID, rawID string) (Detail, error) {
	return service.customerTransition(ctx, actor, requestID, rawID, true)
}

func (service *Service) customerTransition(ctx context.Context, actor Actor, requestID, rawID string, reopen bool) (Detail, error) {
	id, err := parseID(rawID)
	if err != nil {
		return Detail{}, err
	}
	if !keyPattern.MatchString(requestID) {
		return Detail{}, ErrInvalidInput
	}
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		now := service.clock()
		if err := authCustomer(ctx, tx, actor, now); err != nil {
			return err
		}
		row, err := loadCustomerTicket(ctx, tx, actor, id, true)
		if err != nil {
			return err
		}
		from, action := row.Status, "ticket.close"
		if reopen {
			action = "ticket.reopen"
			until := row.reopenableUntil()
			if until == nil {
				return ErrInvalidState
			}
			if !now.Before(*until) {
				return ErrReopenExpired
			}
			status := StatusOpen
			if row.AssigneeID != nil {
				status = StatusProcessing
			}
			_, err = tx.Exec(ctx, `UPDATE tickets SET status=$2,resolved_at=NULL,closed_at=NULL,staff_unread=true,
				revision=revision+1,updated_at=$3 WHERE id=$1`, id, status, now)
			if err == nil {
				err = recordChanges(ctx, tx, id, actor.UserID, AuthorCustomer, now, EventKindReopened, row.Status, status,
					row.Priority, row.Priority, row.AssigneeID, row.AssigneeID)
			}
		} else {
			if row.Status == StatusClosed {
				return nil
			}
			_, err = tx.Exec(ctx, `UPDATE tickets SET status='closed',resolved_at=NULL,closed_at=$2,staff_unread=true,
				revision=revision+1,updated_at=$2 WHERE id=$1`, id, now)
			if err == nil {
				err = recordChanges(ctx, tx, id, actor.UserID, AuthorCustomer, now, EventKindClosed, row.Status, StatusClosed,
					row.Priority, row.Priority, row.AssigneeID, row.AssigneeID)
			}
		}
		if err != nil {
			return err
		}
		return service.audit(ctx, tx, actor, action, id, requestID, map[string]any{"ticket_no": row.TicketNo,
			"from": from})
	})
	if err != nil {
		return Detail{}, err
	}
	return service.Get(ctx, actor, false, id.String())
}

// Update is the staff change of status, priority and assignee.
func (service *Service) Update(ctx context.Context, actor Actor, requestID, rawID string, input UpdateInput) (Detail, error) {
	id, err := parseID(rawID)
	if err != nil {
		return Detail{}, err
	}
	if !keyPattern.MatchString(requestID) || input.ExpectedRevision < 1 ||
		(input.Status == nil && input.Priority == nil && input.AssigneeUserID == nil) ||
		(input.Status != nil && !contains(Statuses, *input.Status)) ||
		(input.Priority != nil && !contains(Priorities, *input.Priority)) {
		return Detail{}, ErrInvalidInput
	}
	var assignee *uuid.UUID
	if input.AssigneeUserID != nil && *input.AssigneeUserID != "" {
		if assignee, err = optionalID(*input.AssigneeUserID); err != nil {
			return Detail{}, err
		}
	}
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		now := service.clock()
		if err := authStaff(ctx, tx, actor, now, PermissionManage); err != nil {
			return err
		}
		row, err := loadTicket(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if row.Revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		status, priority, assigned := row.Status, row.Priority, row.AssigneeID
		if input.Priority != nil {
			priority = *input.Priority
		}
		if input.AssigneeUserID != nil {
			assigned = assignee
			if assignee != nil {
				if err := requireAssignable(ctx, tx, actor.ScopeID, *assignee); err != nil {
					return err
				}
				if status == StatusOpen && input.Status == nil {
					status = StatusProcessing // claiming starts the work
				}
			}
		}
		if input.Status != nil {
			status = *input.Status
		}
		if status == row.Status && priority == row.Priority && idString(assigned) == idString(row.AssigneeID) {
			return nil
		}
		resolvedAt, closedAt := row.ResolvedAt, row.ClosedAt
		if status != row.Status {
			resolvedAt, closedAt = nil, nil
			switch status {
			case StatusResolved:
				resolvedAt = &now
			case StatusClosed:
				closedAt = &now
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE tickets SET status=$2,priority=$3,assignee_user_id=$4,resolved_at=$5,
			closed_at=$6,customer_unread=customer_unread OR $7,revision=revision+1,updated_at=$8 WHERE id=$1`,
			id, status, priority, assigned, resolvedAt, closedAt, input.Status != nil && status != row.Status, now); err != nil {
			return err
		}
		if err := recordChanges(ctx, tx, id, actor.UserID, AuthorStaff, now, EventKindStatus, row.Status, status,
			row.Priority, priority, row.AssigneeID, assigned); err != nil {
			return err
		}
		if err := service.audit(ctx, tx, actor, "ticket.update", id, requestID, map[string]any{
			"ticket_no": row.TicketNo, "status_from": row.Status, "status_to": status,
			"priority_from": row.Priority, "priority_to": priority,
			"assignee_from": idString(row.AssigneeID), "assignee_to": idString(assigned)}); err != nil {
			return err
		}
		// Only an explicit status change is announced; claiming is internal.
		if input.Status != nil && status != row.Status {
			service.notify(ctx, tx, EventStatusChanged, notice{scopeID: row.TenantScopeID, recipient: row.UserID,
				ticketID: id, siteID: row.SiteID, ticketNo: row.TicketNo, subject: row.Subject, status: status,
				sourceID: id.String() + ":" + status + ":" + now.Format(time.RFC3339Nano), actor: actor.UserID,
				requestID: requestID})
		}
		return nil
	})
	if err != nil {
		return Detail{}, err
	}
	return service.Get(ctx, actor, true, id.String())
}

// Delete is the staff soft delete (migration 539): the ticket disappears from
// every surface; its messages and bound attachments stay in the database
// (314 never deletes bound attachments). Deleting again is ErrNotFound.
func (service *Service) Delete(ctx context.Context, actor Actor, requestID, rawID string) error {
	id, err := parseID(rawID)
	if err != nil {
		return err
	}
	if !keyPattern.MatchString(requestID) {
		return ErrInvalidInput
	}
	return pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		now := service.clock()
		if err := authStaff(ctx, tx, actor, now, PermissionManage); err != nil {
			return err
		}
		row, err := loadTicket(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tickets SET deleted_at=$2,deleted_by_user_id=$3,updated_at=$2 WHERE id=$1`,
			id, now, actor.UserID); err != nil {
			return err
		}
		return service.audit(ctx, tx, actor, "ticket.delete", id, requestID, map[string]any{
			"ticket_no": row.TicketNo, "status": row.Status, "customer_scope_id": row.TenantScopeID.String()})
	})
}

func requireAssignable(ctx context.Context, tx pgx.Tx, platformScope, userID uuid.UUID) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_assignments assignment
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
		JOIN memberships membership ON membership.scope_id=assignment.scope_id
			AND membership.user_id=assignment.user_id AND membership.status='active'
		JOIN users account ON account.id=assignment.user_id AND account.status='active'
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		AND grant_row.permission_name IN ($3,'platform.admin'))`, platformScope, userID, PermissionManage).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrInvalidInput
	}
	return nil
}

func customerName(ctx context.Context, tx pgx.Tx, userID uuid.UUID) string {
	var name string
	if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, userID).Scan(&name); err != nil {
		return ""
	}
	return name
}
