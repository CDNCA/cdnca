package tickets

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const ticketColumns = `t.id,t.ticket_no,t.tenant_scope_id,t.user_id,owner.username,t.category,t.subject,t.priority,
	t.status,t.assignee_user_id,COALESCE(NULLIF(assignee.display_name,''),assignee.username,''),t.site_id,
	COALESCE(site.domain,''),t.order_id,t.customer_unread,t.staff_unread,t.revision,t.last_message_at,
	t.first_response_at,t.resolved_at,t.closed_at,t.created_at,t.updated_at`

const ticketFrom = ` FROM tickets t JOIN users owner ON owner.id=t.user_id
	LEFT JOIN users assignee ON assignee.id=t.assignee_user_id
	LEFT JOIN sites site ON site.id=t.site_id`

type ticketRow struct {
	ID, TenantScopeID, UserID uuid.UUID
	TicketNo                  int64
	Username, Category        string
	Subject, Priority, Status string
	AssigneeID                *uuid.UUID
	AssigneeName, SiteDomain  string
	SiteID, OrderID           *uuid.UUID
	CustomerUnread            bool
	StaffUnread               bool
	Revision                  int64
	LastMessageAt             time.Time
	FirstResponseAt           *time.Time
	ResolvedAt, ClosedAt      *time.Time
	CreatedAt, UpdatedAt      time.Time
}

func scanTicket(row pgx.Row) (ticketRow, error) {
	var value ticketRow
	err := row.Scan(&value.ID, &value.TicketNo, &value.TenantScopeID, &value.UserID, &value.Username, &value.Category,
		&value.Subject, &value.Priority, &value.Status, &value.AssigneeID, &value.AssigneeName, &value.SiteID,
		&value.SiteDomain, &value.OrderID, &value.CustomerUnread, &value.StaffUnread, &value.Revision,
		&value.LastMessageAt, &value.FirstResponseAt, &value.ResolvedAt, &value.ClosedAt, &value.CreatedAt,
		&value.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ticketRow{}, ErrNotFound
	}
	return value, err
}

func idString(value *uuid.UUID) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func utc(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	converted := value.UTC()
	return &converted
}

// slaBreached: an active ticket still waiting for the first staff reply.
func (row ticketRow) slaBreached(now time.Time) bool {
	return row.FirstResponseAt == nil && (row.Status == StatusOpen || row.Status == StatusProcessing) &&
		now.Sub(row.CreatedAt) > ResponseSLA
}

func (row ticketRow) view(staff bool, now time.Time) Ticket {
	ticket := Ticket{ID: row.ID.String(), TicketNo: row.TicketNo, Category: row.Category, Subject: row.Subject,
		Priority: row.Priority, Status: row.Status, SiteID: idString(row.SiteID), SiteDomain: row.SiteDomain,
		OrderID: idString(row.OrderID), Revision: row.Revision, LastMessageAt: row.LastMessageAt.UTC(),
		FirstResponseAt: utc(row.FirstResponseAt), ResolvedAt: utc(row.ResolvedAt), ClosedAt: utc(row.ClosedAt),
		CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}
	if staff {
		ticket.TenantScopeID, ticket.UserID, ticket.Username = row.TenantScopeID.String(), row.UserID.String(), row.Username
		ticket.AssigneeUserID, ticket.AssigneeName = idString(row.AssigneeID), row.AssigneeName
		ticket.Unread, ticket.SLABreached = row.StaffUnread, row.slaBreached(now)
		return ticket
	}
	ticket.Unread = row.CustomerUnread
	if until := row.reopenableUntil(); until != nil && now.Before(*until) {
		ticket.ReopenableUntil = until
	}
	return ticket
}

func (row ticketRow) reopenableUntil() *time.Time {
	var since *time.Time
	switch row.Status {
	case StatusResolved:
		since = row.ResolvedAt
	case StatusClosed:
		since = row.ClosedAt
	}
	if since == nil {
		return nil
	}
	until := since.UTC().Add(ReopenWindow)
	return &until
}

// loadCustomerTicket returns the caller's own ticket (404 for anyone else's).
func loadCustomerTicket(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID, lock bool) (ticketRow, error) {
	query := `SELECT ` + ticketColumns + ticketFrom + ` WHERE t.id=$1 AND t.tenant_scope_id=$2 AND t.user_id=$3 AND t.deleted_at IS NULL`
	if lock {
		query += ` FOR UPDATE OF t`
	}
	return scanTicket(tx.QueryRow(ctx, query, id, actor.ScopeID, actor.UserID))
}

// loadStaffTicket is any ticket for platform staff.
func loadStaffTicket(ctx context.Context, tx pgx.Tx, _ Actor, id uuid.UUID, lock bool) (ticketRow, error) {
	return loadTicket(ctx, tx, id, lock)
}

func loadTicket(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (ticketRow, error) {
	query := `SELECT ` + ticketColumns + ticketFrom + ` WHERE t.id=$1 AND t.deleted_at IS NULL`
	if lock {
		query += ` FOR UPDATE OF t`
	}
	return scanTicket(tx.QueryRow(ctx, query, id))
}

func parseID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != strings.ToLower(raw) {
		return uuid.Nil, ErrNotFound
	}
	return id, nil
}

func normalizePage(filter *Filter) error {
	if filter.Limit == 0 {
		filter.Limit = DefaultPageSize
	}
	if filter.Limit < 1 || filter.Limit > MaxPageSize || filter.Offset < 0 || filter.Offset > 100000 {
		return ErrInvalidInput
	}
	return nil
}

type where struct {
	clauses []string
	args    []any
}

func (w *where) add(clause string, args ...any) {
	for _, arg := range args {
		w.args = append(w.args, arg)
		clause = strings.Replace(clause, "?", "$"+strconv.Itoa(len(w.args)), 1)
	}
	w.clauses = append(w.clauses, clause)
}

func (w *where) sql() string {
	if len(w.clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.clauses, " AND ")
}

func (service *Service) filterClauses(filter Filter, actor Actor, staff bool, now time.Time) (*where, error) {
	// Deleted tickets (migration 539) are gone from every surface.
	conditions := &where{clauses: []string{"t.deleted_at IS NULL"}}
	if !staff {
		conditions.add("t.tenant_scope_id=?", actor.ScopeID)
		conditions.add("t.user_id=?", actor.UserID)
	}
	if filter.Status != "" {
		if !contains(Statuses, filter.Status) {
			return nil, ErrInvalidInput
		}
		conditions.add("t.status=?", filter.Status)
	}
	if filter.Category != "" {
		if !contains(Categories, filter.Category) {
			return nil, ErrInvalidInput
		}
		conditions.add("t.category=?", filter.Category)
	}
	if filter.Query != "" {
		query := strings.TrimSpace(filter.Query)
		if query == "" || len([]rune(query)) > 100 {
			return nil, ErrInvalidInput
		}
		if number, err := strconv.ParseInt(strings.TrimPrefix(query, "#"), 10, 64); err == nil {
			conditions.add("t.ticket_no=?", number)
		} else {
			pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query) + "%"
			if staff {
				conditions.add("(t.subject ILIKE ? OR owner.username ILIKE ?)", pattern, pattern)
			} else {
				conditions.add("t.subject ILIKE ?", pattern)
			}
		}
	}
	if !staff {
		if filter.Priority != "" || filter.AssigneeUserID != "" || filter.UserID != "" || filter.SLABreached {
			return nil, ErrInvalidInput
		}
		return conditions, nil
	}
	if filter.Priority != "" {
		if !contains(Priorities, filter.Priority) {
			return nil, ErrInvalidInput
		}
		conditions.add("t.priority=?", filter.Priority)
	}
	switch filter.AssigneeUserID {
	case "":
	case "none":
		conditions.add("t.assignee_user_id IS NULL")
	case "me":
		conditions.add("t.assignee_user_id=?", actor.UserID)
	default:
		id, err := parseID(filter.AssigneeUserID)
		if err != nil {
			return nil, ErrInvalidInput
		}
		conditions.add("t.assignee_user_id=?", id)
	}
	if filter.UserID != "" {
		id, err := parseID(filter.UserID)
		if err != nil {
			return nil, ErrInvalidInput
		}
		conditions.add("t.user_id=?", id)
	}
	if filter.SLABreached {
		conditions.add("t.first_response_at IS NULL AND t.status IN ('open','processing') AND t.created_at < ?",
			now.Add(-ResponseSLA))
	}
	return conditions, nil
}

// List is the customer's own tickets (staff=false) or the admin queue.
func (service *Service) List(ctx context.Context, actor Actor, staff bool, filter Filter) (Page, error) {
	if err := normalizePage(&filter); err != nil {
		return Page{}, err
	}
	now := service.clock()
	conditions, err := service.filterClauses(filter, actor, staff, now)
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: []Ticket{}, Limit: filter.Limit, Offset: filter.Offset}
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			if err := service.authorize(ctx, tx, actor, staff, now, PermissionRead, PermissionManage); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*)`+ticketFrom+conditions.sql(), conditions.args...).Scan(&page.Total); err != nil {
				return err
			}
			args := append(append([]any{}, conditions.args...), filter.Limit, filter.Offset)
			rows, err := tx.Query(ctx, `SELECT `+ticketColumns+ticketFrom+conditions.sql()+fmt.Sprintf(
				` ORDER BY t.last_message_at DESC, t.id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				row, err := scanTicket(rows)
				if err != nil {
					return err
				}
				page.Items = append(page.Items, row.view(staff, now))
			}
			if err := rows.Err(); err != nil {
				return err
			}
			rows.Close()
			return loadLastReplyAuthors(ctx, tx, page.Items, staff)
		})
	return page, err
}

// loadLastReplyAuthors fills LastReplyAuthor from each ticket's newest
// message the viewer can see (no event stream: the message table is the
// record). Customers never see internal notes, and a staff author shows as
// "客服 <name>", the same as in the detail view.
func loadLastReplyAuthors(ctx context.Context, tx pgx.Tx, items []Ticket, staff bool) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]string, len(items))
	index := make(map[string]int, len(items))
	for i, item := range items {
		ids[i], index[item.ID] = item.ID, i
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (message.ticket_id) message.ticket_id::text,message.author_kind,
		COALESCE(NULLIF(author.display_name,''),author.username)
		FROM ticket_messages message JOIN users author ON author.id=message.author_user_id
		WHERE message.ticket_id=ANY($1::uuid[]) AND ($2 OR NOT message.internal)
		ORDER BY message.ticket_id,message.created_at DESC,message.id DESC`, ids, staff)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, kind, name string
		if err := rows.Scan(&id, &kind, &name); err != nil {
			return err
		}
		if !staff && kind == AuthorStaff {
			name = "客服 " + name
		}
		item := &items[index[id]]
		item.LastReplyAuthor, item.LastReplyAuthorKind = name, kind
	}
	return rows.Err()
}

func (service *Service) authorize(ctx context.Context, tx pgx.Tx, actor Actor, staff bool, now time.Time,
	permissions ...string,
) error {
	if staff {
		return authStaff(ctx, tx, actor, now, permissions...)
	}
	return authCustomer(ctx, tx, actor, now)
}

// Get returns the ticket and its timeline and marks it read for the viewer.
// Customers never see internal notes or their attachments.
func (service *Service) Get(ctx context.Context, actor Actor, staff bool, rawID string) (Detail, error) {
	id, err := parseID(rawID)
	if err != nil {
		return Detail{}, err
	}
	var detail Detail
	now := service.clock()
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := service.authorize(ctx, tx, actor, staff, now, PermissionRead, PermissionManage); err != nil {
			return err
		}
		var row ticketRow
		if staff {
			row, err = loadStaffTicket(ctx, tx, actor, id, false)
		} else {
			row, err = loadCustomerTicket(ctx, tx, actor, id, false)
		}
		if err != nil {
			return err
		}
		if staff && row.StaffUnread {
			_, err = tx.Exec(ctx, `UPDATE tickets SET staff_unread=false WHERE id=$1`, id)
			row.StaffUnread = false
		} else if !staff && row.CustomerUnread {
			_, err = tx.Exec(ctx, `UPDATE tickets SET customer_unread=false WHERE id=$1`, id)
			row.CustomerUnread = false
		}
		if err != nil {
			return err
		}
		detail.Ticket = row.view(staff, now)
		detail.Messages, err = loadMessages(ctx, tx, id, staff)
		if err != nil {
			return err
		}
		detail.Events, err = loadEvents(ctx, tx, id, staff)
		return err
	})
	return detail, err
}

// loadEvents is the ticket's change timeline (migration 543). Customers do
// not see assignee changes and see staff names as "客服 <name>", like messages.
func loadEvents(ctx context.Context, tx pgx.Tx, ticketID uuid.UUID, staff bool) ([]Event, error) {
	rows, err := tx.Query(ctx, `SELECT event.id,event.kind,
		COALESCE(event.from_value,COALESCE(NULLIF(from_user.display_name,''),from_user.username),''),
		COALESCE(event.to_value,COALESCE(NULLIF(to_user.display_name,''),to_user.username),''),
		event.actor_kind,COALESCE(NULLIF(actor.display_name,''),actor.username),event.created_at
		FROM ticket_events event JOIN users actor ON actor.id=event.actor_user_id
		LEFT JOIN users from_user ON from_user.id=event.from_user_id
		LEFT JOIN users to_user ON to_user.id=event.to_user_id
		WHERE event.ticket_id=$1 AND ($2 OR event.kind<>'assignee') ORDER BY event.created_at,event.id`, ticketID, staff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var id uuid.UUID
		var event Event
		if err := rows.Scan(&id, &event.Kind, &event.From, &event.To, &event.ActorKind, &event.ActorName,
			&event.CreatedAt); err != nil {
			return nil, err
		}
		event.ID, event.CreatedAt = id.String(), event.CreatedAt.UTC()
		if !staff && event.ActorKind == AuthorStaff {
			event.ActorName = "客服 " + event.ActorName
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func loadMessages(ctx context.Context, tx pgx.Tx, ticketID uuid.UUID, staff bool) ([]Message, error) {
	rows, err := tx.Query(ctx, `SELECT message.id,message.author_kind,
		COALESCE(NULLIF(author.display_name,''),author.username),message.body,message.internal,message.created_at
		FROM ticket_messages message JOIN users author ON author.id=message.author_user_id
		WHERE message.ticket_id=$1 AND ($2 OR NOT message.internal) ORDER BY message.created_at,message.id`,
		ticketID, staff)
	if err != nil {
		return nil, err
	}
	messages := []Message{}
	index := map[uuid.UUID]int{}
	for rows.Next() {
		var id uuid.UUID
		var message Message
		if err := rows.Scan(&id, &message.AuthorKind, &message.AuthorName, &message.Body, &message.Internal,
			&message.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		message.ID, message.CreatedAt, message.Attachments = id.String(), message.CreatedAt.UTC(), []Attachment{}
		if !staff && message.AuthorKind == AuthorStaff {
			message.AuthorName = "客服 " + message.AuthorName
		}
		index[id] = len(messages)
		messages = append(messages, message)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	attachments, err := tx.Query(ctx, `SELECT id,message_id,file_name,mime_type,size_bytes,sha256,created_at
		FROM ticket_attachments WHERE ticket_id=$1 ORDER BY created_at,id`, ticketID)
	if err != nil {
		return nil, err
	}
	defer attachments.Close()
	for attachments.Next() {
		var id, messageID uuid.UUID
		var attachment Attachment
		var digest []byte
		if err := attachments.Scan(&id, &messageID, &attachment.FileName, &attachment.MIMEType, &attachment.SizeBytes,
			&digest, &attachment.CreatedAt); err != nil {
			return nil, err
		}
		position, visible := index[messageID]
		if !visible {
			continue // attachment of an internal note
		}
		attachment.ID, attachment.SHA256, attachment.CreatedAt = id.String(), hex.EncodeToString(digest), attachment.CreatedAt.UTC()
		messages[position].Attachments = append(messages[position].Attachments, attachment)
	}
	return messages, attachments.Err()
}

// Summary is the unread badge (customers) or the queue badges (staff).
func (service *Service) Summary(ctx context.Context, actor Actor, staff bool) (Summary, error) {
	var summary Summary
	now := service.clock()
	err := pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := service.authorize(ctx, tx, actor, staff, now, PermissionRead, PermissionManage); err != nil {
			return err
		}
		if !staff {
			return tx.QueryRow(ctx, `SELECT count(*) FROM tickets WHERE tenant_scope_id=$1 AND user_id=$2
				AND customer_unread AND deleted_at IS NULL`, actor.ScopeID, actor.UserID).Scan(&summary.Unread)
		}
		return tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE staff_unread AND status<>'closed'),
			count(*) FILTER (WHERE status='open'),
			count(*) FILTER (WHERE assignee_user_id=$1 AND status IN ('open','processing')),
			count(*) FILTER (WHERE first_response_at IS NULL AND status IN ('open','processing') AND created_at<$2)
			FROM tickets WHERE deleted_at IS NULL`, actor.UserID, now.Add(-ResponseSLA)).
			Scan(&summary.Unread, &summary.Pending, &summary.Mine, &summary.SLABreached)
	})
	return summary, err
}

// Assignees lists the platform members who can work tickets.
func (service *Service) Assignees(ctx context.Context, actor Actor) ([]Assignee, error) {
	result := []Assignee{}
	now := service.clock()
	err := pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authStaff(ctx, tx, actor, now, PermissionRead, PermissionManage); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT account.id,account.username,account.display_name
			FROM role_assignments assignment
			JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
			JOIN memberships membership ON membership.scope_id=assignment.scope_id
				AND membership.user_id=assignment.user_id AND membership.status='active'
			JOIN users account ON account.id=assignment.user_id AND account.status='active'
			WHERE assignment.scope_id=$1 AND grant_row.permission_name IN ($2,'platform.admin')
			ORDER BY account.username`, actor.ScopeID, PermissionManage)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var assignee Assignee
			if err := rows.Scan(&id, &assignee.Username, &assignee.DisplayName); err != nil {
				return err
			}
			assignee.UserID = id.String()
			result = append(result, assignee)
		}
		return rows.Err()
	})
	return result, err
}
