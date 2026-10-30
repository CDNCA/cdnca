//go:build integration

package tickets

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
)

// TestStaffCreateTicket (fix-ticket2 ①): staff open a ticket for a user; the
// customer sees it unread and can reply; the audit names the staff member;
// the customer is told as for a staff reply, by email and in the message
// center.
func TestStaffCreateTicket(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.subscribe(t, f.customer, EventReplied)
	input := StaffCreateInput{UserID: f.customer.UserID.String(), Category: "billing", Priority: "high",
		Subject: "关于本月账单", Body: "您好，本月账单有一笔调整，请查看。"}
	if _, err := f.service.StaffCreate(ctx, f.reader, "sc-1", "req-sc-1", input); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("reader staff create = %v", err)
	}
	detail, err := f.service.StaffCreate(ctx, f.manager, "sc-1", "req-sc-1", input)
	if err != nil {
		t.Fatal(err)
	}
	ticket := detail.Ticket
	if ticket.Status != StatusPendingCustomer || ticket.AssigneeUserID != f.manager.UserID.String() ||
		ticket.TenantScopeID != f.customer.ScopeID.String() || len(detail.Messages) != 1 ||
		detail.Messages[0].AuthorKind != AuthorStaff || ticket.FirstResponseAt == nil {
		t.Fatalf("staff created ticket = %+v", detail)
	}
	if again, err := f.service.StaffCreate(ctx, f.manager, "sc-1", "req-sc-1", input); err != nil || again.Ticket.ID != ticket.ID {
		t.Fatalf("replay = %+v, %v", again.Ticket, err)
	}
	page, err := f.service.List(ctx, f.customer, false, Filter{})
	if err != nil || page.Total != 1 || !page.Items[0].Unread {
		t.Fatalf("customer list = %+v, %v", page, err)
	}
	if _, err := f.service.Reply(ctx, f.customer, false, "sc-r", "req-sc-r", ticket.ID, ReplyInput{Body: "收到"}); err != nil {
		t.Fatalf("customer reply = %v", err)
	}
	if events, deliveries := f.outbox(t, f.customer, EventReplied); events != 1 || deliveries != 1 {
		t.Fatalf("customer notice = %d events, %d deliveries", events, deliveries)
	}
	var inbox, audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM admin_inbox_messages WHERE recipient_user_id=$1 AND event_type=$2`,
		f.customer.UserID, EventReplied).Scan(&inbox); err != nil || inbox != 1 {
		t.Fatalf("customer inbox = %d, %v", inbox, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='ticket.staff_create' AND resource_id=$1
		AND actor_user_id=$2 AND scope_id=$3`, ticket.ID, f.manager.UserID, f.manager.ScopeID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("staff create audit = %d, %v", audited, err)
	}
	// A platform member is no ticket owner.
	if _, err := f.service.StaffCreate(ctx, f.manager, "sc-2", "req-sc-2", StaffCreateInput{UserID: f.reader.UserID.String(),
		Category: "other", Subject: "x", Body: "y"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("platform target = %v", err)
	}
}

// TestTicketInboxChoiceAndOverdue (fix-ticket2 ②): a customer who turns the
// in-app choice off gets no message-center copy; an unanswered ticket past
// the SLA is reminded to staff exactly once.
func TestTicketInboxChoiceAndOverdue(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	control, err := notificationcontrol.NewStore(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	actor := notificationcontrol.Actor{UserID: f.customer.UserID, ScopeID: f.customer.ScopeID, SessionID: f.customer.SessionID, ScopeKind: "tenant"}
	if _, err := control.UpdateSubscription(ctx, actor, EventCreated, notificationcontrol.UpdateSubscriptionRequest{
		EmailEnabled: true, InboxEnabled: &off, RequestID: "inbox-off"}); err != nil {
		t.Fatal(err)
	}
	created := f.create(t, f.customer, "ov-1", CreateInput{})
	var inbox int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM admin_inbox_messages WHERE recipient_user_id=$1 AND event_type=$2`,
		f.customer.UserID, EventCreated).Scan(&inbox); err != nil || inbox != 0 {
		t.Fatalf("inbox after opting out = %d, %v", inbox, err)
	}
	if sent, err := f.service.RemindOverdue(ctx, 10); err != nil || sent != 0 {
		t.Fatalf("early reminder = %d, %v", sent, err)
	}
	f.clock.Advance(ResponseSLA + time.Minute)
	if sent, err := f.service.RemindOverdue(ctx, 10); err != nil || sent != 1 {
		t.Fatalf("reminder = %d, %v", sent, err)
	}
	if sent, err := f.service.RemindOverdue(ctx, 10); err != nil || sent != 0 {
		t.Fatalf("second reminder = %d, %v", sent, err)
	}
	if events, _ := f.outbox(t, f.manager, EventStaffOverdue); events != 1 {
		t.Fatalf("staff overdue events = %d for ticket %s", events, created.Ticket.ID)
	}
}
