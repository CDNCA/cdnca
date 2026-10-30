//go:build integration

package tickets

import (
	"testing"
	"time"
)

// fix-decide1027b 第6项：工单状态/优先级/处理人变更与关闭、重新打开记入 ticket_events（迁移 543），
// 详情按时间返回；客户看不到处理人变更，客服的名字带"客服 "前缀。
func TestTicketEventsTimeline(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	ticket := f.create(t, f.customer, "events-1", CreateInput{})
	id := ticket.Ticket.ID
	if len(ticket.Events) != 0 {
		t.Fatalf("new ticket events = %+v", ticket.Events)
	}
	f.clock.Advance(time.Second)
	claimed, err := f.service.Update(ctx, f.manager, "r1", id, UpdateInput{ExpectedRevision: ticket.Ticket.Revision,
		AssigneeUserID: ptr(f.manager.UserID.String()), Priority: ptr("urgent")})
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Second)
	resolved, err := f.service.Update(ctx, f.manager, "r2", id, UpdateInput{ExpectedRevision: claimed.Ticket.Revision,
		Status: ptr(StatusResolved)})
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Second)
	if _, err := f.service.Reopen(ctx, f.customer, "r3", id); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Second)
	if _, err := f.service.Close(ctx, f.customer, "r4", id); err != nil {
		t.Fatal(err)
	}
	_ = resolved

	staff, err := f.service.Get(ctx, f.manager, true, id)
	if err != nil {
		t.Fatal(err)
	}
	type line struct{ kind, from, to, actorKind string }
	got := make([]line, len(staff.Events))
	for index, event := range staff.Events {
		got[index] = line{event.Kind, event.From, event.To, event.ActorKind}
	}
	want := []line{
		{EventKindStatus, StatusOpen, StatusProcessing, AuthorStaff},
		{EventKindPriority, "normal", "urgent", AuthorStaff},
		{EventKindAssignee, "", "staff-manager", AuthorStaff},
		{EventKindStatus, StatusProcessing, StatusResolved, AuthorStaff},
		{EventKindReopened, StatusResolved, StatusProcessing, AuthorCustomer},
		{EventKindClosed, StatusProcessing, StatusClosed, AuthorCustomer},
	}
	if len(got) != len(want) {
		t.Fatalf("staff events = %+v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("staff event %d = %+v want %+v (all %+v)", index, got[index], want[index], got)
		}
	}
	if staff.Events[0].ActorName != "staff-manager" || staff.Events[4].ActorName != "customer" ||
		staff.Events[0].CreatedAt.After(staff.Events[3].CreatedAt) {
		t.Fatalf("staff event actors/time = %+v", staff.Events)
	}

	customer, err := f.service.Get(ctx, f.customer, false, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(customer.Events) != 5 {
		t.Fatalf("customer events = %+v", customer.Events)
	}
	for _, event := range customer.Events {
		if event.Kind == EventKindAssignee {
			t.Fatal("customer sees an assignee change")
		}
	}
	if customer.Events[0].ActorName != "客服 staff-manager" {
		t.Fatalf("customer sees staff as %q", customer.Events[0].ActorName)
	}

	// 回复引起的状态变化（客服答复→待用户回复）同样记一行。
	second := f.create(t, f.customer, "events-2", CreateInput{})
	replied, err := f.service.Reply(ctx, f.manager, true, "events-2-reply", "r5", second.Ticket.ID, ReplyInput{Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, event := range replied.Events {
		kinds[event.Kind] = event.To
	}
	if kinds[EventKindStatus] != StatusPendingCustomer || kinds[EventKindAssignee] != "staff-manager" {
		t.Fatalf("reply events = %+v", replied.Events)
	}
}
