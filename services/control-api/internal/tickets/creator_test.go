package tickets

import "testing"

// 代建归因：创建者取首条消息作者（customer 自建 / staff 代建），
// 与审计 actor 一致；工单归属客户（user_id/username）不变。
func TestWithCreatorFollowsFirstMessage(t *testing.T) {
	staffFirst := Detail{Ticket: Ticket{Username: "jason"}, Messages: []Message{
		{AuthorKind: AuthorStaff, AuthorName: "admin"}, {AuthorKind: AuthorCustomer, AuthorName: "jason"}}}
	got := withCreator(staffFirst)
	if got.Ticket.CreatorKind != AuthorStaff || got.Ticket.CreatorName != "admin" || got.Ticket.Username != "jason" {
		t.Fatalf("staff-created = %+v", got.Ticket)
	}
	customerFirst := withCreator(Detail{Messages: []Message{{AuthorKind: AuthorCustomer, AuthorName: "jason"}}})
	if customerFirst.Ticket.CreatorKind != AuthorCustomer || customerFirst.Ticket.CreatorName != "jason" {
		t.Fatalf("customer-created = %+v", customerFirst.Ticket)
	}
	// 内部备注不会是首条（创建必带公开正文）；没有消息时不猜。
	if empty := withCreator(Detail{}); empty.Ticket.CreatorKind != "" || empty.Ticket.CreatorName != "" {
		t.Fatalf("no messages = %+v", empty.Ticket)
	}
	internalFirst := withCreator(Detail{Messages: []Message{{AuthorKind: AuthorStaff, AuthorName: "x", Internal: true},
		{AuthorKind: AuthorCustomer, AuthorName: "jason"}}})
	if internalFirst.Ticket.CreatorKind != AuthorCustomer {
		t.Fatalf("internal first = %+v", internalFirst.Ticket)
	}
}
