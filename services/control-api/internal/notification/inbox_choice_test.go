package notification

import "testing"

// fix-ticket2: ticket events reach the message center of the side they are
// for, and only while the member keeps the in-app choice (546 inbox_enabled).
func TestInboxCopyFollowsScopeAndMemberChoice(t *testing.T) {
	for _, item := range []struct {
		event    string
		platform bool
		inbox    bool
		want     bool
	}{
		{"ticket.created", false, true, true},
		{"ticket.replied", false, true, true},
		{"ticket.status_changed", false, true, true},
		{"ticket.replied", false, false, false},
		{"ticket.staff.created", true, true, true},
		{"ticket.staff.replied", true, false, false},
		{"ticket.staff.overdue", true, true, true},
		{"ticket.staff.overdue", false, true, false},
		{"ticket.replied", true, true, false},
		// Non-ticket operations events keep their existing always-on copy.
		{EventTypeNodeOffline, true, false, true},
		{"security.escalate.blackhole", false, false, false},
		{"package.auto_renew.failed", false, true, false},
	} {
		if got := inboxCopy(item.platform, item.event, item.inbox); got != item.want {
			t.Errorf("inboxCopy(platform=%v, %s, inbox=%v) = %v, want %v", item.platform, item.event, item.inbox, got, item.want)
		}
	}
	if !PlatformEventType("ticket.staff.overdue") {
		t.Fatal("ticket.staff.overdue must be a platform event")
	}
}
