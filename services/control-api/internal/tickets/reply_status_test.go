package tickets

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/pgxscript"
	"github.com/google/uuid"
)

// p1-tickets TKT-02: a reply notice renders the status the reply moved the
// ticket to, not the one it had before.
func TestReplyNoticeRendersUpdatedStatus(t *testing.T) {
	cases := []struct {
		name            string
		current         string
		staff, assigned bool
		want, wantLabel string
	}{
		{"staff answers open", StatusOpen, true, false, StatusPendingCustomer, "待用户回复"},
		{"staff answers processing", StatusProcessing, true, true, StatusPendingCustomer, "待用户回复"},
		{"staff answers waiting", StatusPendingCustomer, true, true, StatusPendingCustomer, "待用户回复"},
		{"customer answers unassigned", StatusPendingCustomer, false, false, StatusOpen, "待处理"},
		{"customer answers assigned", StatusPendingCustomer, false, true, StatusProcessing, "处理中"},
		{"customer adds to open", StatusOpen, false, false, StatusOpen, "待处理"},
	}
	ref := notification.TemplateRef{ID: "ticket_replied", Version: 1, Channel: notification.ChannelEmail}
	var catalog notification.Catalog
	if err := catalog.Register(notification.TemplateDefinition{Ref: ref, Subject: "工单 #{{.ticket_no}} {{.status}}",
		Body: "当前状态：{{.status_label}}", Variables: []string{"ticket_no", "status", "status_label"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := replyStatus(tc.current, tc.staff, tc.assigned)
			if status != tc.want {
				t.Fatalf("replyStatus(%s, staff=%v, assigned=%v) = %s, want %s", tc.current, tc.staff, tc.assigned, status, tc.want)
			}
			enqueuer := &pgxscript.Enqueuer{}
			service := &Service{notifier: enqueuer, logf: t.Logf}
			tx := pgxscript.New(pgxscript.Step{Match: "FROM notification_templates",
				Rows: [][]any{{int64(1), "email", []string{"ticket_no", "status", "status_label"}}}})
			service.notify(context.Background(), tx, EventReplied, notice{scopeID: uuid.New(), recipient: uuid.New(),
				ticketNo: 10001, status: status, sourceID: "m1", requestID: "r"})
			if len(enqueuer.Requests) != 1 {
				t.Fatalf("enqueued %d notices, want 1", len(enqueuer.Requests))
			}
			message, err := catalog.Render(ref, enqueuer.Requests[0].Contexts[notification.ChannelEmail])
			if err != nil {
				t.Fatal(err)
			}
			if message.Subject != "工单 #10001 "+tc.want || message.Body != "当前状态："+tc.wantLabel {
				t.Fatalf("rendered %q / %q, want status %s (%s)", message.Subject, message.Body, tc.want, tc.wantLabel)
			}
		})
	}
}
