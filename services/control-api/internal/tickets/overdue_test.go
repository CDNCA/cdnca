package tickets

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pgxscript"
	"github.com/google/uuid"
)

// fix-ticket2 ②: a ticket past the first-response SLA is marked reminded and
// every ticket staff member gets ticket.staff.overdue once, as a system event
// (no acting user).
func TestRemindOneOverdueMarksAndNotifiesStaff(t *testing.T) {
	ticket, scope, customer := uuid.New(), uuid.New(), uuid.New()
	staffScope, staffA, staffB := uuid.New(), uuid.New(), uuid.New()
	templates := pgxscript.Step{Match: "FROM notification_templates", Rows: [][]any{{int64(1), "email", []string{"ticket_no", "username"}}}}
	tx := pgxscript.New(
		pgxscript.Step{Match: "t.sla_reminded_at IS NULL", Rows: [][]any{{ticket, scope, customer, int64(10050), "退款", StatusOpen, nil, "lily"}}},
		pgxscript.Step{Match: "FROM access_scopes scope", Rows: [][]any{{staffScope, staffA}, {staffScope, staffB}}},
		templates, templates,
	)
	enqueuer := &pgxscript.Enqueuer{}
	service := &Service{notifier: enqueuer, logf: t.Logf}
	done, err := service.remindOneOverdue(context.Background(), tx, time.Now())
	if err != nil || !done {
		t.Fatalf("remind = %v, %v", done, err)
	}
	if len(tx.Execs) == 0 || !strings.Contains(tx.Execs[0], "SET sla_reminded_at") {
		t.Fatalf("execs = %v", tx.Execs)
	}
	if len(enqueuer.Requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(enqueuer.Requests))
	}
	for _, request := range enqueuer.Requests {
		if request.EventType != EventStaffOverdue || request.ScopeID != staffScope || request.ActorUserID != nil ||
			request.SourceEventID != ticket.String()+":overdue" || request.AuditRequestID != overdueRequestID {
			t.Fatalf("request = %+v", request)
		}
	}
	empty := pgxscript.New(pgxscript.Step{Match: "t.sla_reminded_at IS NULL", NoRows: true})
	if done, err := service.remindOneOverdue(context.Background(), empty, time.Now()); err != nil || done {
		t.Fatalf("nothing left = %v, %v", done, err)
	}
}
