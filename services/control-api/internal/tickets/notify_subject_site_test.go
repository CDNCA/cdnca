package tickets

import (
	"context"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/pgxscript"
	"github.com/google/uuid"
)

// evt-site: ticket notices carry the ticket's linked site; a ticket without
// one stays without a subject site.
func TestTicketNoticesRecordSubjectSite(t *testing.T) {
	site, scope, customer := uuid.New(), uuid.New(), uuid.New()
	staffScope, staff := uuid.New(), uuid.New()
	templates := pgxscript.Step{Match: "FROM notification_templates", Rows: [][]any{{int64(1), "email", []string{"ticket_no"}}}}
	enqueuer := &pgxscript.Enqueuer{}
	service := &Service{notifier: enqueuer, logf: t.Logf}
	tx := pgxscript.New(templates, templates, templates,
		pgxscript.Step{Match: "FROM access_scopes scope", Rows: [][]any{{staffScope, staff}}})
	ctx := context.Background()
	service.notify(ctx, tx, EventCreated, notice{scopeID: scope, recipient: customer, siteID: &site, sourceID: "t1", requestID: "r"})
	service.notifyStaff(ctx, tx, scope, EventStaffReplied, notice{siteID: &site, sourceID: "m1", requestID: "r"})
	service.notify(ctx, tx, EventStatusChanged, notice{scopeID: scope, recipient: customer, sourceID: "t2", requestID: "r"})
	if got := enqueuer.SubjectSites(); !slices.Equal(got, []uuid.UUID{site, site, uuid.Nil}) {
		t.Fatalf("subject sites %v, want [%s %s none]", got, site, site)
	}
}
