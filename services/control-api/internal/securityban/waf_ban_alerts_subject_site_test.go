package securityban

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/pgxscript"
	"github.com/google/uuid"
)

// evt-site: the platform WAF ban alert names the banned site.
func TestWAFBanAlertRecordsSubjectSite(t *testing.T) {
	site := uuid.New()
	tx := pgxscript.New(
		pgxscript.Step{Match: "FROM access_scopes WHERE kind='platform'", Rows: [][]any{{uuid.New()}}},
		pgxscript.Step{Match: "FROM sites WHERE id=$1", Rows: [][]any{{"a.example.com"}}},
		pgxscript.Step{Match: "FROM notification_events", Rows: [][]any{{false}}},
		pgxscript.Step{Match: "FROM memberships membership", Rows: [][]any{{uuid.New()}}})
	enqueuer := &pgxscript.Enqueuer{}
	syncer := &Syncer{alerts: enqueuer}
	event := analyticslog.TemporaryBanEvent{SiteID: site.String(), ClientIP: "192.0.2.1", EventType: "waf", OccurredAt: time.Now()}
	if err := syncer.enqueueWAFBanAlert(context.Background(), tx, event, 600); err != nil {
		t.Fatal(err)
	}
	if got := enqueuer.SubjectSites(); len(got) != 1 || got[0] != site {
		t.Fatalf("subject sites %v, want [%s]", got, site)
	}
}
