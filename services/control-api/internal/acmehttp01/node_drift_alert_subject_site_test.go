package acmehttp01

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pgxscript"
	"github.com/google/uuid"
)

// evt-site: the platform drift alert names the drifting site.
func TestEpochDriftAlertRecordsSubjectSite(t *testing.T) {
	site := siteKey{ScopeID: uuid.New(), SiteID: uuid.New()}
	tx := pgxscript.New(
		pgxscript.Step{Match: "FROM access_scopes scope", Rows: [][]any{{uuid.New(), false}}},
		pgxscript.Step{Match: "FROM sites site", Rows: [][]any{{"a.example.com", time.Now()}}},
		pgxscript.Step{Match: "FROM unnest", Rows: [][]any{{"node-1"}}},
		pgxscript.Step{Match: "FROM memberships membership", Rows: [][]any{{uuid.New()}, {uuid.New()}}})
	enqueuer := &pgxscript.Enqueuer{}
	store := &NodeStore{alerts: enqueuer}
	if err := store.alertDriftTx(context.Background(), tx, site, uuid.New(), []uuid.UUID{uuid.New()}); err != nil {
		t.Fatal(err)
	}
	got := enqueuer.SubjectSites()
	if len(got) != 2 || got[0] != site.SiteID || got[1] != site.SiteID {
		t.Fatalf("subject sites %v, want two of %s", got, site.SiteID)
	}
}
