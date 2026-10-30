package domainownership

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/pgxscript"
	"github.com/google/uuid"
)

// evt-site: the suspended notice names the site the claim disabled.
func TestClaimSuspendedNoticeRecordsSubjectSite(t *testing.T) {
	site := uuid.New()
	enqueuer := &pgxscript.Enqueuer{}
	service := &Service{notifier: enqueuer}
	targets := []claimTarget{{scopeID: uuid.New(), siteID: site, ownerID: uuid.New(), domains: []string{"a.example.com"}}}
	var result ClaimResult
	service.notifySuspended(context.Background(), pgxscript.New(), targets,
		map[uuid.UUID][]uuid.UUID{site: {uuid.New()}}, "req", &result)
	if got := enqueuer.SubjectSites(); len(got) != 1 || got[0] != site || enqueuer.Requests[0].EventType != eventSuspended {
		t.Fatalf("subject sites %v, want [%s]", got, site)
	}
}
