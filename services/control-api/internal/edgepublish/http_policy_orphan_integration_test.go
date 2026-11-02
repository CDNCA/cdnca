//go:build integration

package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/jackc/pgx/v5"
)

// an enabled HTTP policy on a deleted site (left by the
// site delete before migration 620; 73 tenant scope 01a192ca) is skipped, not
// a failure of the scope: the other sites publish with their own policies.
func TestHTTPPolicyOfDeletedSiteDoesNotFailScopePublication(t *testing.T) {
	fixture := newPublishFixture(t)
	kept := fixture.createSite(t, "kept.orphan-policy.example.test", 80, false)
	gone := fixture.createSite(t, "gone.orphan-policy.example.test", 8080, false)
	config, err := httppolicycontrol.NewSitePolicyConfig(4<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []fixtureSite{kept.Site, gone.Site} {
		if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			_, err := httppolicycontrol.CreateForNewSiteTx(t.Context(), tx, fixture.platformScopeID, fixture.platformUserID,
				fixture.scopeID, fixture.tenantID, site.ID, fixture.userID, config, publishTestClock)
			return err
		}); err != nil {
			t.Fatalf("create HTTP policy: %v", err)
		}
	}
	// The site delete before the fix: the site row only.
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET deleted_at=$2,updated_at=$2,revision=revision+1
		WHERE id=$1`, gone.Site.ID, publishTestClock); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.Publish(t.Context(), fixture.publishRequest("orphan-policy", fixture.nodeID))
	if err != nil {
		t.Fatalf("publish with an orphan HTTP policy: %v", err)
	}
	if result.SourceRevision < 1 {
		t.Fatalf("publish result = %+v", result)
	}
	// The facts of that release: the kept site's policy only.
	var facts []httpPolicyFact
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		revision := fixture.sourceRevision()
		_, loaded, err := loadHTTPPolicyFactsAt(t.Context(), tx, fixture.scopeID, revision, revision,
			[]siteRuntimeV2Site{{ID: kept.Site.ID.String(), Revision: 1}})
		facts = loaded
		return err
	}); err != nil {
		t.Fatalf("load HTTP policy facts: %v", err)
	}
	if len(facts) != 1 || facts[0].siteID != kept.Site.ID {
		t.Fatalf("HTTP policy facts = %+v, want the kept site's only", facts)
	}
}
