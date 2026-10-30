//go:build integration

package edgepublish_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// FX57: a manual-mode tenant (no automatic policy) whose secondary
// verification is overdue has its website taken off the nodes at once by a
// system republication, and put back once the request no longer applies,
// without anyone publishing and without waiting for the debounce.
func TestSystemRepublishStopsAndRestoresSecondaryVerificationSitesImmediately(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "syspub-secver", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	site := []byte(scope.SiteID.String())
	if !bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("baseline publication lacks the site")
	}
	if _, err := scope.Pool.Exec(t.Context(), `INSERT INTO identity_user_secondary_verification
		(scope_id,user_id,revision,enabled,deadline,expiry_action,requested_at,updated_by_user_id,updated_at)
		VALUES($1,$2,1,true,clock_timestamp()-interval '1 minute','lock_sites',clock_timestamp()-interval '1 day',$2,clock_timestamp())`,
		scope.ScopeID, scope.UserID); err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(scope.Pool)
	republisher := edgeautopublish.SecondaryVerificationRepublisher{}
	if pass, err := store.EnforceSecondaryVerificationDeadlines(t.Context(), republisher, 10); err != nil || pass.Held != 1 {
		t.Fatalf("stop pass=(%+v,%v)", pass, err)
	}
	// Due now: no MakeDue, the republisher picks it up in the same tick.
	if due := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads
		WHERE scope_id=$1 AND state='pending' AND due_at<=clock_timestamp()
		  AND triggers=ARRAY['secondary_verification']::text[]`); due != 1 {
		t.Fatalf("immediately due secondary verification heads = %d", due)
	}
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished ||
		!slices.Equal(attempt.Triggers, []string{"secondary_verification"}) {
		t.Fatalf("stop attempt = %+v", attempt)
	}
	if bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("stopped site is still published")
	}
	scope.SettleDeployments(t)

	// The request no longer applies (switched off): the site is restored and republished at once.
	if _, err := scope.Pool.Exec(t.Context(), `UPDATE identity_user_secondary_verification SET enabled=false,deadline=NULL,
		expiry_action='none',requested_at=NULL,enforced_at=NULL,revision=revision+1 WHERE scope_id=$1 AND user_id=$2`,
		scope.ScopeID, scope.UserID); err != nil {
		t.Fatal(err)
	}
	if pass, err := store.EnforceSecondaryVerificationDeadlines(t.Context(), republisher, 10); err != nil || pass.Released != 1 {
		t.Fatalf("restore pass=(%+v,%v)", pass, err)
	}
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished {
		t.Fatalf("restore attempt = %+v", attempt)
	}
	if !bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("restored site was not republished")
	}
	if segments := scope.Count(t, `SELECT count(*) FROM edge_system_revision_segments
		WHERE scope_id=$1 AND source='secondary_verification'`); segments < 2 {
		t.Fatalf("secondary verification revision segments = %d", segments)
	}
}
