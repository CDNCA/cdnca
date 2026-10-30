//go:build integration

package securityactivation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// saveFixtureRevision3 saves the fixture library once more on the general
// rules page: revision 3 (newer than the binding's active 1 and claimed 2).
func saveFixtureRevision3(t *testing.T, fixture activationFixture, savedAt time.Time) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
		 SELECT policy_id,3,jsonb_set(document,'{version}','3'),created_by_user_id,$2 FROM security_policy_versions
		 WHERE policy_id=$1 AND revision=2`,
		`UPDATE security_policies SET revision=3,updated_at=$2 WHERE id=$1`,
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement, fixture.policyID, savedAt); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRebindLoadsStaleBindingsAsTheSaverInItsTenant(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	// Revision 2 is claimed: nothing is behind.
	if items, err := store.loadRebindItems(t.Context(), fixture.now.Add(time.Hour), uuid.Nil, 10); err != nil || len(items) != 0 {
		t.Fatalf("claimed binding loaded: %+v %v", items, err)
	}
	saveFixtureRevision3(t, fixture, fixture.now.Add(-time.Minute))
	// Inside the grace (a site-context save starts its own site) it waits.
	if items, err := store.loadRebindItems(t.Context(), fixture.now.Add(-2*time.Minute), uuid.Nil, 10); err != nil || len(items) != 0 {
		t.Fatalf("revision inside the grace loaded: %+v %v", items, err)
	}
	items, err := store.loadRebindItems(t.Context(), fixture.now, uuid.Nil, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("stale binding: %+v %v", items, err)
	}
	item := items[0]
	if item.bindingID != fixture.bindingID || item.scopeID != fixture.scopeID || item.siteID != fixture.siteID ||
		item.policyRevision != 3 || item.bindingRevision != 2 || item.activePolicyVersion != 1 {
		t.Fatalf("item = %+v", item)
	}
	if item.actor.ScopeID != fixture.scopeID || item.actor.ScopeKind != "tenant" || item.actor.UserID == uuid.Nil {
		t.Fatalf("actor %+v is not the saver in the site's tenant", item.actor)
	}
	// A capability wait for the site and kind (waiting) defers to its resume.
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO security_activation_capability_waits(id,tenant_scope_id,site_id,
		policy_id,policy_kind,policy_version,expected_binding_revision,expected_active_policy_version,target_node_ids,canary_size,
		actor_user_id,actor_scope_id,actor_scope_kind,capability,required_api_version,blocking_node_ids,created_at,updated_at)
		VALUES($1,$2,$3,$4,'waf',3,2,1,ARRAY[$5::uuid],1,$6,$2,'tenant',1,1,ARRAY[$5::uuid],$7,$7)`,
		uuid.New(), fixture.scopeID, fixture.siteID, fixture.policyID, fixture.canaryNodeID, item.actor.UserID, fixture.now); err != nil {
		t.Fatal(err)
	}
	if items, err := store.loadRebindItems(t.Context(), fixture.now, uuid.Nil, 10); err != nil || len(items) != 0 {
		t.Fatalf("binding with a capability wait loaded: %+v %v", items, err)
	}
}

// The rules page count: the fixture site is moved to a package without WAF,
// so its stale enabled WAF binding is counted as not published for the package.
func TestRebindStatusCountsPackageDeniedSitesInOwnScopeOnly(t *testing.T) {
	fixture := newActivationFixture(t)
	// newActivationFixture links a package with WAF; switch to one without it.
	linkFeatureSubscription(t, fixture.pool, fixture.siteID,
		insertFeatureSubscription(t, fixture.pool, fixture.scopeID, fixture.actor.UserID, fixture.now, false, false))
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	reader := fixture.newPermissionActor(t, "security_policies.read").actor
	status, err := store.RebindStatus(t.Context(), reader, "waf")
	if err != nil || status != (RebindStatus{}) {
		t.Fatalf("before the save: %+v %v", status, err)
	}
	saveFixtureRevision3(t, fixture, fixture.now.Add(-time.Minute))
	status, err = store.RebindStatus(t.Context(), reader, "waf")
	if err != nil || status.PendingSites != 1 || status.PackageDeniedSites != 1 {
		t.Fatalf("after the save: %+v %v", status, err)
	}
	if status, err := store.RebindStatus(t.Context(), reader, "cc"); err != nil || status != (RebindStatus{}) {
		t.Fatalf("cc counted the waf binding: %+v %v", status, err)
	}
	// A session of another tenant scope never reads this scope: the count
	// is of the actor's own scope, and a stranger is refused.
	stranger := reader
	stranger.ScopeID = uuid.New()
	if status, err := store.RebindStatus(t.Context(), stranger, "waf"); err == nil {
		t.Fatalf("stranger scope read %+v", status)
	}
}
