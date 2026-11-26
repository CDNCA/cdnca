package securitybinding

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

// saving a WAF policy with its
// stored content returns the current policy and revision without a new
// version, audit event or publication; a stale revision is still refused,
// and a real change is written as before.
func TestEqualPolicyUpdateIsNoOp(t *testing.T) {
	fixture := newBindingFixture(t)
	pool, tenant := fixture.pool, fixture.tenantA
	sub := insertFeatureSubscription(t, pool, tenant.scopeID, tenant.userID, bindingTestNow, false, true)
	assignFeature(t, pool, tenant.scopeID, tenant.userID, sub, "waf", bindingTestNow)
	actor := tenantActor(tenant)
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, func() time.Time { return bindingTestNow }))
	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "equal save", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow,
		Rules: []securitypolicy.Rule{{Name: "block admin", Priority: 10, Enabled: true, Action: securitypolicy.ActionBlock,
			Flow: securitypolicy.FlowStop, Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}}}}
	created, err := service.Create(t.Context(), actor, securitypolicy.CreateRequest{TargetScopeID: tenant.scopeID,
		OwnerUserID: tenant.userID, Fields: fields, IdempotencyKey: "equal-save-create", RequestID: "equal-save-create"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id := created.Policy.ID
	counts := func() (versions, audits, publications int) {
		versions = countRows(t, pool, `SELECT count(*) FROM security_policy_versions WHERE policy_id='`+id.String()+`'`)
		audits = countRows(t, pool, `SELECT count(*) FROM audit_events WHERE action='security_policy.update' AND resource_id='`+id.String()+`'`)
		publications = countRows(t, pool, `SELECT count(*) FROM security_policy_publications WHERE policy_id='`+id.String()+`'`)
		return
	}
	// What the editor sends back: the stored policy as read.
	stored, err := service.Get(t.Context(), actor, id)
	if err != nil {
		t.Fatal(err)
	}
	same := securitypolicy.PolicyFields{Kind: stored.Kind, Name: stored.Name, Description: stored.Description, Enabled: stored.Enabled,
		DefaultAction: stored.DefaultAction, Rules: stored.Rules, CCSettings: stored.CCSettings, WAFSettings: stored.WAFSettings}
	versions, audits, publications := counts()

	equal, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: id, ExpectedRevision: stored.Revision,
		Fields: same, IdempotencyKey: "equal-save-noop", RequestID: "equal-save-noop"})
	if err != nil {
		t.Fatalf("equal Update: %v", err)
	}
	if equal.Policy.Revision != stored.Revision || !equal.Policy.UpdatedAt.Equal(stored.UpdatedAt) {
		t.Fatalf("equal update moved the policy: revision %d→%d, updated_at %s→%s", stored.Revision, equal.Policy.Revision, stored.UpdatedAt, equal.Policy.UpdatedAt)
	}
	if v, a, p := counts(); v != versions || a != audits || p != publications {
		t.Fatalf("equal update wrote: versions %d→%d, audits %d→%d, publications %d→%d", versions, v, audits, a, publications, p)
	}
	// The same key replays the no-op.
	replayed, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: id, ExpectedRevision: stored.Revision,
		Fields: same, IdempotencyKey: "equal-save-noop", RequestID: "equal-save-noop"})
	if err != nil || !replayed.Replayed || replayed.Policy.Revision != stored.Revision {
		t.Fatalf("replay = %+v, %v", replayed, err)
	}
	// The same key with other fields is still refused.
	other := same
	other.Name = "equal save other"
	if _, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: id, ExpectedRevision: stored.Revision,
		Fields: other, IdempotencyKey: "equal-save-noop", RequestID: "equal-save-noop"}); !errors.Is(err, securitypolicy.ErrIdempotencyConflict) {
		t.Fatalf("same key, other fields: %v, want ErrIdempotencyConflict", err)
	}
	// CAS still holds for an equal save with a stale revision (HTTP 409 version_conflict).
	if _, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: id, ExpectedRevision: stored.Revision + 1,
		Fields: same, IdempotencyKey: "equal-save-stale", RequestID: "equal-save-stale"}); !errors.Is(err, securitypolicy.ErrRevisionConflict) {
		t.Fatalf("equal update with a stale revision: %v, want ErrRevisionConflict", err)
	}
	if v, a, p := counts(); v != versions || a != audits || p != publications {
		t.Fatalf("refused updates wrote: versions %d→%d, audits %d→%d, publications %d→%d", versions, v, audits, a, publications, p)
	}

	changed := same
	changed.Name = "equal save renamed"
	written, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: id, ExpectedRevision: stored.Revision,
		Fields: changed, IdempotencyKey: "equal-save-change", RequestID: "equal-save-change"})
	if err != nil {
		t.Fatalf("changed Update: %v", err)
	}
	if written.Policy.Revision != stored.Revision+1 || written.Policy.Name != changed.Name {
		t.Fatalf("changed update = revision %d name %q", written.Policy.Revision, written.Policy.Name)
	}
	if v, a, _ := counts(); v != versions+1 || a != audits+1 {
		t.Fatalf("changed update: versions %d→%d, audits %d→%d", versions, v, audits, a)
	}
}
