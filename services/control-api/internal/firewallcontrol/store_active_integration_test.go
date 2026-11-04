//go:build integration

package firewallcontrol

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Once a policy is active (active_revision>0, active_sha256 set), saving it
// again and recovering it must work. persistCurrent's INSERT candidate
// carried active_revision without active_sha256, so PostgreSQL refused it
// on global_firewall_policies_check2 before ON CONFLICT: every Put and
// Recover after the first activation failed (500).
func TestPolicySavesAndRecoversAfterActivation(t *testing.T) {
	f := newSharedNodeFixture(t, true)
	// No enabled site: a disabled policy settles active without commands
	// (failUnownedPublication), the real path to an active policy here.
	if _, err := f.pool.Exec(t.Context(), `UPDATE sites SET enabled=false,status='disabled' WHERE id=$1`, f.siteA); err != nil {
		t.Fatal(err)
	}
	store := NewStore(f.pool, allowAuthorizer{}, nil, time.Now)
	actor := Actor{UserID: f.user, ScopeID: f.tenantA, ScopeKind: ScopeTenant, Permissions: []string{PermissionManage}}
	put := func(expected int64) error {
		policy := PolicyInput{Enabled: false, DefaultAction: ActionAllow, Rules: []RuleInput{{ID: uuid.New(), Priority: 1,
			Action: ActionDeny, CIDRs: []string{"192.0.2.0/24"}, Protocol: ProtocolAny}}}
		document, _ := json.Marshal(policy)
		_, err := store.Put(t.Context(), PutRequest{Actor: actor, TargetScopeID: f.tenantA, ExpectedRevision: expected,
			Policy: policy, DocumentSHA256: sha256.Sum256(document), IdempotencyKey: "act-" + uuid.NewString()[:8],
			RequestSHA256: sha256.Sum256([]byte(uuid.NewString())), RequestID: uuid.NewString()})
		return err
	}
	requireSettled := func(revision int64, state string) {
		t.Helper()
		policy, err := store.Get(t.Context(), ReadRequest{Actor: actor, TargetScopeID: f.tenantA})
		if err != nil || policy.Revision != revision || policy.ActiveRevision != revision || policy.DeploymentState != state {
			t.Fatalf("policy = revision %d active %d %s (%v), want revision %d active %d %s", policy.Revision, policy.ActiveRevision,
				policy.DeploymentState, err, revision, revision, state)
		}
	}
	requireActive := func(revision int64) { t.Helper(); requireSettled(revision, DeploymentActive) }
	if err := put(0); err != nil {
		t.Fatal(err)
	}
	f.project(t)
	requireActive(1)
	if err := put(1); err != nil {
		t.Fatalf("second Put after activation: %v", err)
	}
	f.project(t)
	requireActive(2)
	if _, err := store.Recover(t.Context(), RecoverRequest{Actor: actor, TargetScopeID: f.tenantA, ExpectedRevision: 2,
		RecoverRevision: 1, Reason: RecoveryOperator, IdempotencyKey: "act-" + uuid.NewString()[:8], RequestID: uuid.NewString()}); err != nil {
		t.Fatalf("Recover after activation: %v", err)
	}
	f.project(t)
	requireSettled(3, DeploymentRolledBack) // a recovery settles rolled_back
	if err := put(3); err != nil {
		t.Fatalf("Put after a recovery: %v", err)
	}
}
