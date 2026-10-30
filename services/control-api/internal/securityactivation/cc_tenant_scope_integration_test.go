//go:build integration

package securityactivation

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestCCActivationBuildsWhenTenantDiffersFromScope: production tenants
// (accountregistration) get a tenant ID distinct from their configuration
// scope ID. A CC policy compiles with the scope ID as its tenant scope while
// the release keeps the tenant ID for telemetry, so activating even a single
// rate limit must still build.
func TestCCActivationBuildsWhenTenantDiffersFromScope(t *testing.T) {
	fixture := newActivationFixture(t)
	if fixture.tenantID == fixture.scopeID {
		t.Fatal("fixture must give the tenant and its scope different IDs")
	}
	store := newProductionActivationStore(t, fixture)
	ccPolicyID, ccBindingID := uuid.New(), uuid.New()
	policy := securitypolicy.Policy{ID: ccPolicyID, ScopeID: fixture.scopeID, Kind: securitypolicy.KindCC, Name: "limit",
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: []securitypolicy.Rule{{
			ID: uuid.New(), Name: "limit", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{
				Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 10, ResponseAction: "reject_429",
			}},
		}}}
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	ruleJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`UPDATE security_policy_publication_targets SET released_at=$2,release_reason='completed'
				WHERE publication_id=$1 AND released_at IS NULL`, []any{fixture.bundleID, fixture.now}},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'cc','limit',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{ccPolicyID, fixture.scopeID, fixture.tenantID, fixture.actor.UserID, ruleJSON, fixture.now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{ccPolicyID, document, fixture.actor.UserID, fixture.now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'cc',NULL,NULL,NULL,0,$5,$5)`,
				[]any{ccBindingID, fixture.scopeID, fixture.siteID, ccPolicyID, fixture.now}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	started, err := store.Start(t.Context(), fixture.actor, StartInput{
		TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, PolicyID: ccPolicyID, PolicyVersion: 1,
		TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, CanarySize: 1,
		IdempotencyKey: "cc-tenant-scope", RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
		Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
		ExpiresAt:   fixture.now.Add(10 * 60e9),
	})
	if err != nil {
		t.Fatalf("CC activation with tenant %s and scope %s: %v", fixture.tenantID, fixture.scopeID, err)
	}
	if started.Candidate.Status != StatusClaimed {
		t.Fatalf("started candidate status = %s, want %s", started.Candidate.Status, StatusClaimed)
	}
}
