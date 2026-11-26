//go:build integration

package securityactivation

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// /
// a library saved while the site's subscription is suspended is refused with
// package_subscription_suspended (the site is out of every publication until
// it is resumed), not publication_resource_not_found; the saved library and
// binding are kept, and once resumed the same activation starts.
func TestActivationOfSuspendedSubscriptionSaysSuspendedThenStartsOnResume(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	policyID, bindingID := uuid.New(), uuid.New()
	policy := securitypolicy.Policy{ID: policyID, ScopeID: fixture.scopeID, Kind: securitypolicy.KindCC, Name: "suspended limit",
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
	subscriptionID := subscriptionForSite(t, fixture)
	setSuspended := func(suspended bool) {
		t.Helper()
		if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			for _, statement := range []string{
				`SET LOCAL session_replication_role = replica`,
				`UPDATE package_subscriptions SET suspended_at=CASE WHEN $2 THEN clock_timestamp() END,
				  suspend_reason=CASE WHEN $2 THEN 'whmcs-real-name' END WHERE id=$1`,
			} {
				args := []any{}
				if statement[:3] != "SET" {
					args = []any{subscriptionID, suspended}
				}
				if _, err := tx.Exec(t.Context(), statement, args...); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The library saved for the site (security_policies.manage) and its binding.
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`UPDATE security_policy_publication_targets SET released_at=$2,release_reason='completed'
				WHERE publication_id=$1 AND released_at IS NULL`, []any{fixture.bundleID, fixture.now}},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'cc','suspended limit',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{policyID, fixture.scopeID, fixture.tenantID, fixture.actor.UserID, ruleJSON, fixture.now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{policyID, document, fixture.actor.UserID, fixture.now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'cc',NULL,NULL,NULL,0,$5,$5)`,
				[]any{bindingID, fixture.scopeID, fixture.siteID, policyID, fixture.now}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start := func(key string) StartInput {
		return StartInput{
			TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, PolicyID: policyID, PolicyVersion: 1,
			TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, CanarySize: 1,
			IdempotencyKey: key, RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
			Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
			ExpiresAt:   fixture.now.Add(10 * 60e9),
		}
	}

	setSuspended(true)
	if _, err := store.Start(t.Context(), fixture.actor, start("suspended-start")); !errors.Is(err, edgepublish.ErrPackageSubscriptionSuspended) {
		t.Fatalf("start while suspended: %v, want ErrPackageSubscriptionSuspended", err)
	}
	var policies, candidates int
	var bindingRevision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM security_policies WHERE id=$1 AND deleted_at IS NULL),
		(SELECT count(*) FROM security_policy_activation_candidates WHERE binding_id=$2),
		(SELECT revision FROM security_policy_site_bindings WHERE id=$2)`, policyID, bindingID).
		Scan(&policies, &candidates, &bindingRevision); err != nil {
		t.Fatal(err)
	}
	if policies != 1 || candidates != 0 || bindingRevision != 0 {
		t.Fatalf("refused start: library=%d candidates=%d binding revision=%d, want the saved library untouched",
			policies, candidates, bindingRevision)
	}

	setSuspended(false)
	started, err := store.Start(t.Context(), fixture.actor, start("resumed-start"))
	if err != nil || started.Candidate.Status != StatusClaimed {
		t.Fatalf("start after resume = (%+v, %v), want a claimed candidate", started.Candidate, err)
	}
}
