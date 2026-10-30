//go:build integration

package securityactivation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func insertFeatureSubscription(t *testing.T, pool *pgxpool.Pool, scopeID, ownerID uuid.UUID, now time.Time, customCC, waf bool) uuid.UUID {
	t.Helper()
	id, productID, platformScope := uuid.New(), uuid.New(), uuid.Nil
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).Scan(&platformScope); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		platformScope = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
			t.Fatal(err)
		}
	}
	spec := fmt.Sprintf(`{"limits":{"domains":10,"root_domains":10,"http_ports":10,"stream_ports":10,"custom_cc":%t},"protection":{"waf":%t}}`, customCC, waf)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, platformScope); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_products(id,name,spec,created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,$4,$5,$5)`, productID, productID.String(), spec, ownerID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(product_id,revision,name,enabled,sort_order,spec,created_by_user_id,created_at) VALUES($1,1,$2,true,100,$3,$4,$5)`, productID, productID.String(), spec, ownerID, now); err != nil {
			return err
		}
		if err := audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: platformScope, ActorUserID: &ownerID, Action: "package.product.create", ResourceType: "package_product", ResourceID: productID.String(), RequestID: productID.String(), Result: "success", Payload: map[string]any{"revision": 1, "enabled": true}}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
   SELECT $1,$2,product_id,revision,jsonb_build_object('id',product_id::text,'revision',revision,'name',name,'spec',spec),10,10,10,1000000,$4,$5,'UTC','monthly',1,1,$3,$3,$4,$4 FROM package_product_versions WHERE product_id=$6`, id, scopeID, ownerID, now, now.Add(24*time.Hour), productID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(subscription_id,revision,tenant_scope_id,effective_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,currency,entitlement_status,operation,created_by_user_id,created_at)
   SELECT id,1,tenant_scope_id,starts_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,'CNY','active','migration_backfill',created_by_user_id,created_at FROM package_subscriptions WHERE id=$1`, id)
		if err != nil {
			return err
		}
		_, err = tx.Exec(t.Context(), `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',$4)`, id, scopeID, ownerID, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func linkFeatureSubscription(t *testing.T, pool *pgxpool.Pool, siteID, subscriptionID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET package_subscription_id=$2,package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`, siteID, subscriptionID); err != nil {
		t.Fatal(err)
	}
}

func assignFeature(t *testing.T, pool *pgxpool.Pool, scopeID, ownerID, subscriptionID uuid.UUID, kind string, now time.Time) uuid.UUID {
	t.Helper()
	id, addonID := uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT id FROM package_subscriptions WHERE id=$1 FOR UPDATE`, subscriptionID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_addon_products(id,name,kind,quantity,monthly_price_minor,created_at,updated_at) VALUES($1,$2,$3,1,0,$4,$4)`, addonID, addonID.String(), kind, now); err != nil {
			return err
		}
		if err := audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: scopeID, ActorUserID: &ownerID, Action: "package.addon.product.create", ResourceType: "package_addon", ResourceID: addonID.String(), RequestID: addonID.String(), Result: "success", Payload: map[string]any{"revision": 1}}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_addon_assignments(id,addon_id,tenant_scope_id,owner_user_id,subscription_id,kind,amount,snapshot,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,1,'{"quantity":1,"monthly_price_minor":0}',$7,$7)`, id, addonID, scopeID, ownerID, subscriptionID, kind, now); err != nil {
			return err
		}
		return audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: scopeID, ActorUserID: &ownerID, Action: "package.addon.assignment.create", ResourceType: "package_addon", ResourceID: id.String(), RequestID: id.String(), Result: "success", Payload: map[string]any{"revision": 1}})
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func revokeFeatureTx(ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool, scopeID, ownerID, assignmentID uuid.UUID, now time.Time) error {
	if _, err := tx.Exec(ctx, `SELECT s.id FROM package_subscriptions s JOIN package_addon_assignments a ON a.subscription_id=s.id WHERE a.id=$1 FOR UPDATE OF s`, assignmentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE package_addon_assignments SET revoked_at=$2,updated_at=$2,revision=revision+1 WHERE id=$1`, assignmentID, now); err != nil {
		return err
	}
	return audit.New(pool).Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &ownerID, Action: "package.addon.assignment.revoke", ResourceType: "package_addon", ResourceID: assignmentID.String(), RequestID: uuid.NewString(), Result: "success", Payload: map[string]any{"revision": 2}})
}

func TestPackageFeatureClaimAndPromotionRecheck(t *testing.T) {
	fixture := newActivationFixture(t)
	sub := insertFeatureSubscription(t, fixture.pool, fixture.scopeID, fixture.actor.UserID, fixture.now, false, false)
	linkFeatureSubscription(t, fixture.pool, fixture.siteID, sub)
	if err := fixture.pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, fixture.scopeID).Scan(&fixture.sourceRevision); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	input := fixture.claimInput("feature-claim")
	if _, err := store.Claim(t.Context(), fixture.actor, input); !errors.Is(err, packageaddon.ErrFeatureDenied) {
		t.Fatalf("claim without feature: %v", err)
	}
	assignment := assignFeature(t, fixture.pool, fixture.scopeID, fixture.actor.UserID, sub, "waf", fixture.now)
	seedFeatureActiveIdentity(t, fixture)
	created, err := store.Claim(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	fixture.markCandidateHealthy(t, created.Candidate.ID)
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := revokeFeatureTx(t.Context(), tx, fixture.pool, fixture.scopeID, fixture.actor.UserID, assignment, fixture.now); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := store.Promote(t.Context(), fixture.actor, created.Candidate.ID, created.Candidate.PromotionCAS())
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("promotion passed subscription lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, packageaddon.ErrFeatureDenied) {
			t.Fatalf("promotion after revoke: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("promotion deadlock")
	}
	if replay, err := store.Claim(t.Context(), fixture.actor, input); err != nil || !replay.Replayed {
		t.Fatalf("claim replay=%+v %v", replay, err)
	}
	var active int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT active_policy_version FROM security_policy_site_bindings WHERE id=$1`, fixture.bindingID).Scan(&active); err != nil || active != 1 {
		t.Fatalf("running active version changed=%d %v", active, err)
	}
	assignment = assignFeature(t, fixture.pool, fixture.scopeID, fixture.actor.UserID, sub, "waf", fixture.now)
	promoted, err := store.Promote(t.Context(), fixture.actor, created.Candidate.ID, created.Candidate.PromotionCAS())
	if err != nil || promoted.Status != StatusPromoted {
		t.Fatalf("promote with restored addon=%+v %v", promoted, err)
	}
	testFeatureDisableAndRelease(t, fixture, assignment)
}

func seedFeatureActiveIdentity(t *testing.T, fixture activationFixture) {
	t.Helper()
	rolloutID, canaryDeploymentID, expandDeploymentID := uuid.New(), uuid.New(), uuid.New()
	command := []byte("feature-activation-command")
	commandDigest := sha256.Sum256(command)
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,revision,max_attempts,contract_version)
			VALUES($1,$2,$3,'apply','completed',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9,1,3,0)`, rolloutID, fixture.scopeID, fixture.previousConfigID, "feature-active-identity", make([]byte, 32), uuid.New(), uuid.New(), fixture.now.Add(time.Hour), fixture.now); err != nil {
			return err
		}
		for index, nodeID := range []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID} {
			deploymentID := canaryDeploymentID
			if index == 1 {
				deploymentID = expandDeploymentID
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,$9,$9)`, deploymentID, rolloutID, nodeID, fixture.previousConfigID, uuid.New(), command, commandDigest[:], fixture.now.Add(time.Hour), fixture.now); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal) VALUES($1,1,$2,$3,1)`, deploymentID, fixture.previousConfigID, fixture.previousArtifactID); err != nil {
				return err
			}
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_config_state SET current_config_identity_schema=1,current_config_artifact_sha256=$2 WHERE node_id=ANY($1)`, []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, fixture.previousArtifactDigest[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func featureAdmin(t *testing.T, fixture activationFixture) packageaddon.Actor {
	t.Helper()
	var platformScope uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).Scan(&platformScope); err != nil {
		t.Fatal(err)
	}
	actor := packageaddon.Actor{ScopeID: platformScope, UserID: fixture.actor.UserID, SessionID: uuid.New()}
	roleID := uuid.New()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO memberships(scope_id,user_id)VALUES($1,$2)`, []any{actor.ScopeID, actor.UserID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role)VALUES($1,$2,'platform_admin','',true)`, []any{roleID, actor.ScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name)VALUES($1,'platform.admin')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id)VALUES($1,$2,$3)`, []any{actor.ScopeID, actor.UserID, roleID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{actor.SessionID, uuid.New(), actor.UserID, actor.ScopeID, make([]byte, 32), fixture.now, fixture.now.Add(time.Hour)}},
	}
	for _, s := range statements {
		if _, err := fixture.pool.Exec(t.Context(), s.sql, s.args...); err != nil {
			t.Fatal(err)
		}
	}
	return actor
}

func assertFeatureGuard(t *testing.T, fixture activationFixture, actor packageaddon.Actor, id uuid.UUID, want error) {
	t.Helper()
	store := packageaddon.Store{Pool: fixture.pool, Now: func() time.Time { return fixture.now }}
	key := uuid.NewString()
	_, err := store.Write(t.Context(), actor, packageaddon.Command{Action: "assignment.delete", ID: id, ExpectedRevision: 1}, key, key)
	if !errors.Is(err, want) {
		t.Fatalf("assignment revoke error=%v want=%v", err, want)
	}
	var revision int64
	var revoked *time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT revision,revoked_at FROM package_addon_assignments WHERE id=$1`, id).Scan(&revision, &revoked); err != nil {
		t.Fatal(err)
	}
	if want != nil && (revision != 1 || revoked != nil) {
		t.Fatalf("failed revoke mutated assignment: %d %v", revision, revoked)
	}
	if want == nil && (revision != 2 || revoked == nil) {
		t.Fatalf("successful revoke did not persist: %d %v", revision, revoked)
	}
}

func testFeatureDisableAndRelease(t *testing.T, fixture activationFixture, assignment uuid.UUID) {
	actor := featureAdmin(t, fixture)
	var policy securitypolicy.Policy
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		var err error
		policy, err = loadPolicyVersion(t.Context(), tx, fixture.scopeID, fixture.policyID, 2)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(fixture.pool, func() time.Time { return fixture.now }))
	update := securitypolicy.UpdateRequest{ID: policy.ID, ExpectedRevision: 2, Fields: securitypolicy.PolicyFields{Kind: policy.Kind, Name: policy.Name, Description: policy.Description, Enabled: false, DefaultAction: policy.DefaultAction, Rules: policy.Rules}, IdempotencyKey: "disable-feature", RequestID: "disable-feature"}
	disabled, err := service.Update(t.Context(), fixture.actor, update)
	if err != nil {
		t.Fatal(err)
	}
	assertFeatureGuard(t, fixture, actor, assignment, packageaddon.ErrWAFInUse)
	production := newProductionActivationStore(t, fixture)
	input := StartInput{TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, PolicyID: fixture.policyID, PolicyVersion: disabled.Policy.Revision, ExpectedBindingRevision: 3, ExpectedActivePolicyVersion: 2, TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID}, CanarySize: 1, IdempotencyKey: "disable-activate", RequestID: "disable-activate", ExpiresAt: fixture.now.Add(10 * time.Minute)}
	started, err := production.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	completeProductionActivation(t, fixture, production, started.Candidate)
	assertFeatureGuard(t, fixture, actor, assignment, nil)
	// An enabled pending publication reserves WAF even while the active version is disabled.
	assignment = assignFeature(t, fixture.pool, fixture.scopeID, fixture.actor.UserID, subscriptionForSite(t, fixture), "waf", fixture.now)
	update.ExpectedRevision = disabled.Policy.Revision
	update.Fields.Enabled = true
	update.IdempotencyKey = "reenable-feature"
	enabled, err := service.Update(t.Context(), fixture.actor, update)
	if err != nil {
		t.Fatal(err)
	}
	input.PolicyVersion = enabled.Policy.Revision
	input.ExpectedBindingRevision = started.Candidate.BindingRevision + 1
	input.ExpectedActivePolicyVersion = disabled.Policy.Revision
	input.IdempotencyKey = "pending-feature"
	if _, err := production.Start(t.Context(), fixture.actor, input); err != nil {
		t.Fatal(err)
	}
	assertFeatureGuard(t, fixture, actor, assignment, packageaddon.ErrWAFInUse)
}

func subscriptionForSite(t *testing.T, fixture activationFixture) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT package_subscription_id FROM sites WHERE id=$1`, fixture.siteID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
