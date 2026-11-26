//go:build integration

package securityactivation

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// a new site
// was created with a default WAF and CC library. The WAF candidate (source
// revision 62) was healthy on its node at 18:37:37; the site's own automatic
// publication (63) was healthy on the same node at 18:37:58, and the WAF
// promotion failed then (promotion-failed) and recovered. The binding was
// left with last claimed = the library's revision and no active version, and
// nothing ever claimed it again; the CC, refused while the WAF held the node,
// was promoted at 64.

// newClockedProductionStore is newProductionActivationStore reading the
// clock through fixture, so a test can move time forward.
func newClockedProductionStore(t *testing.T, fixture *activationFixture) *Store {
	t.Helper()
	clock := func() time.Time { return fixture.now }
	bundlePublisher, err := securitybundle.NewPublisher(fixture.signer, securitybundle.Config{Clock: clock, Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := securitybinding.NewStore(fixture.pool, bundlePublisher, clock)
	if err != nil {
		t.Fatal(err)
	}
	deployments, err := edgedeployment.NewStoreWithClock(fixture.pool, clock)
	if err != nil {
		t.Fatal(err)
	}
	publishConfig := edgepublish.DefaultConfig()
	publishConfig.Clock = clock
	publishConfig.EntitlementAuthorizer = activationIntegrationEntitlement{}
	publisher, err := edgepublish.NewService(fixture.pool, deployments, fixture.signer, publishConfig)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewProductionStore(fixture.pool, clock, bindings, publisher, deployments, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// addNewSiteCCBinding binds a CC library to the fixture site, never claimed,
// as site creation leaves the site's default CC (copySiteDefaults).
func addNewSiteCCBinding(t *testing.T, fixture activationFixture) uuid.UUID {
	t.Helper()
	policyID := uuid.New()
	policy := securitypolicy.Policy{ID: policyID, ScopeID: fixture.scopeID, Kind: securitypolicy.KindCC, Name: "site default cc",
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
	rules, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'cc','site default cc',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{policyID, fixture.scopeID, fixture.tenantID, fixture.actor.UserID, rules, fixture.now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{policyID, document, fixture.actor.UserID, fixture.now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'cc',NULL,NULL,NULL,0,$5,$5)`,
				[]any{uuid.New(), fixture.scopeID, fixture.siteID, policyID, fixture.now}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return policyID
}

// rebindItemsByKind loads the worker's rebind batch as of fixture.now.
func rebindItemsByKind(t *testing.T, fixture *activationFixture, store *Store) map[uuid.UUID]rebindItem {
	t.Helper()
	items, err := store.loadRebindItems(t.Context(), fixture.now.Add(-rebindGrace), uuid.Nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	byPolicy := map[uuid.UUID]rebindItem{}
	for _, item := range items {
		byPolicy[item.policyID] = item
	}
	return byPolicy
}

// startRebindItem starts item as the worker does (rebindInput), naming the
// fixture's canary node (the fixture site has no line group to resolve).
func startRebindItem(t *testing.T, fixture *activationFixture, store *Store, item rebindItem) (StartResult, error) {
	t.Helper()
	input := rebindInput(item, fixture.now, store.config.CandidateTTL)
	input.TargetNodeIDs, input.CanarySize = []uuid.UUID{fixture.canaryNodeID}, 1
	return store.Start(t.Context(), item.actor, input)
}

// supersedeAndRecover: the candidate is healthy on its node, then another
// publication of the scope advances the source revision and reaches the node
// (the new site's automatic publication). Promotion is refused with
// ErrSourceRevisionConflict and the candidate fails; its recovery rollback
// then completes on the node.
func supersedeAndRecover(t *testing.T, fixture *activationFixture, store *Store, candidate Candidate) {
	t.Helper()
	fixture.now = fixture.now.Add(2 * time.Second)
	// The node keeps what it ran before as its previous configuration (the
	// recovery rollback's target), as an agent reports it.
	var previousID uuid.UUID
	var previousDigest []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT current_config_version_id,current_config_artifact_sha256
		FROM node_config_state WHERE node_id=$1`, fixture.canaryNodeID).Scan(&previousID, &previousDigest); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE edge_command_outbox SET status='publishing',updated_at=$2 WHERE deployment_id IN (
		   SELECT deployment.id FROM node_deployments deployment WHERE deployment.rollout_id=$1) AND status='pending'`,
		`UPDATE edge_command_outbox SET status='published',published_at=$2,updated_at=$2 WHERE deployment_id IN (
		   SELECT deployment.id FROM node_deployments deployment WHERE deployment.rollout_id=$1) AND status='publishing'`,
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement,
			productionPhaseRolloutID(t, fixture.pool, candidate.ID, "canary"), fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	markProductionPhaseHealthy(t, *fixture, candidate, "canary")
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE node_config_state SET previous_config_version_id=$2,
		previous_config_identity_schema=1,previous_config_artifact_sha256=$3 WHERE node_id=$1`,
		fixture.canaryNodeID, previousID, previousDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(2 * time.Second)
	if _, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "superseded-"+candidate.ID.String())); !errors.Is(err, ErrSourceRevisionConflict) {
		t.Fatalf("promotion after the scope moved on = %v, want ErrSourceRevisionConflict", err)
	}
	assertCandidateStatus(t, fixture.pool, candidate.ID, StatusFailed, false)
	fixture.now = fixture.now.Add(10 * time.Second)
	if err := markProductionRecoveryReverted(t, *fixture, candidate.ID, fixture.canaryNodeID); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(10 * time.Second)
	recovered, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "superseded-recover-"+candidate.ID.String()))
	if err != nil || recovered.Action != string(actionRecover) {
		t.Fatalf("recovery once the node rolled back = (%+v, %v)", recovered, err)
	}
}

func assertPromotionFailure(t *testing.T, fixture *activationFixture, store *Store, failures int, retrying bool) {
	t.Helper()
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil {
		t.Fatal(err)
	}
	if status.Binding == nil || status.Binding.ActivePolicyVersion != 1 || status.LatestCandidate == nil ||
		status.LatestCandidate.Status != StatusFailed {
		t.Fatalf("status binding/candidate = %+v / %+v", status.Binding, status.LatestCandidate)
	}
	want := PromotionFailure{Reason: PromotionFailureSuperseded, Failures: failures, MaxReclaims: promotionReclaimLimit, Retrying: retrying}
	if status.PromotionFailure == nil || *status.PromotionFailure != want {
		t.Fatalf("promotion failure = %+v, want %+v", status.PromotionFailure, want)
	}
}

func TestNewSiteDefaultWAFReclaimedAfterScopePublicationSupersedesIt(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newClockedProductionStore(t, &fixture)
	ccPolicyID := addNewSiteCCBinding(t, fixture)

	// The site's WAF library takes its next version (claimed by the worker),
	// and the CC is refused while the WAF candidate holds the node.
	wafInput := prepareProductionStart(t, fixture, store, "new-site-waf", []uuid.UUID{fixture.canaryNodeID}, 1)
	waf, err := store.Start(t.Context(), fixture.actor, wafInput)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(rebindGrace + time.Second)
	cc, found := rebindItemsByKind(t, &fixture, store)[ccPolicyID]
	if !found || cc.reclaim != 0 {
		t.Fatalf("new CC binding not loaded: %+v", cc)
	}
	if _, err := startRebindItem(t, &fixture, store, cc); !errors.Is(err, ErrTargetBusy) {
		t.Fatalf("CC start while the WAF holds the node = %v, want ErrTargetBusy", err)
	}

	supersedeAndRecover(t, &fixture, store, waf.Candidate)
	assertPromotionFailure(t, &fixture, store, 1, true)

	// Within rebindGrace of the recovery the binding waits; then it is
	// claimed again at the same version.
	if item, found := rebindItemsByKind(t, &fixture, store)[fixture.policyID]; found {
		t.Fatalf("reclaim inside the grace: %+v", item)
	}
	fixture.now = fixture.now.Add(rebindGrace + time.Second)
	items := rebindItemsByKind(t, &fixture, store)
	item, found := items[fixture.policyID]
	if !found || item.reclaim != 1 || item.policyRevision != wafInput.PolicyVersion || item.activePolicyVersion != 1 {
		t.Fatalf("WAF reclaim item = %+v (found %v)", item, found)
	}
	reclaimed, err := startRebindItem(t, &fixture, store, item)
	if err != nil || reclaimed.Candidate.LastClaimedPolicyVersion != wafInput.PolicyVersion ||
		reclaimed.Candidate.CandidateSourceRevision <= waf.Candidate.CandidateSourceRevision {
		t.Fatalf("WAF reclaim = (%+v, %v)", reclaimed.Candidate, err)
	}
	if replay, err := startRebindItem(t, &fixture, store, item); err != nil || !replay.Replayed || replay.Candidate.ID != reclaimed.Candidate.ID {
		t.Fatalf("WAF reclaim replay = (%+v, %v)", replay, err)
	}
	if _, err := startRebindItem(t, &fixture, store, items[ccPolicyID]); !errors.Is(err, ErrTargetBusy) {
		t.Fatalf("CC start while the reclaim holds the node = %v, want ErrTargetBusy", err)
	}
	fixture.now = fixture.now.Add(2 * time.Second)
	completeProductionActivation(t, fixture, store, reclaimed.Candidate)
	assertCandidateStatus(t, fixture.pool, reclaimed.Candidate.ID, StatusPromoted, false)
	var active int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT active_policy_version FROM security_policy_site_bindings
		WHERE id=$1`, fixture.bindingID).Scan(&active); err != nil || active != wafInput.PolicyVersion {
		t.Fatalf("WAF active version = %d (%v), want %d", active, err, wafInput.PolicyVersion)
	}
	if status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF); err != nil ||
		status.PromotionFailure != nil {
		t.Fatalf("promoted status = (%+v, %v)", status.PromotionFailure, err)
	}

	// The CC then takes the node and is promoted too.
	fixture.now = fixture.now.Add(rebindGrace + time.Second)
	cc, found = rebindItemsByKind(t, &fixture, store)[ccPolicyID]
	if !found {
		t.Fatal("CC binding no longer loaded")
	}
	ccStarted, err := startRebindItem(t, &fixture, store, cc)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(2 * time.Second)
	completeProductionActivation(t, fixture, store, ccStarted.Candidate)
	if items := rebindItemsByKind(t, &fixture, store); len(items) != 0 {
		t.Fatalf("bindings still behind after both promotions: %+v", items)
	}
}

// Reclaims of one version are bounded: after promotionReclaimLimit reclaims
// fail as well the binding stays failed, the status says it is not retried,
// and a newer saved version is still started.
func TestPromotionReclaimIsBounded(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newClockedProductionStore(t, &fixture)
	input := prepareProductionStart(t, fixture, store, "bounded-waf", []uuid.UUID{fixture.canaryNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	candidate := started.Candidate
	for attempt := 1; ; attempt++ {
		supersedeAndRecover(t, &fixture, store, candidate)
		fixture.now = fixture.now.Add(rebindGrace + time.Second)
		item, found := rebindItemsByKind(t, &fixture, store)[fixture.policyID]
		if attempt > promotionReclaimLimit {
			if found {
				t.Fatalf("reclaim %d past the limit: %+v", attempt, item)
			}
			assertPromotionFailure(t, &fixture, store, attempt, false)
			break
		}
		assertPromotionFailure(t, &fixture, store, attempt, true)
		if !found || item.reclaim != attempt {
			t.Fatalf("reclaim %d item = %+v (found %v)", attempt, item, found)
		}
		reclaimed, err := startRebindItem(t, &fixture, store, item)
		if err != nil {
			t.Fatalf("reclaim %d: %v", attempt, err)
		}
		candidate = reclaimed.Candidate
	}

	// A version saved afterwards is an ordinary rebind again.
	saveFixtureRevision(t, fixture, input.PolicyVersion+1, fixture.now.Add(-time.Minute))
	item, found := rebindItemsByKind(t, &fixture, store)[fixture.policyID]
	if !found || item.reclaim != 0 || item.policyRevision != input.PolicyVersion+1 {
		t.Fatalf("newer saved version item = %+v (found %v)", item, found)
	}
	assertPromotionFailure(t, &fixture, store, promotionReclaimLimit+1, true)
}

// A candidate that failed on its node (not at promotion) is not reclaimed:
// the same version would fail the same way; a newer save or the operator
// starts it again.
func TestNodeFailedCandidateIsNotReclaimed(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newClockedProductionStore(t, &fixture)
	input := prepareProductionStart(t, fixture, store, "node-failed-waf", []uuid.UUID{fixture.canaryNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := markPartialCandidateLoaded(t, fixture, started.Candidate, fixture.canaryNodeID); err != nil {
		t.Fatal(err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	if expired, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "node-failed-expire")); err != nil || expired.Candidate.Status != StatusExpired {
		t.Fatalf("expire = (%+v, %v)", expired, err)
	}
	newer := insertReleasableConfig(t, fixture, "node-failed-newer")
	applyReleasableConfig(t, fixture, fixture.canaryNodeID, newer, fixture.now)
	if recovered, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "node-failed-recover")); err != nil || recovered.Action != string(actionRecover) {
		t.Fatalf("recover = (%+v, %v)", recovered, err)
	}
	fixture.now = fixture.now.Add(rebindGrace + time.Second)
	if item, found := rebindItemsByKind(t, &fixture, store)[fixture.policyID]; found {
		t.Fatalf("expired candidate reclaimed: %+v", item)
	}
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil || status.PromotionFailure != nil {
		t.Fatalf("expired candidate status = (%+v, %v)", status.PromotionFailure, err)
	}
}

// saveFixtureRevision saves the fixture library at revision (a copy of the
// latest document) as the rules page would.
func saveFixtureRevision(t *testing.T, fixture activationFixture, revision int64, savedAt time.Time) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
		 SELECT policy_id,$2,jsonb_set(document,'{version}',to_jsonb($2::bigint)),created_by_user_id,$3 FROM security_policy_versions
		 WHERE policy_id=$1 AND revision=$2::bigint-1`,
		`UPDATE security_policies SET revision=$2,updated_at=$3 WHERE id=$1`,
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement, fixture.policyID, revision, savedAt); err != nil {
			t.Fatal(err)
		}
	}
}
