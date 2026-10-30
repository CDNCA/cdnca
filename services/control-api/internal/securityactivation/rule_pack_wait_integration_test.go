//go:build integration

package securityactivation

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// mountActivationRulePack mounts the system-sqli test pack on the fixture's
// site (a platform operator imports it, the site enables it, the tenant
// publishes the mounts) and returns its digest. Nothing applied it on a node.
func mountActivationRulePack(t *testing.T, fixture activationFixture) string {
	t.Helper()
	platformScopeID, platformUserID := uuid.Nil, uuid.New()
	// One platform scope per database (access_scopes_single_platform_idx): reuse the fixture's.
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).
		Scan(&platformScopeID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		platformScopeID = uuid.New()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID); err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'rule-pack-operator','operator','hash')`,
			[]any{platformUserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platformScopeID, platformUserID}},
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	packs := rulepackcontrol.NewService(fixture.pool, func() time.Time { return fixture.now })
	platform := rulepackcontrol.Actor{UserID: platformUserID, ScopeID: platformScopeID, ScopeKind: "platform"}
	tenant := rulepackcontrol.Actor{UserID: fixture.actor.UserID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-sqli.json"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := packs.Import(t.Context(), platform, content)
	if err != nil {
		t.Fatalf("import pack: %v", err)
	}
	site := fixture.siteID
	for _, input := range []rulepackcontrol.OverrideInput{
		{Level: rulepack.LevelPlatform, PackID: pack.PackID, State: rulepack.StateDisabled, AllowLower: true},
		{Level: rulepack.LevelSite, LevelObjectID: &site, PackID: pack.PackID, State: rulepack.StateEnabled},
	} {
		if _, _, err := packs.PutOverride(t.Context(), platform, input); err != nil {
			t.Fatalf("override %+v: %v", input, err)
		}
	}
	published, err := packs.PublishSite(t.Context(), tenant, site)
	if err != nil || published.Published == nil || len(published.Published.Security.Mounts) != 1 {
		t.Fatalf("publish mounts: %+v %v", published.Published, err)
	}
	return published.Published.Security.Mounts[0].SHA256
}

// applyActivationRulePack records that nodeID applied the pack from its node
// artifact set, as edgestatus writes it from the node's receipt.
func applyActivationRulePack(t *testing.T, fixture activationFixture, nodeID uuid.UUID, digest string) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO node_artifact_applied_items(
		node_id,artifact_id,version,item_revision,media_type,sha256,set_revision,applied_at)
		VALUES($1,$2,'1.0.0',1,$3,$4,1,$5) ON CONFLICT DO NOTHING`, nodeID, "rule_pack/"+digest,
		artifactset.MediaTypeRulePack, digest, fixture.now); err != nil {
		t.Fatal(err)
	}
}

type ruleWaitRow struct {
	id        uuid.UUID
	status    string
	kind      string
	blocking  []uuid.UUID
	packs     []string
	candidate *uuid.UUID
}

func ruleWaits(t *testing.T, fixture activationFixture) []ruleWaitRow {
	t.Helper()
	rows, err := fixture.pool.Query(t.Context(), `SELECT id,status,wait_kind,blocking_node_ids,COALESCE(rule_pack_sha256,'{}'),
		resumed_candidate_id FROM security_activation_capability_waits WHERE site_id=$1 ORDER BY created_at,id`, fixture.siteID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var waits []ruleWaitRow
	for rows.Next() {
		var row ruleWaitRow
		if err := rows.Scan(&row.id, &row.status, &row.kind, &row.blocking, &row.packs, &row.candidate); err != nil {
			t.Fatal(err)
		}
		waits = append(waits, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return waits
}

func startRulePackActivation(t *testing.T, fixture activationFixture, store *Store, key string) (StartInput, error) {
	t.Helper()
	input := prepareProductionStart(t, fixture, store, key, []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	input.SiteRuntimeSchema = ""
	_, err := store.Start(t.Context(), fixture.actor, input)
	return input, err
}

// TestActivationWaitsForRulePacksAndResumesOnceApplied (sa-rulepack-wait):
// the site mounts a rule pack neither target node has applied. Activating
// its WAF policy
//   - is refused with rule_pack_unavailable (auto_resume set), nothing
//     published, and the request recorded as a rule pack wait naming both
//     nodes and the pack, with an audit event;
//   - keeps waiting while only one node has applied the pack;
//   - is started by the activation worker once both nodes' receipts hold
//     the pack, and runs canary → expand → promoted (nodes healthy);
//   - is started once: further worker passes start nothing more.
func TestActivationWaitsForRulePacksAndResumesOnceApplied(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	digest := mountActivationRulePack(t, fixture.activationFixture)

	input, err := startRulePackActivation(t, fixture.activationFixture, store, "rule-pack-refused")
	var refusal *edgepublish.RulePackUnavailableError
	if !errors.As(err, &refusal) || !refusal.AutoResume || !slices.Equal(refusal.Required, []string{digest}) ||
		len(refusal.OtherNodeIDs) != 1 {
		t.Fatalf("activation to nodes without the pack = %v (%+v)", err, refusal)
	}
	var candidates int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_activation_candidates
		WHERE site_id=$1`, fixture.siteID).Scan(&candidates); err != nil || candidates != 0 {
		t.Fatalf("refused activation persisted %d candidates, %v", candidates, err)
	}
	waits := ruleWaits(t, fixture.activationFixture)
	if len(waits) != 1 || waits[0].status != "waiting" || waits[0].kind != waitKindRulePack ||
		len(waits[0].blocking) != 2 || !slices.Equal(waits[0].packs, []string{digest}) {
		t.Fatalf("waits after the refusal = %+v", waits)
	}
	var audits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1
		AND action='security_policy.activation.wait' AND resource_id=$2 AND result='failure'
		AND reason_code='rule_pack_unavailable' AND payload->>'wait_kind'='rule_pack'`,
		fixture.scopeID, waits[0].id.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("wait audit events = %d, %v", audits, err)
	}
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil || status.CapabilityWait == nil || status.CapabilityWait.WaitKind != waitKindRulePack ||
		!slices.Equal(status.CapabilityWait.RulePacks, []string{digest}) || status.CapabilityWait.PolicyVersion != input.PolicyVersion {
		t.Fatalf("status wait = %+v, %v", status.CapabilityWait, err)
	}

	worker, err := NewWorker(store)
	if err != nil {
		t.Fatal(err)
	}
	applyActivationRulePack(t, fixture.activationFixture, fixture.canaryNodeID, digest)
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile with one node holding the pack: %v", err)
	}
	if waits := ruleWaits(t, fixture.activationFixture); len(waits) != 1 || waits[0].status != "waiting" ||
		!slices.Equal(waits[0].blocking, []uuid.UUID{fixture.expandNodeID}) {
		t.Fatalf("waits with one node holding the pack = %+v", waits)
	}

	applyActivationRulePack(t, fixture.activationFixture, fixture.expandNodeID, digest)
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile once both nodes hold the pack: %v", err)
	}
	waits = ruleWaits(t, fixture.activationFixture)
	if len(waits) != 1 || waits[0].status != "resumed" || waits[0].candidate == nil {
		t.Fatalf("waits after the packs arrived = %+v", waits)
	}
	candidate, err := store.Get(t.Context(), fixture.actor, *waits[0].candidate)
	if err != nil || candidate.Status != StatusClaimed || candidate.LastClaimedPolicyVersion != input.PolicyVersion {
		t.Fatalf("resumed candidate = %+v, %v", candidate, err)
	}

	// Idempotent: further passes start nothing more.
	for range 2 {
		if err := worker.reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_activation_candidates
		WHERE site_id=$1`, fixture.siteID).Scan(&candidates); err != nil || candidates != 1 {
		t.Fatalf("candidates after repeated passes = %d, %v", candidates, err)
	}

	markV2PhaseHealthy(t, fixture, candidate, "canary")
	canary, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "rule-pack-canary"))
	if err != nil || canary.Action != string(actionExpand) {
		t.Fatalf("canary Reconcile = (%+v, %v)", canary, err)
	}
	markV2PhaseHealthy(t, fixture, candidate, "expand")
	final, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "rule-pack-expand"))
	if err != nil || final.Action != string(actionPromote) || final.Candidate.Status != StatusPromoted {
		t.Fatalf("expand Reconcile = (%+v, %v)", final, err)
	}
	if status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF); err != nil ||
		status.CapabilityWait != nil {
		t.Fatalf("status still waiting after the resumed activation: %+v, %v", status.CapabilityWait, err)
	}
}

// TestRulePackWaitResumesOnceAfterAnInterruptedPass: a pass that started the
// waiting request but stopped before marking the wait resumed (crash) does
// not start it again; the next pass marks the wait resumed with the
// candidate already started.
func TestRulePackWaitResumesOnceAfterAnInterruptedPass(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	digest := mountActivationRulePack(t, fixture.activationFixture)
	if _, err := startRulePackActivation(t, fixture.activationFixture, store, "rule-pack-interrupted"); !errors.As(err,
		new(*edgepublish.RulePackUnavailableError)) {
		t.Fatalf("refusal = %v", err)
	}
	for _, nodeID := range []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID} {
		applyActivationRulePack(t, fixture.activationFixture, nodeID, digest)
	}
	waits := ruleWaits(t, fixture.activationFixture)
	if len(waits) != 1 {
		t.Fatalf("waits = %+v", waits)
	}
	if err := store.resumeCapabilityWaits(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Undo only the status update, as if the pass had stopped right after Start.
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE security_activation_capability_waits
		SET status='waiting',resumed_candidate_id=NULL WHERE id=$1`, waits[0].id); err != nil {
		t.Fatal(err)
	}
	if err := store.resumeCapabilityWaits(t.Context()); err != nil {
		t.Fatal(err)
	}
	var candidates int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_activation_candidates
		WHERE site_id=$1`, fixture.siteID).Scan(&candidates); err != nil || candidates != 1 {
		t.Fatalf("candidates after the repeated pass = %d, %v", candidates, err)
	}
	if waits := ruleWaits(t, fixture.activationFixture); len(waits) != 1 || waits[0].status != "resumed" || waits[0].candidate == nil {
		t.Fatalf("waits after the repeated pass = %+v", waits)
	}
}

// TestNewActivationSupersedesRulePackWait: a later activation the user starts
// for the site and policy kind replaces the rule pack wait (a newer refusal
// records a new wait and supersedes the old one; a started activation
// supersedes it), and the superseded wait is never resumed.
func TestNewActivationSupersedesRulePackWait(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	digest := mountActivationRulePack(t, fixture.activationFixture)
	if _, err := startRulePackActivation(t, fixture.activationFixture, store, "rule-pack-first"); !errors.As(err,
		new(*edgepublish.RulePackUnavailableError)) {
		t.Fatalf("first refusal = %v", err)
	}
	first := ruleWaits(t, fixture.activationFixture)
	if len(first) != 1 || first[0].status != "waiting" {
		t.Fatalf("first wait = %+v", first)
	}
	// The user saves again (a new policy version) and activates again.
	if _, err := startRulePackActivation(t, fixture.activationFixture, store, "rule-pack-second"); !errors.As(err,
		new(*edgepublish.RulePackUnavailableError)) {
		t.Fatalf("second refusal = %v", err)
	}
	// The store clock is fixed (fixture.now), so both waits share created_at
	// and the ORDER BY falls back to the random id: match by id, not position.
	waits := ruleWaits(t, fixture.activationFixture)
	if len(waits) != 2 {
		t.Fatalf("waits after the second refusal = %+v", waits)
	}
	for _, wait := range waits {
		if want := map[bool]string{true: "superseded", false: "waiting"}[wait.id == first[0].id]; wait.status != want {
			t.Fatalf("waits after the second refusal = %+v", waits)
		}
	}
	// Once the packs arrived the user activates by hand before the worker:
	// that start supersedes the wait; the worker then starts nothing.
	for _, nodeID := range []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID} {
		applyActivationRulePack(t, fixture.activationFixture, nodeID, digest)
	}
	if _, err := startRulePackActivation(t, fixture.activationFixture, store, "rule-pack-manual"); err != nil {
		t.Fatalf("manual activation once the packs arrived: %v", err)
	}
	worker, err := NewWorker(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, wait := range ruleWaits(t, fixture.activationFixture) {
		if wait.status != "superseded" || wait.candidate != nil {
			t.Fatalf("wait %s after the manual activation = %+v", wait.id, wait)
		}
	}
	var candidates int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_activation_candidates
		WHERE site_id=$1`, fixture.siteID).Scan(&candidates); err != nil || candidates != 1 {
		t.Fatalf("candidates = %d, %v (only the manual activation)", candidates, err)
	}
}
