//go:build integration

package edgedeployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// /
// the operator reconciled a rollback_failed first apply without a version
// (operator_confirmed, null) although the node kept serving it; the agent
// holds that version's access records. The null reconciliation lifted the
// node's hold, so the waiting automatic publication reached the node at once
// and became healthy. The supplemental confirmation of the source
// deployment's own version still applies: it appends only the reconciliation
// record (the node state keeps the later deployment's version) and the
// scope's next apply command lists the source version in
// released_config_version_ids. A scope not reconciled without a version,
// another version, or an unverifiable source artifact is refused.
func TestSupplementalConfirmationAfterALaterDeploymentReleasesTheSourceVersion(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	platformScopeID := seedCommandScope(t, pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	scopeID, userID := seedEdgeScope(t, pool)
	source := persistTestConfig(t, store, testConfigRequest(t, scopeID, "supplement-source", "supplement-key", fixture.publicKey, fixture.privateKey, []byte("generation 1")))
	other := persistTestConfig(t, store, testConfigRequest(t, scopeID, "supplement-other", "supplement-key", fixture.publicKey, fixture.privateKey, []byte("another version")))
	next := persistTestConfig(t, store, testConfigRequest(t, scopeID, "supplement-next", "supplement-key", fixture.publicKey, fixture.privateKey, []byte("automatic publication")))
	later := persistTestConfig(t, store, testConfigRequest(t, scopeID, "supplement-later", "supplement-key", fixture.publicKey, fixture.privateKey, []byte("next publication")))
	nodeID, confirmedNodeID, unverifiableNodeID := uuid.New(), uuid.New(), uuid.New()
	nodes := []uuid.UUID{nodeID, confirmedNodeID, unverifiableNodeID}
	for _, id := range nodes {
		seedEdgeNode(t, pool, scopeID, userID, id)
	}
	failed, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, source.ID, nodes, "supplement-first-apply"))
	if err != nil {
		t.Fatal(err)
	}
	deployments := map[uuid.UUID]uuid.UUID{}
	for _, deployment := range failed.Rollout.Deployments {
		deployments[deployment.NodeID] = deployment.ID
		for _, state := range []string{"delivered", "staged", "prechecked", "reverting", "rollback_failed"} {
			advanceDeploymentState(t, pool, deployment.ID, state)
		}
		markRollbackFailedReconciliation(t, pool, deployment.NodeID, scopeID, deployment.ID)
	}

	command := func(node uuid.UUID, observed *uuid.UUID, key string) ReconcileNodeConfigCommandRequest {
		return ReconcileNodeConfigCommandRequest{
			Actor: actor, NodeID: node, ConfigurationScopeID: scopeID, SourceDeploymentID: deployments[node],
			SourceDeploymentAttempt: 1, ObservedConfigVersionID: observed,
			Resolution: ReconciliationOperatorConfirmed, Evidence: "operator verified the node still serves the source release",
			IdempotencyKey: key, RequestID: uuid.NewString(),
		}
	}
	reconcile := func(request ReconcileNodeConfigCommandRequest) (ReconcileNodeConfigResult, error) {
		return store.ReconcileNodeConfigCommand(context.Background(), request)
	}
	for _, node := range []uuid.UUID{nodeID, unverifiableNodeID} {
		if _, err := reconcile(command(node, nil, "supplement-null-"+node.String())); err != nil {
			t.Fatalf("reconcile node %s without a version: %v", node, err)
		}
	}
	if _, err := reconcile(command(confirmedNodeID, &source.ID, "supplement-direct")); err != nil {
		t.Fatalf("confirm the source version directly: %v", err)
	}

	// The automatic publication waiting on the reconciliation reaches the
	// nodes at once: its command names no previous version and releases
	// nothing, and it becomes healthy (the scope's current version).
	automatic, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, next.ID, []uuid.UUID{nodeID, unverifiableNodeID}, "supplement-automatic"))
	if err != nil {
		t.Fatal(err)
	}
	for _, deployment := range automatic.Rollout.Deployments {
		if deployment.Command.PreviousConfigVersionId != nil || len(deployment.Command.ReleasedConfigVersionIds) != 0 {
			t.Fatalf("automatic publication command after a null reconciliation = %+v", deployment.Command)
		}
		for _, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
			advanceDeploymentState(t, pool, deployment.ID, state)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_version_id=$3,revision=revision+1
			WHERE node_id=$1 AND configuration_scope_id=$2`, deployment.NodeID, scopeID, next.ID); err != nil {
			t.Fatal(err)
		}
	}
	dropSourceArtifactBinding(t, pool, deployments[unverifiableNodeID])

	for _, refused := range []struct {
		name    string
		request ReconcileNodeConfigCommandRequest
		want    error
	}{
		{"another version of the scope", command(nodeID, &other.ID, "supplement-other-version"), ErrReconciliationObservedNotSource},
		{"the later deployment's version", command(nodeID, &next.ID, "supplement-next-version"), ErrReconciliationObservedNotSource},
		{"not reconciled without a version", command(confirmedNodeID, &source.ID, "supplement-already"), ErrReconciliationSupplementNotEligible},
		{"unverifiable source artifact", command(unverifiableNodeID, &source.ID, "supplement-unverifiable"), ErrReconciliationSourceUnverifiable},
	} {
		if _, err := reconcile(refused.request); !errors.Is(err, refused.want) {
			t.Fatalf("%s: error = %v, want %v", refused.name, err, refused.want)
		}
	}
	assertSupplementFacts(t, pool, nodeID, 1)
	stateBefore := readSupplementNodeState(t, pool, nodeID, scopeID)

	supplement := command(nodeID, &source.ID, "supplement-confirm")
	supplement.Evidence = supplementEvidence
	confirmed, err := reconcile(supplement)
	if err != nil || confirmed.Replayed || confirmed.Reconciliation.ObservedConfigVersionID == nil ||
		*confirmed.Reconciliation.ObservedConfigVersionID != source.ID ||
		confirmed.Reconciliation.PreviousConfigVersionID == nil || *confirmed.Reconciliation.PreviousConfigVersionID != next.ID {
		t.Fatalf("supplemental confirmation = (%+v, %v)", confirmed, err)
	}
	// Only the reconciliation record: current, previous and revision stay.
	if after := readSupplementNodeState(t, pool, nodeID, scopeID); after != stateBefore {
		t.Fatalf("node state after the supplement = %+v, want unchanged %+v", after, stateBefore)
	}
	var nullReconciliationID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM node_config_reconciliations
		WHERE node_id=$1 AND observed_config_version_id IS NULL`, nodeID).Scan(&nullReconciliationID); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := pool.QueryRow(t.Context(), `SELECT payload FROM audit_events
		WHERE action='edge_config.reconcile_supplement' AND resource_id=$1`, nodeID.String()).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var audit map[string]any
	if err := json.Unmarshal(payload, &audit); err != nil {
		t.Fatal(err)
	}
	if audit["recovery_mode"] != "rollback_failed_source_serving_supplement" || audit["operator_attestation"] != supplementAttestation ||
		audit["supplements_reconciliation_id"] != nullReconciliationID.String() ||
		audit["observed_config_version_id"] != source.ID.String() {
		t.Fatalf("supplement audit payload = %s", payload)
	}

	// A retry of the same request replays; a second supplement is refused.
	if replayed, err := reconcile(supplement); err != nil || !replayed.Replayed || replayed.Reconciliation.ID != confirmed.Reconciliation.ID {
		t.Fatalf("supplement retry = (%+v, %v), want the stored fact", replayed, err)
	}
	if _, err := reconcile(command(nodeID, &source.ID, "supplement-again")); !errors.Is(err, ErrReconciliationSupplementNotEligible) {
		t.Fatalf("second supplement: error = %v, want ErrReconciliationSupplementNotEligible", err)
	}
	// Only null -> the source version: no way back to null either.
	if _, err := reconcile(command(nodeID, nil, "supplement-back-to-null")); !errors.Is(err, ErrReconciliationNotRequired) {
		t.Fatalf("back to no version: error = %v, want ErrReconciliationNotRequired", err)
	}
	assertSupplementFacts(t, pool, nodeID, 2)

	// The scope's next apply commands: the supplemented node and the directly
	// confirmed one list the source version as released; the node reconciled
	// without a version and never supplemented lists nothing. previous stays
	// the version in effect.
	republished, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, later.ID, nodes, "supplement-next-apply"))
	if err != nil || len(republished.Rollout.Deployments) != len(nodes) {
		t.Fatalf("next publication = (%+v, %v)", republished, err)
	}
	for _, deployment := range republished.Rollout.Deployments {
		released := deployment.Command.ReleasedConfigVersionIds
		previous := deployment.Command.GetPreviousConfigVersionId()
		switch deployment.NodeID {
		case nodeID:
			if !slices.Equal(released, []string{source.ID.String()}) || previous != next.ID.String() {
				t.Fatalf("supplemented node command released %v previous %q", released, previous)
			}
		case confirmedNodeID:
			if !slices.Equal(released, []string{source.ID.String()}) || previous != source.ID.String() {
				t.Fatalf("directly confirmed node command released %v previous %q", released, previous)
			}
		case unverifiableNodeID:
			if len(released) != 0 || previous != next.ID.String() {
				t.Fatalf("unsupplemented node command released %v previous %q", released, previous)
			}
		}
	}
}

// (two rollback failures): the scope's
// first apply on the node failed its rollback and was reconciled without a
// version; a second apply failed its rollback too and was reconciled with its
// own version. The first source may still be supplemented (the other
// source's reconciliation does not end it), once, for this scope only; the
// next apply command lists both versions as released.
func TestSupplementalConfirmationOfTheOlderOfTwoRollbackFailures(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	platformScopeID := seedCommandScope(t, pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	scopeID, userID := seedEdgeScope(t, pool)
	otherScopeID, _ := seedEdgeScope(t, pool)
	first := persistTestConfig(t, store, testConfigRequest(t, scopeID, "two-first", "two-key", fixture.publicKey, fixture.privateKey, []byte("generation 1")))
	second := persistTestConfig(t, store, testConfigRequest(t, scopeID, "two-second", "two-key", fixture.publicKey, fixture.privateKey, []byte("generation 2")))
	later := persistTestConfig(t, store, testConfigRequest(t, scopeID, "two-later", "two-key", fixture.publicKey, fixture.privateKey, []byte("next publication")))
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	failApply := func(config ConfigVersion, key string) uuid.UUID {
		t.Helper()
		created, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, config.ID, []uuid.UUID{nodeID}, key))
		if err != nil || len(created.Rollout.Deployments) != 1 {
			t.Fatalf("rollout %s = (%+v, %v)", key, created, err)
		}
		deploymentID := created.Rollout.Deployments[0].ID
		for _, state := range []string{"delivered", "staged", "prechecked", "reverting", "rollback_failed"} {
			advanceDeploymentState(t, pool, deploymentID, state)
		}
		markRollbackFailedReconciliation(t, pool, nodeID, scopeID, deploymentID)
		return deploymentID
	}
	command := func(scope, source uuid.UUID, observed *uuid.UUID, key string) ReconcileNodeConfigCommandRequest {
		return ReconcileNodeConfigCommandRequest{
			Actor: actor, NodeID: nodeID, ConfigurationScopeID: scope, SourceDeploymentID: source,
			SourceDeploymentAttempt: 1, ObservedConfigVersionID: observed,
			Resolution: ReconciliationOperatorConfirmed, Evidence: "operator verified the node still serves the source release",
			IdempotencyKey: key, RequestID: uuid.NewString(),
		}
	}
	reconcile := func(request ReconcileNodeConfigCommandRequest) (ReconcileNodeConfigResult, error) {
		return store.ReconcileNodeConfigCommand(context.Background(), request)
	}

	firstSource := failApply(first, "two-first-apply")
	if _, err := reconcile(command(scopeID, firstSource, nil, "two-first-null")); err != nil {
		t.Fatalf("reconcile the first failure without a version: %v", err)
	}
	secondSource := failApply(second, "two-second-apply")
	if _, err := reconcile(command(scopeID, secondSource, &second.ID, "two-second-confirm")); err != nil {
		t.Fatalf("confirm the second failure's own version: %v", err)
	}
	stateBefore := readSupplementNodeState(t, pool, nodeID, scopeID)

	if _, err := reconcile(command(otherScopeID, firstSource, &first.ID, "two-other-scope")); !errors.Is(err, ErrReconciliationNotRequired) {
		t.Fatalf("supplement under another scope: error = %v, want ErrReconciliationNotRequired", err)
	}
	if _, err := reconcile(command(scopeID, secondSource, &second.ID, "two-second-again")); !errors.Is(err, ErrReconciliationSupplementNotEligible) {
		t.Fatalf("supplement of a source confirmed with its version: error = %v, want ErrReconciliationSupplementNotEligible", err)
	}
	if _, err := reconcile(command(scopeID, firstSource, &second.ID, "two-wrong-version")); !errors.Is(err, ErrReconciliationObservedNotSource) {
		t.Fatalf("supplement naming the other source's version: error = %v, want ErrReconciliationObservedNotSource", err)
	}
	supplementRequest := command(scopeID, firstSource, &first.ID, "two-first-supplement")
	supplementRequest.Evidence = supplementEvidence
	supplemented, err := reconcile(supplementRequest)
	if err != nil || supplemented.Replayed {
		t.Fatalf("supplement of the older failure = (%+v, %v)", supplemented, err)
	}
	if after := readSupplementNodeState(t, pool, nodeID, scopeID); after != stateBefore {
		t.Fatalf("node state after the supplement = %+v, want unchanged %+v", after, stateBefore)
	}
	if _, err := reconcile(command(scopeID, firstSource, &first.ID, "two-first-again")); !errors.Is(err, ErrReconciliationSupplementNotEligible) {
		t.Fatalf("second supplement of the same source: error = %v, want ErrReconciliationSupplementNotEligible", err)
	}
	assertSupplementFacts(t, pool, nodeID, 3)

	next, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, later.ID, []uuid.UUID{nodeID}, "two-next-apply"))
	if err != nil || len(next.Rollout.Deployments) != 1 {
		t.Fatalf("next publication = (%+v, %v)", next, err)
	}
	want := []string{first.ID.String(), second.ID.String()}
	slices.Sort(want)
	if released := next.Rollout.Deployments[0].Command.ReleasedConfigVersionIds; !slices.Equal(released, want) {
		t.Fatalf("next apply command released %v, want %v", released, want)
	}
}

// two rollback failures of the scope
// on the node were reconciled without a version, then a publication became
// healthy (current version c3). The scope offers the older source first, then
// the newer one; each supplement records that the source ran on the node
// after its rollback failed, the current version stays c3, and the next apply
// command releases both versions.
func TestHistoricalSourcesAreSupplementedOldestFirst(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	clock := integrationClock
	store.now = func() time.Time { return clock }
	platformScopeID := seedCommandScope(t, pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	scopeID, userID := seedEdgeScope(t, pool)
	first := persistTestConfig(t, store, testConfigRequest(t, scopeID, "hist-first", "hist-key", fixture.publicKey, fixture.privateKey, []byte("generation 1")))
	second := persistTestConfig(t, store, testConfigRequest(t, scopeID, "hist-second", "hist-key", fixture.publicKey, fixture.privateKey, []byte("generation 2")))
	current := persistTestConfig(t, store, testConfigRequest(t, scopeID, "hist-current", "hist-key", fixture.publicKey, fixture.privateKey, []byte("generation 3")))
	later := persistTestConfig(t, store, testConfigRequest(t, scopeID, "hist-later", "hist-key", fixture.publicKey, fixture.privateKey, []byte("generation 4")))
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	rollout := func(config ConfigVersion, key string, states ...string) uuid.UUID {
		t.Helper()
		created, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, config.ID, []uuid.UUID{nodeID}, key))
		if err != nil || len(created.Rollout.Deployments) != 1 {
			t.Fatalf("rollout %s = (%+v, %v)", key, created, err)
		}
		for _, state := range states {
			advanceDeploymentState(t, pool, created.Rollout.Deployments[0].ID, state)
		}
		return created.Rollout.Deployments[0].ID
	}
	request := func(source uuid.UUID, observed *uuid.UUID, key, evidence string) ReconcileNodeConfigCommandRequest {
		return ReconcileNodeConfigCommandRequest{
			Actor: actor, NodeID: nodeID, ConfigurationScopeID: scopeID, SourceDeploymentID: source,
			SourceDeploymentAttempt: 1, ObservedConfigVersionID: observed,
			Resolution: ReconciliationOperatorConfirmed, Evidence: evidence,
			IdempotencyKey: key, RequestID: uuid.NewString(),
		}
	}
	sources := []uuid.UUID{}
	for index, config := range []ConfigVersion{first, second} {
		source := rollout(config, fmt.Sprintf("hist-apply-%d", index), "delivered", "staged", "prechecked", "reverting", "rollback_failed")
		markRollbackFailedReconciliation(t, pool, nodeID, scopeID, source)
		if _, err := store.ReconcileNodeConfigCommand(context.Background(),
			request(source, nil, fmt.Sprintf("hist-null-%d", index), "operator confirmed; node state unconfirmed")); err != nil {
			t.Fatalf("reconcile failure %d without a version: %v", index, err)
		}
		sources = append(sources, source)
		clock = clock.Add(time.Minute)
	}
	healthy := rollout(current, "hist-current", "delivered", "staged", "prechecked", "activated", "healthy")
	if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_version_id=$3,revision=revision+1
		WHERE node_id=$1 AND configuration_scope_id=$2`, nodeID, scopeID, current.ID); err != nil {
		t.Fatal(err)
	}
	stateBefore := readSupplementNodeState(t, pool, nodeID, scopeID)

	inventory := nodepresence.NewInventory(pool, nil, time.Minute, func() time.Time { return clock }, nil)
	offered := func(step string) *nodepresence.ScopeSourceConfirmation {
		t.Helper()
		read, err := inventory.ConfigurationScopes(context.Background(), scopeID, nodeID)
		if err != nil || len(read.Scopes) != 1 {
			t.Fatalf("%s: configuration scopes = (%+v, %v)", step, read, err)
		}
		if read.Scopes[0].LatestDeployment == nil || read.Scopes[0].LatestDeployment.DeploymentID != healthy {
			t.Fatalf("%s: latest deployment = %+v, want the healthy publication", step, read.Scopes[0].LatestDeployment)
		}
		return read.Scopes[0].SourceConfirmation
	}
	for index, config := range []ConfigVersion{first, second} {
		got := offered(fmt.Sprintf("before supplement %d", index))
		if got == nil || got.SourceDeploymentID != sources[index] || got.ConfigVersionID != config.ID {
			t.Fatalf("offered source %d = %+v, want %s of %s", index, got, sources[index], config.ID)
		}
		supplement := request(sources[index], &config.ID, fmt.Sprintf("hist-supplement-%d", index), supplementEvidence)
		if _, err := store.ReconcileNodeConfigCommand(context.Background(), supplement); err != nil {
			t.Fatalf("supplement source %d: %v", index, err)
		}
		if after := readSupplementNodeState(t, pool, nodeID, scopeID); after != stateBefore {
			t.Fatalf("node state after supplement %d = %+v, want unchanged %+v", index, after, stateBefore)
		}
	}
	if got := offered("after both supplements"); got != nil {
		t.Fatalf("source offered after both supplements: %+v", got)
	}
	var attestations []string
	rows, err := pool.Query(t.Context(), `SELECT payload->>'operator_attestation' FROM audit_events
		WHERE action='edge_config.reconcile_supplement' AND resource_id=$1`, nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var attestation string
		if err := rows.Scan(&attestation); err != nil {
			t.Fatal(err)
		}
		attestations = append(attestations, attestation)
	}
	rows.Close()
	if len(attestations) != 2 || attestations[0] != supplementAttestation || attestations[1] != supplementAttestation {
		t.Fatalf("supplement attestations = %q", attestations)
	}

	next, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, later.ID, []uuid.UUID{nodeID}, "hist-next"))
	if err != nil || len(next.Rollout.Deployments) != 1 {
		t.Fatalf("next publication = (%+v, %v)", next, err)
	}
	want := []string{first.ID.String(), second.ID.String()}
	slices.Sort(want)
	command := next.Rollout.Deployments[0].Command
	if !slices.Equal(command.ReleasedConfigVersionIds, want) || command.GetPreviousConfigVersionId() != current.ID.String() {
		t.Fatalf("next apply command released %v previous %q, want %v and %s", command.ReleasedConfigVersionIds,
			command.GetPreviousConfigVersionId(), want, current.ID)
	}
}

// supplementEvidence is what the operator records for a supplemental
// confirmation: the source release ran on the node after its rollback failed
// .
const supplementEvidence = "operator verified on the node that the source release ran there after its rollback failed; current version unchanged"

type supplementNodeState struct {
	required          bool
	current, previous uuid.UUID
	revision          int64
}

func readSupplementNodeState(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID uuid.UUID) supplementNodeState {
	t.Helper()
	var state supplementNodeState
	var current, previous *uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT reconciliation_required,current_config_version_id,previous_config_version_id,revision
		FROM node_config_state WHERE node_id=$1 AND configuration_scope_id=$2`, nodeID, scopeID).Scan(
		&state.required, &current, &previous, &state.revision); err != nil {
		t.Fatal(err)
	}
	if current != nil {
		state.current = *current
	}
	if previous != nil {
		state.previous = *previous
	}
	return state
}

// assertSupplementFacts: refused requests append no reconciliation.
func assertSupplementFacts(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, want int) {
	t.Helper()
	var facts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_config_reconciliations WHERE node_id=$1`, nodeID).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if facts != want {
		t.Fatalf("node %s has %d reconciliation facts, want %d", nodeID, facts, want)
	}
}
