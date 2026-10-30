//go:build integration

package edgepublish_test

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// N15 (live-retest3): a node whose artifact set has not applied a rule pack
// the scope's sites mount is left out of the automatic publication. The
// capability hold audit names, per left-out node, what it lacks (feature,
// rule pack digest and pack_id@version); once the node's receipt applies the
// pack, the scope's latest release goes to it by itself and its
// node_config_state advances; a second announce queues nothing.
func TestAutomaticPublicationLeftOutForRulePackCatchesUpAfterReceipt(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	scope.EnableAutomaticPolicy(t, nodeA, nodeB)
	store := edgeautopublish.NewStore(scope.Pool)
	worker, err := edgeautopublish.NewWorker(store, scope.AutomaticService(t, store), edgeautopublish.WorkerConfig{
		WorkerID: "n15-auto", LeaseDuration: time.Minute, RetryDelay: 0})
	if err != nil {
		t.Fatal(err)
	}
	publish := func(trigger, key string) {
		t.Helper()
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			_, err := edgeautopublish.RequestRepublicationTx(t.Context(), tx, edgeautopublish.RepublishRequest{
				ScopeID: scope.ScopeID, Trigger: trigger, SourceResourceID: nodeA, SourceRequestID: key})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
			t.Fatalf("automatic worker (%s): worked=%v err=%v", key, worked, err)
		}
	}
	nodeConfig := func(nodeID uuid.UUID) uuid.UUID {
		t.Helper()
		var configID uuid.UUID
		if err := scope.Pool.QueryRow(t.Context(), `SELECT current_config_version_id FROM node_config_state
			WHERE node_id=$1 AND configuration_scope_id=$2`, nodeID, scope.ScopeID).Scan(&configID); err != nil {
			t.Fatal(err)
		}
		return configID
	}
	latestConfig := func() uuid.UUID {
		t.Helper()
		var configID uuid.UUID
		if err := scope.Pool.QueryRow(t.Context(), `SELECT config_version_id FROM edge_config_publications
			WHERE configuration_scope_id=$1 ORDER BY source_revision DESC LIMIT 1`, scope.ScopeID).Scan(&configID); err != nil {
			t.Fatal(err)
		}
		return configID
	}

	// Both nodes take the scope's first release (the site, no rule pack).
	publish(edgepublish.SystemTriggerLineGroup, "n15-initial")
	if first := scope.LatestPublication(t); !slices.Equal(first.NodeIDs, sortedNodes(nodeA, nodeB)) {
		t.Fatalf("initial publication went to %v", first.NodeIDs)
	}
	scope.SettleDeployments(t)
	initial := nodeConfig(nodeB)

	// The site mounts a rule pack; only A applied it (B's artifact set is stuck).
	digest, packName := scope.MountRulePack(t)
	scope.ApplyRulePack(t, nodeA, digest)
	publish(edgepublish.SystemTriggerRuleCatalog, "n15-rule-catalog")
	held := scope.LatestPublication(t)
	if !slices.Equal(held.NodeIDs, []uuid.UUID{nodeA}) {
		t.Fatalf("publication with the pack went to %v, want only %s", held.NodeIDs, nodeA)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_capability_publication_holds WHERE scope_id=$1
		AND source_revision=$2 AND published AND refused_node_ids=ARRAY[$3::uuid]`, held.SourceRevision, nodeB); got != 1 {
		t.Fatalf("hold leaving B out = %d", got)
	}
	// The audit says what B lacks.
	var payload []byte
	if err := scope.Pool.QueryRow(t.Context(), `SELECT payload FROM audit_events WHERE scope_id=$1
		AND action='edge_publication.capability_hold' AND (payload->>'source_revision')::bigint=$2`,
		scope.ScopeID, held.SourceRevision).Scan(&payload); err != nil {
		t.Fatalf("capability hold audit: %v", err)
	}
	var facts struct {
		RefusedNodes []struct {
			NodeID      uuid.UUID `json:"node_id"`
			Feature     string    `json:"feature"`
			RulePacks   []string  `json:"rule_packs"`
			RulePackIDs []string  `json:"rule_pack_ids"`
		} `json:"refused_nodes"`
	}
	if err := json.Unmarshal(payload, &facts); err != nil || len(facts.RefusedNodes) != 1 {
		t.Fatalf("capability hold audit payload %s: %v", payload, err)
	}
	if refusal := facts.RefusedNodes[0]; refusal.NodeID != nodeB || refusal.Feature == "" ||
		!slices.Equal(refusal.RulePacks, []string{digest}) || !slices.Equal(refusal.RulePackIDs, []string{packName}) {
		t.Fatalf("capability hold audit names %+v, want B lacking %s (%s)", refusal, digest, packName)
	}
	scope.SettleDeployments(t)
	if nodeConfig(nodeB) != initial {
		t.Fatal("left-out node B advanced before it had the pack")
	}

	// B's receipt applies the pack; the distributor's announce queues the
	// scope (the same call artifactsetdist makes) and its latest release goes
	// to both nodes.
	scope.ApplyRulePack(t, nodeB, digest)
	announce := func() int {
		t.Helper()
		queued := 0
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			var err error
			queued, err = edgeautopublish.RequestNodeReadyRepublicationsTx(t.Context(), tx, nodeB,
				"artifact-set-applied/"+nodeB.String()+"/1", edgepublish.SystemRepublicationDebounce)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return queued
	}
	if queued := announce(); queued != 1 {
		t.Fatalf("announce after B applied the pack queued %d scopes", queued)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("automatic worker after B's receipt: worked=%v err=%v", worked, err)
	}
	caught := scope.LatestPublication(t)
	if !slices.Equal(caught.NodeIDs, sortedNodes(nodeA, nodeB)) || caught.SourceRevision <= held.SourceRevision {
		t.Fatalf("catch-up publication went to %v at %d (held at %d)", caught.NodeIDs, caught.SourceRevision, held.SourceRevision)
	}
	scope.SettleDeployments(t)
	if got, want := nodeConfig(nodeB), latestConfig(); got != want {
		t.Fatalf("B runs %s, want the latest release %s", got, want)
	}
	// Bounded and idempotent: nothing waits on B any more.
	if queued := announce(); queued != 0 {
		t.Fatalf("second announce queued %d scopes", queued)
	}
}
