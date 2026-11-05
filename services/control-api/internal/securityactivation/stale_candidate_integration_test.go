//go:build integration

package securityactivation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// nextVersionStart clones the policy forward one version and returns a Start
// of it against the binding's current revision and active version.
func nextVersionStart(t *testing.T, fixture activationFixture, store *Store, key string, nodes []uuid.UUID) StartInput {
	t.Helper()
	var revision, bindingRevision, active int64
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		policy, err := store.clonePolicyVersionTx(t.Context(), tx, fixture.actor, fixture.scopeID,
			fixture.policyID, 2, uuid.NewString())
		revision = policy.Revision
		if err != nil {
			return err
		}
		return tx.QueryRow(t.Context(), `SELECT revision,COALESCE(active_policy_version,0)
			FROM security_policy_site_bindings WHERE id=$1`, fixture.bindingID).Scan(&bindingRevision, &active)
	}); err != nil {
		t.Fatal(err)
	}
	return StartInput{
		TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, PolicyID: fixture.policyID,
		PolicyVersion: revision, ExpectedBindingRevision: bindingRevision, ExpectedActivePolicyVersion: active,
		TargetNodeIDs: nodes, CanarySize: 1, IdempotencyKey: key, RequestID: uuid.NewString(),
		CorrelationID: uuid.NewString(), Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
		ExpiresAt: fixture.now.Add(10 * time.Minute),
	}
}

// A candidate failed while one node had loaded it, and that node
// then moved on to a newer ordinary configuration of the scope (a publication
// after the candidate's apply). Recovery used to require the node back on the
// recovery configuration or a proven rollback; neither ever happens then, so
// the candidate stayed open and every later version's Start was refused
// (security activation conflict, then the open-candidate unique index). The
// newer configuration does not run the candidate: it now counts as recovered.
// A configuration the node ran before the candidate's apply does not.
func TestFailedCandidateRecoversOnceNodeRunsNewerConfig(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	nodes := []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}
	first := prepareProductionStart(t, fixture, store, "stale-first", nodes, 1)
	started, err := store.Start(t.Context(), fixture.actor, first)
	if err != nil {
		t.Fatal(err)
	}
	loaded := started.Candidate.CanaryNodeIDs[0]
	if err := markPartialCandidateLoaded(t, fixture, started.Candidate, loaded); err != nil {
		t.Fatal(err)
	}
	// A configuration applied before the candidate's apply is no proof: the
	// node runs it when the candidate expires, and the candidate stays open.
	older := insertReleasableConfig(t, fixture, "older-ordinary")
	applyReleasableConfig(t, fixture, loaded, older, fixture.now.Add(-time.Hour))
	fixture.now = first.ExpiresAt.Add(time.Second)
	store = newProductionActivationStore(t, fixture)
	expired, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(started.Candidate, "stale-expire"))
	if err != nil || expired.Candidate.Status != StatusExpired || expired.Candidate.RecoveredAt != nil {
		t.Fatalf("expire = (%+v, %v)", expired, err)
	}
	if waited, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(expired.Candidate, "stale-older")); err != nil || waited.Candidate.RecoveredAt != nil {
		t.Fatalf("reconcile on an older configuration = (%+v, %v)", waited, err)
	}
	next := nextVersionStart(t, fixture, store, "stale-next", nodes)
	if _, err := store.Start(t.Context(), fixture.actor, next); !errors.Is(err, ErrConflict) {
		t.Fatalf("start while the failed candidate holds the targets = %v, want ErrConflict", err)
	}

	// An ordinary publication reaches the node after the candidate's apply.
	newer := insertReleasableConfig(t, fixture, "newer-ordinary")
	applyReleasableConfig(t, fixture, loaded, newer, fixture.now)
	recovered, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(expired.Candidate, "stale-newer"))
	if err != nil || recovered.Action != string(actionRecover) || recovered.Candidate.RecoveredAt == nil {
		t.Fatalf("reconcile on a newer configuration = (%+v, %v)", recovered, err)
	}
	// The binding takes the next version again.
	retry := nextVersionStart(t, fixture, store, "stale-retry", nodes)
	if result, err := store.Start(t.Context(), fixture.actor, retry); err != nil || result.Candidate.Status != StatusClaimed {
		t.Fatalf("start after recovery = (%+v, %v)", result, err)
	}
}

type releasableConfig struct {
	id     uuid.UUID
	digest [32]byte
}

// insertReleasableConfig adds a releasable configuration of the fixture
// scope, as an ordinary publication would.
func insertReleasableConfig(t *testing.T, fixture activationFixture, name string) releasableConfig {
	t.Helper()
	wire := []byte(name + "-artifact")
	out := releasableConfig{id: uuid.New(), digest: sha256.Sum256(wire)}
	snapshot := []byte(`{"name":"` + name + `"}`)
	snapshotDigest := sha256.Sum256(snapshot)
	signature := ed25519.Sign(fixture.signer.private, wire)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at)
			VALUES($1,$2,$3,$4,'activation-test','1','building',$5,$4,$6)`,
			[]any{out.id, fixture.scopeID, snapshot, snapshotDigest[:], "activation-" + name, fixture.now}},
		{`INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,
			signing_key_id,signature_algorithm,compression,media_type,encryption_algorithm,created_at)
			VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none','application/octet-stream','none',$8)`,
			[]any{uuid.New(), out.id, wire, len(wire), out.digest[:], signature, fixture.signer.KeyID(), fixture.now}},
		{`UPDATE config_versions SET status='validating' WHERE id=$1`, []any{out.id}},
		{`UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, []any{out.id, fixture.now}},
	}
	for _, statement := range statements {
		if _, err := fixture.pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatalf("%v\n%s", err, statement.sql)
		}
	}
	return out
}

// applyReleasableConfig records the node running config as a completed
// ordinary rollout created at at (a healthy apply bound to its artifact) and
// points the node at it.
func applyReleasableConfig(t *testing.T, fixture activationFixture, nodeID uuid.UUID, config releasableConfig, at time.Time) {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	command := []byte("ordinary-apply-" + deploymentID.String())
	commandDigest := sha256.Sum256(command)
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), "SET CONSTRAINTS ALL DEFERRED"); err != nil {
			return err
		}
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,revision,max_attempts,contract_version)
				VALUES($1,$2,$3,'apply','completed',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9,1,3,0)`,
				[]any{rolloutID, fixture.scopeID, config.id, "ordinary-" + rolloutID.String(), make([]byte, 32),
					uuid.New(), uuid.New(), at.Add(time.Hour), at}},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,$9,$9)`,
				[]any{deploymentID, rolloutID, nodeID, config.id, uuid.New(), command, commandDigest[:],
					at.Add(time.Hour), at}},
			{`INSERT INTO node_deployment_artifacts(deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal)
				SELECT $1,1,$2,id,1 FROM configuration_artifacts WHERE config_version_id=$2`, []any{deploymentID, config.id}},
			{`UPDATE node_config_state SET
				previous_config_version_id=$5,previous_config_identity_schema=1,previous_config_artifact_sha256=$6,
				current_config_version_id=$2,current_config_identity_schema=1,current_config_artifact_sha256=$3,updated_at=$4
				WHERE node_id=$1`, []any{nodeID, config.id, config.digest[:], fixture.now,
				fixture.previousConfigID, fixture.previousArtifactDigest[:]}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return fmt.Errorf("%w\n%s", err, statement.sql)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// After 634: the worker's event key is derived from the
// candidate, receipt, node state and recovery rollout times only. When none
// of them changes, every pass sends the same key; a stored "wait" under it
// was replayed for good, so a recovery that became provable (the predicate
// changed, or the node moved on) or a deadline that passed was never seen.
// A replayed wait is decided again: still waiting appends nothing, a new
// outcome is applied and recorded under a key derived from it.
func TestReconcileRechecksReplayedWait(t *testing.T) {
	events := func(t *testing.T, fixture activationFixture, candidateID uuid.UUID) map[string]int {
		t.Helper()
		rows, err := fixture.pool.Query(t.Context(), `SELECT action,count(*) FROM security_policy_activation_events
			WHERE candidate_id=$1 GROUP BY action`, candidateID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var action string
			var count int
			if err := rows.Scan(&action, &count); err != nil {
				t.Fatal(err)
			}
			out[action] = count
		}
		return out
	}

	t.Run("recovery becomes provable under the same key", func(t *testing.T) {
		fixture := newActivationFixture(t)
		store := newProductionActivationStore(t, fixture)
		nodes := []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}
		first := prepareProductionStart(t, fixture, store, "recheck-recover", nodes, 1)
		started, err := store.Start(t.Context(), fixture.actor, first)
		if err != nil {
			t.Fatal(err)
		}
		loaded := started.Candidate.CanaryNodeIDs[0]
		if err := markPartialCandidateLoaded(t, fixture, started.Candidate, loaded); err != nil {
			t.Fatal(err)
		}
		fixture.now = first.ExpiresAt.Add(time.Second)
		store = newProductionActivationStore(t, fixture)
		expired, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(started.Candidate, "recheck-expire"))
		if err != nil || expired.Candidate.Status != StatusExpired {
			t.Fatalf("expire = (%+v, %v)", expired, err)
		}
		input := productionReconcileInput(expired.Candidate, "recheck-same-key")
		waited, err := store.Reconcile(t.Context(), fixture.actor, input)
		if err != nil || waited.Action != string(actionWait) || waited.Candidate.RecoveredAt != nil {
			t.Fatalf("first pass = (%+v, %v)", waited, err)
		}
		// Still not provable: the same key decides again, appends nothing.
		again, err := store.Reconcile(t.Context(), fixture.actor, input)
		if err != nil || again.Action != string(actionWait) || again.Candidate.RecoveredAt != nil {
			t.Fatalf("second pass = (%+v, %v)", again, err)
		}
		if got := events(t, fixture, started.Candidate.ID)["wait"]; got != 1 {
			t.Fatalf("wait events = %d, want 1", got)
		}
		newer := insertReleasableConfig(t, fixture, "recheck-newer")
		applyReleasableConfig(t, fixture, loaded, newer, fixture.now)
		recovered, err := store.Reconcile(t.Context(), fixture.actor, input)
		if err != nil || recovered.Action != string(actionRecover) || recovered.Candidate.RecoveredAt == nil {
			t.Fatalf("pass after recovery became provable = (%+v, %v)", recovered, err)
		}
		if got := events(t, fixture, started.Candidate.ID)["recover"]; got != 1 {
			t.Fatalf("recover events = %d, want 1", got)
		}
		// The same key again returns the recorded recovery.
		replayed, err := store.Reconcile(t.Context(), fixture.actor, input)
		if err != nil || replayed.Candidate.RecoveredAt == nil {
			t.Fatalf("pass after recovery = (%+v, %v)", replayed, err)
		}
		if got := events(t, fixture, started.Candidate.ID)["recover"]; got != 1 {
			t.Fatalf("recover events after replay = %d, want 1", got)
		}
	})

	t.Run("deadline passes under the same key", func(t *testing.T) {
		fixture := newActivationFixture(t)
		store := newProductionActivationStore(t, fixture)
		nodes := []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}
		first := prepareProductionStart(t, fixture, store, "recheck-deadline", nodes, 1)
		started, err := store.Start(t.Context(), fixture.actor, first)
		if err != nil {
			t.Fatal(err)
		}
		input := productionReconcileInput(started.Candidate, "recheck-deadline-key")
		waited, err := store.Reconcile(t.Context(), fixture.actor, input)
		if err != nil || waited.Action != string(actionWait) || waited.Candidate.Status != StatusClaimed {
			t.Fatalf("pass before the deadline = (%+v, %v)", waited, err)
		}
		fixture.now = first.ExpiresAt.Add(time.Second)
		store = newProductionActivationStore(t, fixture)
		expired, err := store.Reconcile(t.Context(), fixture.actor, input)
		if err != nil || expired.Action != string(actionExpire) || expired.Candidate.Status != StatusExpired {
			t.Fatalf("pass after the deadline = (%+v, %v)", expired, err)
		}
		if got := events(t, fixture, started.Candidate.ID); got["wait"] != 1 || got["expire"] != 1 {
			t.Fatalf("events = %v, want one wait and one expire", got)
		}
	})
}
