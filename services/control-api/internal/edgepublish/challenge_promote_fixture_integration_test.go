//go:build integration

package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InstallChallengeRollout records one challenge secret rollout of policyID at
// version with a deployment per node in states[node] (the shape of each
// node's latest deployment of the scope), makes it the secret of the site's
// active binding and returns the rollout. The scope must have published to
// every node once.
func (scope *SystemRepublishScope) InstallChallengeRollout(t *testing.T, policyID uuid.UUID, version int64,
	states map[uuid.UUID]string) uuid.UUID {
	t.Helper()
	snapshot, err := json.Marshal(map[string]any{"schema_version": "cdnca.edge.challenge/v1", "policy_version": version,
		"rules": []map[string]any{{"rule_id": policyID.String(), "site_id": scope.SiteID.String()}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	configID, rolloutID := uuid.New(), uuid.New()
	nodes := make([]uuid.UUID, 0, len(states))
	for nodeID := range states {
		nodes = append(nodes, nodeID)
	}
	slices.SortFunc(nodes, compareUUID)
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		statements := []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,$3,$4,$5,'1.0.0','releasable',$6,$4,clock_timestamp(),clock_timestamp())`,
				[]any{configID, scope.ScopeID, snapshot, digest[:], ChallengeSecretGeneratorName, "challenge-" + configID.String()}},
			{`CREATE TEMP TABLE promote_rollout_copy ON COMMIT DROP AS SELECT rollout.* FROM rollouts rollout
				WHERE rollout.configuration_scope_id=$1 ORDER BY rollout.created_at DESC LIMIT 1`, []any{scope.ScopeID}},
			{`UPDATE promote_rollout_copy SET id=$1,config_version_id=$2,idempotency_key=$3,status='running'`,
				[]any{rolloutID, configID, "challenge-" + rolloutID.String()}},
			{`INSERT INTO rollouts SELECT * FROM promote_rollout_copy`, nil},
			{`UPDATE challenge_site_binding_revisions_138 revision SET secret_rollout_id=$3,secret_config_version_id=$4
				FROM challenge_site_bindings_138 binding WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2
				  AND revision.tenant_scope_id=binding.tenant_scope_id AND revision.site_id=binding.site_id
				  AND revision.binding_revision=binding.active_binding_revision`,
				[]any{scope.ScopeID, scope.SiteID, rolloutID, configID}},
		}
		for _, nodeID := range nodes {
			statements = append(statements, []struct {
				sql  string
				args []any
			}{
				{`CREATE TEMP TABLE promote_deployment_copy ON COMMIT DROP AS SELECT * FROM node_deployments
					WHERE node_id=$1 AND configuration_scope_id=$2 ORDER BY created_at DESC LIMIT 1`, []any{nodeID, scope.ScopeID}},
				{`UPDATE promote_deployment_copy SET id=$1,rollout_id=$2,config_version_id=$3,state=$4,attempt=1,
					command_event_id=$5,previous_config_version_id=NULL,deadline_at=clock_timestamp()+interval '1 hour'`,
					[]any{uuid.New(), rolloutID, configID, states[nodeID], uuid.New()}},
				{`INSERT INTO node_deployments SELECT * FROM promote_deployment_copy`, nil},
				{`DROP TABLE promote_deployment_copy`, nil},
			}...)
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rolloutID
}

// ExpireRolloutDeployment puts the rollout's deployment on nodeID past its
// deadline.
func (scope *SystemRepublishScope) ExpireRolloutDeployment(t *testing.T, rolloutID, nodeID uuid.UUID) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_deployments SET deadline_at=clock_timestamp()-interval '1 second'
			WHERE rollout_id=$1 AND node_id=$2`, rolloutID, nodeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// PublishChallengeBinding publishes the scope's current facts (the bound
// challenge) to ready and defers deferred in the same transaction, as the
// durable binding publisher of a challenge promotion does.
func (scope *SystemRepublishScope) PublishChallengeBinding(t *testing.T, key string, ready, deferred []uuid.UUID,
	policyID, rolloutID uuid.UUID, version int64) (PublishResult, error) {
	t.Helper()
	var result PublishResult
	err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		request := scope.fixture.publishRequest(key, ready[0])
		request.NodeIDs = slices.Clone(ready)
		var err error
		if result, err = scope.fixture.service.PublishTx(t.Context(), tx, request); err != nil {
			return err
		}
		if len(deferred) == 0 {
			return nil
		}
		return scope.fixture.service.DeferChallengeNodesTx(t.Context(), tx, ChallengeDeferral{
			Actor: request.Actor, ScopeID: scope.ScopeID, SourceRevision: result.SourceRevision,
			RequestID: request.RequestID, PublishedNodeIDs: slices.Clone(ready), DeferredNodeIDs: slices.Clone(deferred),
			SiteID: scope.SiteID, PolicyID: policyID, PolicyVersion: version, SecretRolloutID: rolloutID,
		})
	})
	return result, err
}
