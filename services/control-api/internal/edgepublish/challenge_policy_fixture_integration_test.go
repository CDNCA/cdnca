//go:build integration

package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BindChallenge gives the scope's site an active JS challenge binding of
// policyID at version (the challenge promotion's facts) and advances the
// scope's source revision as a tenant edit does.
func (scope *SystemRepublishScope) BindChallenge(t *testing.T, policyID uuid.UUID, version int64) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var tenantID uuid.UUID
		var host string
		if err := tx.QueryRow(t.Context(), `SELECT scope.tenant_id,site.domain FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id WHERE site.id=$1`, scope.SiteID).Scan(&tenantID, &host); err != nil {
			return err
		}
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO challenge_site_bindings_138(tenant_scope_id,tenant_id,site_id,host,active_binding_revision,created_at,updated_at)
				VALUES($1,$2,$3,$4,1,clock_timestamp(),clock_timestamp())
				ON CONFLICT (tenant_scope_id,site_id) DO UPDATE SET active_binding_revision=challenge_site_bindings_138.active_binding_revision+1`,
				[]any{scope.ScopeID, tenantID, scope.SiteID, host}},
			{`INSERT INTO challenge_site_binding_revisions_138(tenant_scope_id,tenant_id,site_id,host,binding_revision,policy_id,
				policy_revision,secret_rollout_id,secret_config_version_id,secret_revision,state,idempotency_key,request_digest,request_id,
				correlation_id,actor_scope_id,actor_user_id,created_at)
				SELECT $1,$2,$3,$4,active_binding_revision,$5,$6,$7,$8,1,'candidate','challenge-'||active_binding_revision,
				  decode(repeat('00',32),'hex'),'challenge-'||active_binding_revision,'challenge',$1,$9,clock_timestamp()
				FROM challenge_site_bindings_138 WHERE tenant_scope_id=$1 AND site_id=$3`,
				[]any{scope.ScopeID, tenantID, scope.SiteID, host, policyID, version, uuid.New(), uuid.New(), scope.UserID}},
			{`SELECT advance_edge_configuration_scope_revision($1)`, []any{scope.ScopeID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// InstallChallengePolicy records a challenge secret rollout of policyID at
// version that reached nodeID in state (healthy = the node installed the
// policy file). It copies the shape of the scope's latest deployment to
// nodeID, so the scope must have published to nodeID once.
func (scope *SystemRepublishScope) InstallChallengePolicy(t *testing.T, nodeID, policyID uuid.UUID, version int64, state string) {
	t.Helper()
	snapshot, err := json.Marshal(map[string]any{"schema_version": "cdnca.edge.challenge/v1", "policy_version": version,
		"rules": []map[string]any{{"rule_id": policyID.String(), "site_id": scope.SiteID.String()}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,$3,$4,$5,'1.0.0','releasable',$6,$4,clock_timestamp(),clock_timestamp())`,
				[]any{configID, scope.ScopeID, snapshot, digest[:], ChallengeSecretGeneratorName, "challenge-" + configID.String()}},
			{`CREATE TEMP TABLE challenge_rollout_copy ON COMMIT DROP AS SELECT rollout.* FROM rollouts rollout
				JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
				WHERE rollout.configuration_scope_id=$1 AND deployment.node_id=$2 ORDER BY rollout.created_at DESC LIMIT 1`,
				[]any{scope.ScopeID, nodeID}},
			{`UPDATE challenge_rollout_copy SET id=$1,config_version_id=$2,idempotency_key=$3`,
				[]any{rolloutID, configID, "challenge-" + rolloutID.String()}},
			{`INSERT INTO rollouts SELECT * FROM challenge_rollout_copy`, nil},
			{`CREATE TEMP TABLE challenge_deployment_copy ON COMMIT DROP AS SELECT * FROM node_deployments
				WHERE node_id=$1 AND configuration_scope_id=$2 ORDER BY created_at DESC LIMIT 1`, []any{nodeID, scope.ScopeID}},
			{`UPDATE challenge_deployment_copy SET id=$1,rollout_id=$2,config_version_id=$3,state=$4,attempt=1,
				command_event_id=$5,previous_config_version_id=NULL`,
				[]any{deploymentID, rolloutID, configID, state, uuid.New()}},
			{`INSERT INTO node_deployments SELECT * FROM challenge_deployment_copy`, nil},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// PublishExcluding publishes the scope's current facts to nodes the way the
// system and automatic channels do (publishExcludingIncapableTx): refused
// nodes are left out. It returns the nodes published to and the refused ones
// with the site whose JS challenge policy each lacks ("" for a capability).
func (scope *SystemRepublishScope) PublishExcluding(t *testing.T, key string, nodes ...uuid.UUID) ([]uuid.UUID, map[uuid.UUID]string) {
	t.Helper()
	var published []uuid.UUID
	refusedSites := map[uuid.UUID]string{}
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		now, err := databaseNow(t.Context(), tx)
		if err != nil {
			return err
		}
		_, nodesOut, refused, err := scope.fixture.service.publishExcludingIncapableTx(t.Context(), tx, nodes,
			func(candidates []uuid.UUID) (normalizedPublishRequest, error) {
				request := scope.fixture.publishRequest(key, candidates[0])
				request.NodeIDs = candidates
				return normalizePublishRequest(request, now)
			}, now)
		published = nodesOut
		for _, item := range refused {
			refusedSites[item.NodeID] = ""
			if item.Challenge != nil {
				refusedSites[item.NodeID] = item.Challenge.SiteID
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return published, refusedSites
}

// PublishManuallyV2 publishes the scope's current facts with site runtime v2
// after nodes declare site runtime v8 (JS challenge on the listener needs a
// v6 document; delivery is site objects).
func (scope *SystemRepublishScope) PublishManuallyV2(t *testing.T, key string, nodeIDs ...uuid.UUID) error {
	t.Helper()
	for _, nodeID := range nodeIDs {
		features := systemRepublishFeatures(6)
		for index, capability := range features {
			if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
				features[index] = &agentv1.Capability{Name: capability.GetName(), ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion}
			}
		}
		seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, "1.0.35-v8", features)
	}
	request := siteRuntimeV2PublishRequest(scope.fixture, key, nodeIDs[0], siteRuntimeV2Schema)
	request.NodeIDs = slices.Clone(nodeIDs)
	_, err := scope.fixture.service.Publish(t.Context(), request)
	return err
}
