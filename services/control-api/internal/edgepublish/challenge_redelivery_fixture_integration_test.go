//go:build integration

package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetPresence records nodeID online in session epoch (a reconnect is a new
// epoch) or offline (epoch 0 keeps the current one).
func (scope *SystemRepublishScope) SetPresence(t *testing.T, nodeID uuid.UUID, online bool, epoch int64) {
	t.Helper()
	digest := sha256.Sum256(nodeID[:])
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if !online {
			_, err := tx.Exec(t.Context(), `UPDATE node_presence SET status='offline',offline_since=clock_timestamp(),
				online_since=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE node_id=$1`, nodeID)
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,'online',$2,1,$3,$4,$5,clock_timestamp(),clock_timestamp(),clock_timestamp(),$2,1,$3,$4,$5,
			  clock_timestamp(),'running','running',100,50,0,clock_timestamp())
			ON CONFLICT (node_id) DO UPDATE SET status='online',session_epoch=EXCLUDED.session_epoch,
			  confirmed_session_epoch=EXCLUDED.session_epoch,online_since=clock_timestamp(),offline_since=NULL,
			  revision=node_presence.revision+1,updated_at=clock_timestamp()`,
			nodeID, epoch, uuid.New(), uuid.New(), digest[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// ExcludeFromSystemRepublication records nodeID the way a system
// republication that refused it does (the node joined the scope's targets
// and lacked the challenge policy).
func (scope *SystemRepublishScope) ExcludeFromSystemRepublication(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `INSERT INTO edge_system_republication_heads(
		scope_id,generation,state,triggers,due_at,attempt,excluded_node_ids,last_outcome,created_at,updated_at)
		VALUES($1,1,'idle',ARRAY['line_group'],clock_timestamp(),0,ARRAY[$2::uuid],'published',clock_timestamp(),clock_timestamp())
		ON CONFLICT (scope_id) DO UPDATE SET excluded_node_ids=ARRAY[$2::uuid]`, scope.ScopeID, nodeID); err != nil {
		t.Fatal(err)
	}
}

// InstallChallengePolicyTx is InstallChallengePolicy in the caller's
// transaction (a fake redeliverer's secret rollout); it returns the rollout.
func (scope *SystemRepublishScope) InstallChallengePolicyTx(t *testing.T, tx pgx.Tx, nodeID, policyID uuid.UUID,
	version int64, state string) uuid.UUID {
	t.Helper()
	snapshot, err := json.Marshal(map[string]any{"schema_version": "cdnca.edge.challenge/v1", "policy_version": version,
		"rules": []map[string]any{{"rule_id": policyID.String(), "site_id": scope.SiteID.String()}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	suffix := "_" + uuid.NewString()[:8]
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`SET LOCAL session_replication_role = replica`, nil},
		{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,$3,$4,$5,'1.0.0','releasable',$6,$4,clock_timestamp(),clock_timestamp())`,
			[]any{configID, scope.ScopeID, snapshot, digest[:], ChallengeSecretGeneratorName, "challenge-" + configID.String()}},
		{`CREATE TEMP TABLE rollout_copy` + suffix + ` AS SELECT rollout.* FROM rollouts rollout
			JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
			WHERE rollout.configuration_scope_id=$1 AND deployment.node_id=$2 ORDER BY rollout.created_at DESC LIMIT 1`,
			[]any{scope.ScopeID, nodeID}},
		{`UPDATE rollout_copy` + suffix + ` SET id=$1,config_version_id=$2,idempotency_key=$3`,
			[]any{rolloutID, configID, "challenge-" + rolloutID.String()}},
		{`INSERT INTO rollouts SELECT * FROM rollout_copy` + suffix, nil},
		{`CREATE TEMP TABLE deployment_copy` + suffix + ` AS SELECT * FROM node_deployments
			WHERE node_id=$1 AND configuration_scope_id=$2 ORDER BY created_at DESC LIMIT 1`, []any{nodeID, scope.ScopeID}},
		{`UPDATE deployment_copy` + suffix + ` SET id=$1,rollout_id=$2,config_version_id=$3,state=$4,attempt=1,
			command_event_id=$5,previous_config_version_id=NULL,deadline_at=clock_timestamp()+interval '1 hour'`,
			[]any{deploymentID, rolloutID, configID, state, uuid.New()}},
		{`INSERT INTO node_deployments SELECT * FROM deployment_copy` + suffix, nil},
		{`DROP TABLE rollout_copy` + suffix + `, deployment_copy` + suffix, nil},
		{`SET LOCAL session_replication_role = DEFAULT`, nil},
	} {
		if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return rolloutID
}

// SetRolloutDeploymentState moves the rollout's deployment on nodeID to state
// (the node's receipt).
func (scope *SystemRepublishScope) SetRolloutDeploymentState(t *testing.T, rolloutID, nodeID uuid.UUID, state string) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$3,updated_at=clock_timestamp()
			WHERE rollout_id=$1 AND node_id=$2`, rolloutID, nodeID, state)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// IgnoreRolloutAsOldRelease fails the rollout's deployment on nodeID as an
// ignored old release (edgedeployment.SupersededDeploymentSQL): a failed
// status event of its attempt carrying ERROR_CODE_STALE_ATTEMPT.
func (scope *SystemRepublishScope) IgnoreRolloutAsOldRelease(t *testing.T, rolloutID, nodeID uuid.UUID) {
	t.Helper()
	payload := []byte("challenge-redelivery-ignored-old-release")
	digest := sha256.Sum256(payload)
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(
			id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at,error_code)
			SELECT $3,deployment.id,$4,deployment.attempt,1000,'failed',$5,$6,clock_timestamp(),clock_timestamp(),
			  'ERROR_CODE_STALE_ATTEMPT'
			FROM node_deployments deployment WHERE deployment.rollout_id=$1 AND deployment.node_id=$2`,
			rolloutID, nodeID, uuid.New(), uuid.New(), payload, digest[:]); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state='failed',updated_at=clock_timestamp()
			WHERE rollout_id=$1 AND node_id=$2`, rolloutID, nodeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// ChallengeRedeliveryRow is one edge_challenge_redeliveries row.
type ChallengeRedeliveryRow struct {
	State     string
	Attempt   int
	Epoch     int64
	RolloutID *uuid.UUID
	LastError *string
	DueInMS   int64
}

// ChallengeRedeliveries returns the scope's rows by node.
func (scope *SystemRepublishScope) ChallengeRedeliveries(t *testing.T) map[uuid.UUID]ChallengeRedeliveryRow {
	t.Helper()
	rows, err := scope.Pool.Query(t.Context(), `SELECT node_id,state,attempt,session_epoch,rollout_id,last_error,
		(extract(epoch FROM due_at-clock_timestamp())*1000)::bigint FROM edge_challenge_redeliveries WHERE scope_id=$1`,
		scope.ScopeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[uuid.UUID]ChallengeRedeliveryRow{}
	for rows.Next() {
		var nodeID uuid.UUID
		var row ChallengeRedeliveryRow
		if err := rows.Scan(&nodeID, &row.State, &row.Attempt, &row.Epoch, &row.RolloutID, &row.LastError, &row.DueInMS); err != nil {
			t.Fatal(err)
		}
		result[nodeID] = row
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

// ChallengeOrigin is the published challenge policy revision of the scope's
// site that SeedChallengeOrigin records.
type ChallengeOrigin struct {
	TenantID uuid.UUID
	Host     string
}

// SeedChallengeOrigin records revision version of policyID for the scope's
// site (click mode, keyref:challenge-primary) and returns its identity; the
// caller builds the published document from it.
func (scope *SystemRepublishScope) SeedChallengeOrigin(t *testing.T, policyID uuid.UUID, version int64) ChallengeOrigin {
	t.Helper()
	var origin ChallengeOrigin
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `SELECT scope.tenant_id,site.domain FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id WHERE site.id=$1`, scope.SiteID).Scan(&origin.TenantID, &origin.Host); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO challenge_policy_revisions(policy_id,tenant_scope_id,tenant_id,site_id,host,
			revision,action,priority,mode,min_delay_seconds,challenge_ttl_seconds,pass_ttl_seconds,clock_skew_seconds,
			attempts_per_nonce,failure_window_seconds,max_failures_per_window,ip_binding,bind_user_agent,bypass_routes,
			key_reference,enabled,deleted,document,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,'update',10,'click',0,60,300,5,1,60,3,'exact',false,'[]','keyref:challenge-primary',
			  true,false,'{}',$2,$7,'redeliver-origin','redeliver-origin',clock_timestamp())`,
			policyID, scope.ScopeID, origin.TenantID, scope.SiteID, origin.Host, version, scope.UserID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return origin
}

// PublishChallengeOrigin stores document as the binding's challenge secret
// config version (what its promotion published).
func (scope *SystemRepublishScope) PublishChallengeOrigin(t *testing.T, document []byte) uuid.UUID {
	t.Helper()
	configID := uuid.New()
	digest := sha256.Sum256(document)
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
			canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,$3,$4,$5,'1.0.0','releasable',$6,$4,clock_timestamp(),clock_timestamp())`,
			configID, scope.ScopeID, document, digest[:], ChallengeSecretGeneratorName, "origin-"+configID.String()); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE challenge_site_binding_revisions_138 revision SET secret_config_version_id=$3
			FROM challenge_site_bindings_138 binding WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2
			  AND revision.tenant_scope_id=binding.tenant_scope_id AND revision.site_id=binding.site_id
			  AND revision.binding_revision=binding.active_binding_revision`, scope.ScopeID, scope.SiteID, configID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return configID
}

// DeploymentStore is the edge deployment store of the scope's fixture.
func (scope *SystemRepublishScope) DeploymentStore(t *testing.T) *edgedeployment.Store {
	t.Helper()
	return scope.fixture.deploymentStore(t)
}
