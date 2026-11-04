//go:build integration

package node

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A deployment a reinstall ended (627 host replacement fact) does not keep
// the node from being deleted; the fact goes with the deployment, and stays
// immutable outside the purge.
func TestNodePurgeRemovesHostReplacementFacts(t *testing.T) {
	f := newPurgeHistoryFixture(t)
	nodeID := f.platformNode(t, "purge-replaced")
	f.enrollment(t, nodeID)
	deploymentID := f.runningDeployment(t, nodeID, "activated")
	f.enrollment(t, nodeID) // the reinstall
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		closed, err := edgedeployment.CloseReplacedHostDeploymentsTx(t.Context(), tx, nodeID)
		if err == nil && closed != 1 {
			t.Errorf("closed %d deployments, want 1", closed)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `DELETE FROM node_deployment_host_replacements WHERE deployment_id=$1`,
		deploymentID); err == nil {
		t.Fatal("direct delete of a host replacement fact was accepted")
	}
	if err := f.retire(t, nodeID); err != nil {
		t.Fatalf("delete node with a host replaced deployment: %v", err)
	}
	if got := f.count(t, `SELECT count(*) FROM node_deployment_host_replacements WHERE node_id=$1`, nodeID); got != 0 {
		t.Fatalf("host replacement facts after purge = %d, want 0", got)
	}
}

// enrollment records one enrollment (an initial certificate) of the node.
func (f *purgeHistoryFixture) enrollment(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	now := time.Now()
	tokenID, authorizationID, certificateID := uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(certificateID.String()))
	f.exec(t, `INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, tokenID, nodeID, digest[:], f.operator, now.Add(-time.Minute), now.Add(time.Hour))
	f.exec(t, `INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, authorizationID, tokenID, nodeID, authorizationID.String(), digest[:], now.Add(-time.Minute))
	f.exec(t, `INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,
		csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,
		protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
		gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		VALUES($1,$2,$3,'initial_enrollment',$1,$4,$4,'test',$4,$4,1,0,1,0,1,0,'{}',$4,
		'spiffe://cdn-platform/gateway/test','test','test-key',$4,'authorized',$5,$6)`,
		authorizationID, tokenID, nodeID, digest[:], now.Add(-time.Minute), now.Add(time.Hour))
	f.exec(t, `INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,
		csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,
		issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
		VALUES($1,$2,'initial',$3,$4,$5,$5,$6,$7,$8,$9,'test',ARRAY['test'::bytea],$5,'active',$7)`,
		certificateID, nodeID, authorizationID, strings.ReplaceAll(certificateID.String(), "-", ""), digest[:],
		"spiffe://cdn-platform/node/"+nodeID.String(), now.Add(-time.Minute), now.Add(time.Hour), now.Add(30*time.Minute))
}

// runningDeployment records a contract-v1 deployment of the tenant to the
// node in state, created three hours ago (written as a replica: the seed
// state has no status events).
func (f *purgeHistoryFixture) runningDeployment(t *testing.T, nodeID uuid.UUID, state string) uuid.UUID {
	t.Helper()
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
				generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,'replaced',$3,'purge-test','1','releasable',$4,$3,now(),now())`,
				[]any{configID, f.tenant.ScopeID, make([]byte, 32), "purge-replaced-" + configID.String()}},
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,contract_version,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,'apply','building',1,$4,$5,$6,$6,60000,60000,1,
				now()+interval '1 hour',now()-interval '3 hours',now()-interval '3 hours')`,
				[]any{rolloutID, f.tenant.ScopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New()}},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
				command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES($1,$2,$3,1,$4,'apply',$5,$6,'x',$7,now()+interval '1 hour',
				now()-interval '3 hours',now()-interval '3 hours',$8)`,
				[]any{deploymentID, rolloutID, nodeID, configID, state, uuid.New(), make([]byte, 32), f.tenant.ScopeID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed running deployment: %v", err)
	}
	return deploymentID
}
