//go:build integration

package retentioncleanup

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A reinstalled host ("重装此节点") numbers its samples from 1 again
// (migration 626 host_epoch). "Never the node's newest" is in (host_epoch,
// publication_sequence) order: the previous host's highest sequence is not
// kept forever, and the new host's newest sample is kept.
func TestWorkerPrunesReinstalledHostMetricsByHostOrder(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	grantCleanupRole(t, pool)
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'retention-reinstall','Retention','unused')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'retention-reinstall','active',$3,1)`,
			[]any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	sample := func(sequence int64, age string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
			publication_sequence,observed_at,metrics_known,puback_stream,puback_sequence,consumer_durable,consumer_sequence,
			num_delivered,wire_sha256,ingested_at,record_kind,active_config_revision,probe_port,healthy,probe_succeeded,
			consecutive_failures,consecutive_successes,probes_total,probe_failures_total,recovered,recovery_notified,rolled_back)
			VALUES($1,$2,$3,1,1,$4,now()-$5::interval,false,'NODE_MONITORING_STATUS',$6,'control_api_node_metrics',$6,
			1,$7,now(),'metric',1,80,true,true,0,1,1,0,false,false,false)`,
			uuid.NewSHA1(nodeID, []byte{byte(sequence)}), uuid.New(), nodeID, sequence, age,
			time.Now().UnixNano(), make([]byte, 32)); err != nil {
			t.Fatalf("insert sample %d: %v", sequence, err)
		}
	}
	seedNodeEnrollment(t, pool, nodeID, userID)
	sample(1, "30 days") // the previous host, its newest (3) expired too
	sample(2, "20 days")
	sample(3, "10 days")
	seedNodeEnrollment(t, pool, nodeID, userID) // reinstall
	sample(1, "9 days") // the new host, same event ID as the previous host's 1
	sample(2, "1 hour")

	worker, err := NewWorker(pool, audit.New(pool), Config{BatchSize: 10, BatchPause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if results := worker.RunOnce(ctx); results[0].Err != nil || results[0].Deleted != 4 {
		t.Fatalf("node metric results = %+v", results[0])
	}
	var kept string
	if err := pool.QueryRow(ctx, `SELECT string_agg(host_epoch||'/'||publication_sequence,',') FROM node_metric_samples
		WHERE node_id=$1`, nodeID).Scan(&kept); err != nil || kept != "1/2" {
		t.Fatalf("kept samples = %s (%v)", kept, err)
	}
	// The cleanup role still cannot delete the node's newest sample.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE cdnca_retention_cleanup`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM node_metric_samples WHERE node_id=$1`, nodeID); !hasCode(err, "P3202") {
		t.Fatalf("cleanup delete of the newest sample = %v, want P3202", err)
	}
}

// seedNodeEnrollment records one enrollment (an initial certificate) of the
// node, as a host taking it over does.
func seedNodeEnrollment(t *testing.T, pool *pgxpool.Pool, nodeID, userID uuid.UUID) {
	t.Helper()
	now := time.Now()
	tokenID, authorizationID, certificateID := uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(certificateID.String()))
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		 VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, []any{tokenID, nodeID, digest[:], userID, now.Add(-time.Minute), now.Add(time.Hour)}},
		{`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		 VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, []any{authorizationID, tokenID, nodeID, authorizationID.String(), digest[:], now.Add(-time.Minute)}},
		{`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,
		 csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,
		 protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
		 gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		 VALUES($1,$2,$3,'initial_enrollment',$1,$4,$4,'test',$4,$4,1,0,1,0,1,0,'{}',$4,
		 'spiffe://cdn-platform/gateway/test','test','test-key',$4,'authorized',$5,$6)`,
			[]any{authorizationID, tokenID, nodeID, digest[:], now.Add(-time.Minute), now.Add(time.Hour)}},
		{`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,
		 csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,
		 issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
		 VALUES($1,$2,'initial',$3,$4,$5,$5,$6,$7,$8,$9,'test',ARRAY['test'::bytea],$5,'active',$7)`,
			[]any{certificateID, nodeID, authorizationID, strings.ReplaceAll(certificateID.String(), "-", ""), digest[:],
				"spiffe://cdn-platform/node/" + nodeID.String(), now.Add(-time.Minute), now.Add(time.Hour), now.Add(30 * time.Minute)}},
	} {
		if _, err := pool.Exec(context.Background(), statement.sql, statement.args...); err != nil {
			t.Fatalf("seed enrollment: %v", err)
		}
	}
}
