package nodeserving

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A reinstalled host ("重装此节点") numbers its telemetry from 1 again
// (migration 626 host_epoch). The period's traffic accounting must count the
// new host's samples although their sequences are below the previous host's
// (the cursor is host_epoch, then sequence).
func TestAutoDisableCountsReinstalledHostTraffic(t *testing.T) {
	harness := newServingHarness(t)
	nodeID := harness.addNode()
	worker, err := NewWorker(harness.store, time.Second, nil, NewAutoDisableEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	var now time.Time
	if err := harness.pool.QueryRow(harness.ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	anchor := now.In(chinaStandardTime).Add(-time.Hour)
	day := min(anchor.Day(), 28)
	harness.autoDisable(nodeID, map[string]any{"traffic_enabled": true, "traffic_total_gb": 1, "traffic_from_day": day,
		"traffic_from_time": anchor.Format("15:04:05"), "traffic_types": []string{"outbound"}})
	telemetry := func(sequence int64, age time.Duration, txBytes uint64) {
		t.Helper()
		encoded, err := json.Marshal(map[string]any{"schema_version": 1, "network_interfaces": []any{nic("eth0", txBytes, 0)},
			"total_rx_bytes": 0, "total_tx_bytes": 0})
		if err != nil {
			t.Fatal(err)
		}
		harness.sequence++ // a distinct puback per sample
		harness.exec(`INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
			publication_sequence,observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,active_connections,
			rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,puback_sequence,consumer_durable,consumer_sequence,
			num_delivered,wire_sha256,ingested_at,record_kind,telemetry_json,total_rx_bytes,total_tx_bytes)
			VALUES($1,$2,$3,1,0,$4,clock_timestamp()-$5::interval,true,1,1,2,0,0,0,'NODE_MONITORING_STATUS',$6,
			'control_api_node_metrics',$6,1,$7,clock_timestamp(),'host_metric',$8,0,0)`,
			uuid.New(), uuid.New(), nodeID, sequence, age.String(), harness.sequence, make([]byte, 32), encoded)
	}
	usage := func() int64 {
		t.Helper()
		var bytes int64
		if err := harness.pool.QueryRow(harness.ctx, `SELECT usage_bytes FROM node_auto_disable_usage WHERE node_id=$1`,
			nodeID).Scan(&bytes); err != nil {
			t.Fatal(err)
		}
		return bytes
	}

	// The previous host: 512 MiB out in the period, up to sequence 50.
	seedServingNodeEnrollment(t, harness, nodeID)
	telemetry(1, 30*time.Minute, 0)
	telemetry(50, 25*time.Minute, 512<<20)
	run()
	if got := usage(); got != 512<<20 {
		t.Fatalf("previous host usage = %d", got)
	}
	// The new host starts at sequence 1 with fresh counters: 600 MiB more.
	seedServingNodeEnrollment(t, harness, nodeID)
	telemetry(1, 10*time.Minute, 0)
	telemetry(2, 5*time.Minute, 600<<20)
	run()
	if got := usage(); got != (512<<20)+(600<<20) {
		t.Fatalf("usage after reinstall = %d, want the new host's traffic counted", got)
	}
	if held, reason := harness.autoHold(nodeID); !held || reason != ReasonTrafficExceeded {
		t.Fatalf("over quota after reinstall: held=%v reason=%q", held, reason)
	}
}

// seedServingNodeEnrollment records one enrollment (an initial certificate) of
// the node, as a host taking it over does.
func seedServingNodeEnrollment(t *testing.T, harness *servingHarness, nodeID uuid.UUID) {
	t.Helper()
	now := time.Now()
	tokenID, authorizationID, certificateID := uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(certificateID.String()))
	harness.exec(`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, tokenID, nodeID, digest[:], harness.userID, now.Add(-time.Minute), now.Add(time.Hour))
	harness.exec(`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, authorizationID, tokenID, nodeID, authorizationID.String(), digest[:], now.Add(-time.Minute))
	harness.exec(`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,
		csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,
		protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
		gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		VALUES($1,$2,$3,'initial_enrollment',$1,$4,$4,'test',$4,$4,1,0,1,0,1,0,'{}',$4,
		'spiffe://cdn-platform/gateway/test','test','test-key',$4,'authorized',$5,$6)`,
		authorizationID, tokenID, nodeID, digest[:], now.Add(-time.Minute), now.Add(time.Hour))
	harness.exec(`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,
		csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,
		issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
		VALUES($1,$2,'initial',$3,$4,$5,$5,$6,$7,$8,$9,'test',ARRAY['test'::bytea],$5,'active',$7)`,
		certificateID, nodeID, authorizationID, strings.ReplaceAll(certificateID.String(), "-", ""), digest[:],
		"spiffe://cdn-platform/node/"+nodeID.String(), now.Add(-time.Minute), now.Add(time.Hour), now.Add(30*time.Minute))
}
