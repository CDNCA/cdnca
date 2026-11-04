//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestNodeMetricHostEpoch626UpDown: existing samples become host epoch 0 and
// survive up/down/up; once a reinstalled host has samples (host_epoch > 0)
// the rollback is refused (P6262), because the 150 keys cannot hold the
// repeated event IDs and sequences.
func TestNodeMetricHostEpoch626UpDown(t *testing.T) {
	const version = 626
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'host-epoch-626','Host epoch','unused')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'host-epoch','active',$3,1)`,
			[]any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatalf("seed %q: %v", seed.sql, err)
		}
	}
	const columns = `event_id,request_id,node_id,schema_version,config_revision,
		publication_sequence,observed_at,metrics_known,puback_stream,puback_sequence,consumer_durable,consumer_sequence,
		num_delivered,wire_sha256,ingested_at,record_kind,active_config_revision,probe_port,healthy,probe_succeeded,
		consecutive_failures,consecutive_successes,probes_total,probe_failures_total,recovered,recovery_notified,rolled_back`
	const values = `$1,$2,$3,1,1,$4,now(),false,'NODE_MONITORING_STATUS',$5,'control_api_node_metrics',$5,
		1,$6,now(),'metric',1,80,true,true,0,1,1,0,false,false,false`
	sampleSQL := `INSERT INTO node_metric_samples(` + columns + `) VALUES(` + values + `)`
	epochSampleSQL := `INSERT INTO node_metric_samples(host_epoch,` + columns + `) VALUES(1,` + values + `)`
	eventID := uuid.NewSHA1(nodeID, []byte("node-monitoring-metric/1"))
	if _, err := pool.Exec(ctx, sampleSQL, eventID, uuid.New(), nodeID, 1, 1, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var epoch int
	if err := pool.QueryRow(ctx, `SELECT host_epoch FROM node_metric_samples WHERE event_id=$1`, eventID).Scan(&epoch); err != nil || epoch != 0 {
		t.Fatalf("existing sample host_epoch = %d, %v", epoch, err)
	}
	// A reinstalled host's sample: same event ID and sequence, host epoch 1
	// (written with the guard off; the guard derives it from certificates).
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `ALTER TABLE node_metric_samples DISABLE TRIGGER node_metric_sequence_guard_626`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, epochSampleSQL, eventID, uuid.New(), nodeID, 1, 2, make([]byte, 32)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `ALTER TABLE node_metric_samples ENABLE TRIGGER node_metric_sequence_guard_626`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !pgCode(err, "P6262") {
		t.Fatalf("down %d with a reinstalled host's sample = %v, want P6262", version, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_metric_samples WHERE node_id=$1`, nodeID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("samples after refused rollback = %d, %v", count, err)
	}
}
