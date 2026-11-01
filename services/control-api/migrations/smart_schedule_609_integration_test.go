//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSmartSchedule609: defaults, bounds, province line
// scopes on cname_carrier_line_records and the down guard refusing while a
// province line record exists.
func TestSmartSchedule609(t *testing.T) {
	// Keep equal to the 609 contract's version (renum-one.sh rewrites it).
	const version = 609
	pool := migrationPoolAt(t, version)
	ctx := t.Context()
	scopeID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'smart-609','Smart 609','test-only')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'smart-609',1,$3,$3,now(),now())`,
			groupID, scopeID, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'smart-609','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now())`,
			groupID, scopeID, make([]byte, 32), userID)
		if err != nil {
			return err
		}
		endpointID := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoints(id,tenant_scope_id,line_group_id,config_revision,address,
			address_family,port,region,carrier,priority,weight,enabled) VALUES($1,$2,$3,1,'192.0.2.1',4,443,'广东','电信',0,1,true)`,
			endpointID, scopeID, groupID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			VALUES($1,$2,1,$3,'unknown',0,0,0,now(),1,now(),now())`, scopeID, groupID, endpointID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, scopeID, groupID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	mustExec(t, pool, `INSERT INTO node_line_group_smart_schedules(tenant_scope_id,line_group_id,revision,updated_by_user_id,updated_at)
		VALUES($1,$2,1,$3,$4)`, scopeID, groupID, userID, now)
	var enabled bool
	var topN, window, maxLoad int
	var granularity, fallback string
	if err := pool.QueryRow(ctx, `SELECT enabled,top_n,granularity,latency_window_minutes,max_load_percent,fallback
		FROM node_line_group_smart_schedules WHERE line_group_id=$1`, groupID).Scan(&enabled, &topN, &granularity, &window,
		&maxLoad, &fallback); err != nil || enabled || topN != 3 || granularity != "carrier" || window != 15 || maxLoad != 85 ||
		fallback != "carrier_then_default" {
		t.Fatalf("defaults = %v %d %s %d %d %s (%v)", enabled, topN, granularity, window, maxLoad, fallback, err)
	}
	for name, statement := range map[string]string{
		"top_n 21":      `UPDATE node_line_group_smart_schedules SET top_n=21`,
		"granularity":   `UPDATE node_line_group_smart_schedules SET granularity='city'`,
		"window 61":     `UPDATE node_line_group_smart_schedules SET latency_window_minutes=61`,
		"bad province":  `INSERT INTO node_line_smart_selections VALUES('` + scopeID.String() + `','` + groupID.String() + `','香港:mobile',1,'latency','','[]','` + zeros + `',now(),now())`,
		"fallback pair": `INSERT INTO node_line_smart_selections VALUES('` + scopeID.String() + `','` + groupID.String() + `','telecom',1,'fallback','','[]','` + zeros + `',now(),now())`,
		"null selected": `INSERT INTO node_line_smart_selections VALUES('` + scopeID.String() + `','` + groupID.String() + `','telecom',1,'static','','null','` + zeros + `',now(),now())`,
		"bucket second": `INSERT INTO node_line_latency_samples VALUES('` + scopeID.String() + `','` + groupID.String() + `','` + uuid.NewString() + `','192.0.2.1','广东','telecom','dnspup','2026-10-31T00:00:01Z','{10}',now())`,
		"zero latency":  `INSERT INTO node_line_latency_samples VALUES('` + scopeID.String() + `','` + groupID.String() + `','` + uuid.NewString() + `','192.0.2.1','广东','telecom','dnspup','2026-10-31T00:00:00Z','{0}',now())`,
		"overseas line": `INSERT INTO node_line_latency_samples VALUES('` + scopeID.String() + `','` + groupID.String() + `','` + uuid.NewString() + `','192.0.2.1','','overseas','dnspup','2026-10-31T00:00:00Z','{5}',now())`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	mustExec(t, pool, `INSERT INTO node_line_smart_selections VALUES($1,$2,'广东:mobile',1,'latency','','[]',$3,now(),now()),
		($1,$2,'unicom',1,'fallback','carrier','[]',$3,now(),now())`, scopeID, groupID, zeros)
	mustExec(t, pool, `INSERT INTO node_line_latency_samples VALUES($1,$2,$3,'192.0.2.1','','mobile','peer',$4,'{5,6}',now())`,
		scopeID, groupID, uuid.New(), now)

	// Province scopes are accepted on the carrier line records (checked on the
	// constraint itself: a site row needs the whole site fixture).
	var accepts, rejects bool
	if err := pool.QueryRow(ctx, `SELECT '广东:telecom' ~ '^(北京|广东):(telecom|unicom|mobile)$',
		pg_get_constraintdef(oid) LIKE '%overseas%' FROM pg_constraint
		WHERE conname='cname_carrier_line_records_line_scope_609_check'`).Scan(&accepts, &rejects); err != nil || !accepts || !rejects {
		t.Fatalf("609 line scope constraint missing (%v)", err)
	}
	// The down guard refuses while a province line record exists.
	siteID := uuid.New()
	mustExec(t, pool, `BEGIN; SET LOCAL session_replication_role=replica;
		INSERT INTO cname_carrier_line_records(site_id,line_scope,desired_digest,next_attempt_at,updated_at)
		VALUES('`+siteID.String()+`','广东:telecom','`+zeros+`',now(),now()); COMMIT`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("down accepted with a province line record")
	}
	mustExec(t, pool, `DELETE FROM cname_carrier_line_records WHERE site_id=$1`, siteID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('node_line_smart_selections') IS NOT NULL OR
		to_regclass('node_line_latency_samples') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("609 tables survived down (%v)", err)
	}
}

const zeros = "0000000000000000000000000000000000000000000000000000000000000000"
