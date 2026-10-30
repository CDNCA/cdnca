package nodeserving

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type servingHarness struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	scopeID  uuid.UUID
	userID   uuid.UUID
	store    *Store
	config   *systemconfig.Service
	head     int64
	sequence int64
	display  int
}

func newServingHarness(t *testing.T) *servingHarness {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "node_serving_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE")
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	harness := &servingHarness{t: t, ctx: ctx, pool: pool, scopeID: uuid.New(), userID: uuid.New()}
	roleID := uuid.New()
	harness.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, harness.scopeID)
	harness.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'serving-owner','Serving owner','test-only')`, harness.userID)
	harness.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, harness.scopeID, harness.userID)
	harness.exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, roleID, harness.scopeID)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.read'),
		($1,'system_configuration.manage'),($1,'platform.admin'),($1,'node_scheduling.manage')`, roleID)
	harness.exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, harness.scopeID, harness.userID, roleID)
	if harness.store, err = NewStore(pool); err != nil {
		t.Fatal(err)
	}
	if harness.config, err = systemconfig.NewServiceWithDependencies(pool, audit.New(pool), time.Now); err != nil {
		t.Fatal(err)
	}
	return harness
}

func (harness *servingHarness) exec(query string, args ...any) {
	harness.t.Helper()
	if _, err := harness.pool.Exec(harness.ctx, query, args...); err != nil {
		harness.t.Fatal(err)
	}
}

func (harness *servingHarness) addNode() uuid.UUID {
	harness.t.Helper()
	id := uuid.New()
	harness.display++
	harness.exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,$5)`,
		id, harness.scopeID, id.String(), harness.userID, harness.display)
	return id
}

// activate makes a platform monitoring policy with the given failure action active.
func (harness *servingHarness) activate(action string) {
	harness.t.Helper()
	actor := systemconfig.Actor{UserID: harness.userID, ScopeID: harness.scopeID, ScopeKind: "platform"}
	key := "serving-" + uuid.NewString()
	configuration := systemconfig.ProjectBootstrapConfiguration()
	monitoring := systemconfig.EffectiveNodeMonitoring(configuration.NodeMonitoring)
	monitoring.ProbeIntervalMS, monitoring.ProbeTimeoutMS = 10_000, 3_000
	monitoring.FailureThreshold, monitoring.RecoveryThreshold = 3, 2
	monitoring.MonitorAction = action
	configuration.NodeMonitoring = &monitoring
	draft, err := harness.config.CreateDraft(harness.ctx, actor, systemconfig.CreateDraftRequest{
		ExpectedHeadRevision: harness.head, Configuration: configuration, IdempotencyKey: key + "-d", RequestID: key + "-d",
	})
	if err != nil {
		harness.t.Fatal(err)
	}
	checks := []systemconfig.PreflightCheck{}
	for _, name := range []string{systemconfig.PreflightSchema, systemconfig.PreflightReferences,
		systemconfig.PreflightCapacity, systemconfig.PreflightNginxSafety, systemconfig.PreflightErrorPages} {
		checks = append(checks, systemconfig.PreflightCheck{Name: name, Status: systemconfig.CheckPass})
	}
	if _, err := harness.config.RecordPreflight(harness.ctx, actor, systemconfig.RecordPreflightRequest{
		Revision: draft.Revision, ExpectedStatus: systemconfig.StatusDraft, SnapshotSHA256: draft.SnapshotSHA256,
		Checks: checks, IdempotencyKey: key + "-p", RequestID: key + "-p",
	}); err != nil {
		harness.t.Fatal(err)
	}
	active := harness.head
	if _, err := harness.config.Activate(harness.ctx, actor, systemconfig.ActivateRequest{
		Revision: draft.Revision, ExpectedActiveRevision: active, IdempotencyKey: key + "-a", RequestID: key + "-a",
	}); err != nil {
		harness.t.Fatal(err)
	}
	harness.head = draft.Revision
}

// report stores one Agent probe report ingested `age` ago on the database clock.
func (harness *servingHarness) report(nodeID uuid.UUID, healthy, succeeded bool, age time.Duration) {
	harness.t.Helper()
	harness.sequence++
	failures, successes := 0, 1
	if !succeeded {
		failures, successes = 1, 0
	}
	harness.exec(`INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
		publication_sequence,observed_at,metrics_known,puback_stream,puback_sequence,consumer_durable,consumer_sequence,
		num_delivered,wire_sha256,ingested_at,record_kind,active_config_revision,probe_port,healthy,probe_succeeded,
		consecutive_failures,consecutive_successes,probes_total,probe_failures_total,recovered,recovery_notified,rolled_back)
		VALUES($1,$2,$3,1,1,$4,clock_timestamp()-$5::interval,false,'NODE_MONITORING_STATUS',$4,'control_api_node_metrics',$4,
		1,$6,clock_timestamp()-$5::interval,'metric',1,80,$7,$8,$9::integer,$10::integer,10,$9::integer,false,false,false)`,
		uuid.New(), uuid.New(), nodeID, harness.sequence, age.String(), make([]byte, 32), healthy, succeeded, failures, successes)
}

// lineGroup seals revision 1 of a platform line group with one enabled
// endpoint per node (same statements as the edgepublish resolver fixture).
func (harness *servingHarness) lineGroup(addresses map[uuid.UUID]string) (uuid.UUID, int64) {
	harness.t.Helper()
	groupID := uuid.New()
	err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,'serving-group',1,$3,$3,now(),now())`,
			groupID, harness.scopeID, harness.userID); err != nil {
			return err
		}
		if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'serving-group','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,$3,$4,$5,now())`,
			groupID, harness.scopeID, len(addresses), make([]byte, 32), harness.userID); err != nil {
			return err
		}
		for nodeID, address := range addresses {
			family := 4
			if strings.Contains(address, ":") {
				family = 6
			}
			if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,
				config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,$5,$6,80,'','',0,1,true)`, uuid.New(), nodeID, harness.scopeID, groupID, address, family); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now() FROM node_line_endpoints
			WHERE tenant_scope_id=$1 AND line_group_id=$2`, harness.scopeID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(harness.ctx, `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, harness.scopeID, groupID)
		return err
	})
	if err != nil {
		harness.t.Fatal(err)
	}
	return groupID, 1
}

func (harness *servingHarness) hold(nodeID uuid.UUID) (bool, string, int) {
	harness.t.Helper()
	var held bool
	var reason string
	var protected int
	err := harness.pool.QueryRow(harness.ctx, `SELECT held,reason_code,protected_groups FROM node_serving_holds
		WHERE node_id=$1 AND source='availability_monitor'`, nodeID).Scan(&held, &reason, &protected)
	if err == pgx.ErrNoRows {
		return false, "", 0
	}
	if err != nil {
		harness.t.Fatal(err)
	}
	return held, reason, protected
}

func (harness *servingHarness) serving(groupID uuid.UUID, revision int64) map[string]bool {
	harness.t.Helper()
	rows, err := harness.pool.Query(harness.ctx, `SELECT host(address),serving FROM node_line_endpoint_serving
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3`, harness.scopeID, groupID, revision)
	if err != nil {
		harness.t.Fatal(err)
	}
	result := map[string]bool{}
	for rows.Next() {
		var address string
		var serving bool
		if err := rows.Scan(&address, &serving); err != nil {
			harness.t.Fatal(err)
		}
		result[address] = serving
	}
	return result
}

func TestMonitorPauseRemovesNodeFromServingEndpointsAndRestoresIt(t *testing.T) {
	harness := newServingHarness(t)
	nodeA, nodeB, nodeC := harness.addNode(), harness.addNode(), harness.addNode()
	groupID, revision := harness.lineGroup(map[uuid.UUID]string{nodeA: "192.0.2.1", nodeB: "192.0.2.2", nodeC: "2001:db8::3"})
	harness.activate("pause")
	evaluator := NewMonitorEvaluator(harness.store)
	worker, err := NewWorker(harness.store, time.Second, nil, evaluator)
	if err != nil {
		t.Fatal(err)
	}

	harness.report(nodeA, false, false, time.Second)
	harness.report(nodeB, true, true, time.Second)
	harness.report(nodeC, false, false, time.Second)
	for range 2 { // the second run must be a no-op
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if held, reason, protected := harness.hold(nodeA); !held || reason != ReasonProbeUnhealthy || protected != 0 {
		t.Fatalf("node A hold = %v %q %d", held, reason, protected)
	}
	// C is the only IPv6 endpoint: held, but kept serving and reported protected.
	if held, _, protected := harness.hold(nodeC); !held || protected != 1 {
		t.Fatalf("node C hold = %v protected=%d", held, protected)
	}
	if held, _, _ := harness.hold(nodeB); held {
		t.Fatal("healthy node B was held")
	}
	if got := harness.serving(groupID, revision); got["192.0.2.1"] || !got["192.0.2.2"] || !got["2001:db8::3"] {
		t.Fatalf("serving set after pause = %v", got)
	}
	var events int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM node_serving_events`).Scan(&events); err != nil || events != 3 {
		t.Fatalf("events = %d %v; want held A, held C, protected C", events, err)
	}
	var audits int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1
		AND action LIKE 'node.serving.%' AND actor_user_id IS NULL AND resource_type='node'`, harness.scopeID).Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("serving audits = %d %v", audits, err)
	}

	// One healthy report is below recovery_threshold=2: still held.
	harness.report(nodeA, true, true, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, _, _ := harness.hold(nodeA); !held {
		t.Fatal("node A released before the recovery threshold")
	}
	harness.report(nodeA, true, true, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, reason, _ := harness.hold(nodeA); held || reason != ReasonProbeRecovered {
		t.Fatalf("node A not restored: held=%v reason=%q", held, reason)
	}
	if got := harness.serving(groupID, revision); !got["192.0.2.1"] {
		t.Fatalf("node A not back in serving set: %v", got)
	}

	// A node that stops reporting is held after the stale window, once warm.
	harness.report(nodeB, true, true, 2*time.Minute)
	evaluator.warmUntil = time.Time{}.Add(time.Nanosecond)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, reason, _ := harness.hold(nodeB); !held || reason != ReasonProbeStale {
		t.Fatalf("silent node B hold = %v %q", held, reason)
	}

	// Switching the failure action back to "none" releases every hold.
	harness.activate("none")
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	for _, node := range []uuid.UUID{nodeA, nodeB, nodeC} {
		if held, _, protected := harness.hold(node); held || protected != 0 {
			t.Fatalf("node %s still held after action none", node)
		}
	}
	if got := harness.serving(groupID, revision); !got["192.0.2.1"] || !got["192.0.2.2"] || !got["2001:db8::3"] {
		t.Fatalf("serving set after release = %v", got)
	}
	page, err := harness.store.Events(harness.ctx, harness.scopeID, nodeC, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 1, 10)
	if err != nil || page.Total != 3 || page.Items[0].Event != EventReleased || page.Items[0].ReasonCode != ReasonActionNone {
		t.Fatalf("node C events = %+v %v", page, err)
	}
	if _, err := harness.store.Events(harness.ctx, uuid.New(), nodeC, time.Now().Add(-time.Hour), time.Now(), 1, 10); err != ErrNotFound {
		t.Fatalf("foreign scope events: %v", err)
	}

	// Admin-disabled endpoints and nodes never serve, independent of holds.
	harness.exec(`UPDATE nodes SET admin_state='disabled' WHERE id=$1`, nodeB)
	if got := harness.serving(groupID, revision); got["192.0.2.2"] {
		t.Fatalf("disabled node still serving: %v", got)
	}
}

// telemetry stores one report with per-NIC counters observed `age` ago.
func (harness *servingHarness) telemetry(nodeID uuid.UUID, age time.Duration, interfaces ...map[string]any) {
	harness.t.Helper()
	harness.sequence++
	encoded, err := json.Marshal(map[string]any{"schema_version": 1, "network_interfaces": interfaces, "total_rx_bytes": 0, "total_tx_bytes": 0})
	if err != nil {
		harness.t.Fatal(err)
	}
	harness.exec(`INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
		publication_sequence,observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,active_connections,
		rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,puback_sequence,consumer_durable,consumer_sequence,
		num_delivered,wire_sha256,ingested_at,record_kind,telemetry_json,total_rx_bytes,total_tx_bytes)
		VALUES($1,$2,$3,1,0,$4,clock_timestamp()-$5::interval,true,1,1,2,0,0,0,'NODE_MONITORING_STATUS',$4,
		'control_api_node_metrics',$4,1,$6,clock_timestamp(),'host_metric',$7,0,0)`,
		uuid.New(), uuid.New(), nodeID, harness.sequence, age.String(), make([]byte, 32), encoded)
}

func nic(name string, tx uint64, txBPS uint64) map[string]any {
	return map[string]any{"name": name, "rx_bytes": 0, "tx_bytes": tx, "rx_bandwidth_bps": 0, "tx_bandwidth_bps": txBPS}
}

func (harness *servingHarness) autoDisable(nodeID uuid.UUID, settings map[string]any) {
	harness.t.Helper()
	encoded, _ := json.Marshal(settings)
	harness.exec(`UPDATE nodes SET management_settings=jsonb_set(management_settings,'{auto_disable}',
		(management_settings->'auto_disable') || $2::jsonb) WHERE id=$1`, nodeID, encoded)
}

func (harness *servingHarness) autoHold(nodeID uuid.UUID) (bool, string) {
	harness.t.Helper()
	var held bool
	var reason string
	err := harness.pool.QueryRow(harness.ctx, `SELECT held,reason_code FROM node_serving_holds
		WHERE node_id=$1 AND source='auto_disable'`, nodeID).Scan(&held, &reason)
	if err == pgx.ErrNoRows {
		return false, ""
	}
	if err != nil {
		harness.t.Fatal(err)
	}
	return held, reason
}

func TestAutoDisableEnforcesTrafficBandwidthAndWindowsThroughServingHolds(t *testing.T) {
	harness := newServingHarness(t)
	nodeA, nodeB, spare := harness.addNode(), harness.addNode(), harness.addNode()
	groupID, revision := harness.lineGroup(map[uuid.UUID]string{nodeA: "192.0.2.1", nodeB: "192.0.2.2", spare: "192.0.2.3"})
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
	local := now.In(chinaStandardTime)
	// The period started one hour ago (a day <= 28 keeps the anchor valid).
	anchor := local.Add(-time.Hour)
	day := anchor.Day()
	if day > 28 {
		day = 28
	}
	harness.autoDisable(nodeA, map[string]any{"traffic_enabled": true, "traffic_total_gb": 1, "traffic_from_day": day,
		"traffic_from_time": anchor.Format("15:04:05"), "traffic_types": []string{"outbound"}, "excluded_interfaces": "docker0"})

	// Before the period: never counted. In the period: baseline, then 1.2 GiB out on eth0.
	harness.telemetry(nodeA, 3*time.Hour, nic("eth0", 0, 0))
	harness.telemetry(nodeA, 30*time.Minute, nic("eth0", 1<<30, 0), nic("docker0", 0, 0))
	harness.telemetry(nodeA, 20*time.Minute, nic("eth0", 1<<30+(1<<29), 0), nic("docker0", 8<<30, 0))
	run()
	if held, _ := harness.autoHold(nodeA); held {
		t.Fatal("0.5 GiB of a 1 GiB quota held the node")
	}
	// Reboot: counter restarts; the 0.6 GiB since it still counts.
	harness.telemetry(nodeA, 10*time.Minute, nic("eth0", 600<<20, 0))
	run()
	if held, reason := harness.autoHold(nodeA); !held || reason != ReasonTrafficExceeded {
		t.Fatalf("over quota: held=%v reason=%q", held, reason)
	}
	if got := harness.serving(groupID, revision); got["192.0.2.1"] || !got["192.0.2.2"] {
		t.Fatalf("serving set with node A over quota = %v", got)
	}
	var usage int64
	if err := harness.pool.QueryRow(harness.ctx, `SELECT usage_bytes FROM node_auto_disable_usage WHERE node_id=$1`, nodeA).Scan(&usage); err != nil ||
		usage != (1<<29)+(600<<20) {
		t.Fatalf("usage = %d %v", usage, err)
	}
	run() // idempotent
	// Raising the quota releases it.
	harness.autoDisable(nodeA, map[string]any{"traffic_total_gb": 2})
	run()
	if held, reason := harness.autoHold(nodeA); held || reason != ReasonSettingsChanged {
		t.Fatalf("raised quota: held=%v reason=%q", held, reason)
	}

	// Bandwidth: three live samples over 100 Mbps hold; the hold lasts at least 5 minutes.
	harness.autoDisable(nodeB, map[string]any{"bandwidth_limit": 100, "bandwidth_unit": "Mbps", "traffic_types": []string{"outbound"}})
	for range 2 {
		harness.telemetry(nodeB, time.Second, nic("eth0", 0, 200_000_000))
	}
	run()
	if held, _ := harness.autoHold(nodeB); held {
		t.Fatal("two samples over the limit held the node")
	}
	harness.telemetry(nodeB, time.Second, nic("eth0", 0, 200_000_000))
	run()
	if held, reason := harness.autoHold(nodeB); !held || reason != ReasonBandwidthExceeded {
		t.Fatalf("bandwidth: held=%v reason=%q", held, reason)
	}
	for range 3 {
		harness.telemetry(nodeB, time.Second, nic("eth0", 0, 10_000_000))
	}
	run()
	if held, _ := harness.autoHold(nodeB); !held {
		t.Fatal("bandwidth hold released before the minimum hold time")
	}
	// Time travel past the minimum hold (a revision-advancing write, as the trigger requires).
	harness.exec(`UPDATE node_serving_holds SET held_since=held_since-interval '10 minutes',revision=revision+1,
		changed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE node_id=$1 AND source='auto_disable'`, nodeB)
	run()
	if held, reason := harness.autoHold(nodeB); held || reason != ReasonBandwidthRecovered {
		t.Fatalf("bandwidth recovery: held=%v reason=%q", held, reason)
	}

	// Disabled window around now, then a window that excludes now.
	window := func(from, to time.Time) string { return from.Format("15:04:05") + "-" + to.Format("15:04:05") }
	harness.autoDisable(nodeB, map[string]any{"bandwidth_limit": 0, "disabled_periods": window(local.Add(-time.Minute), local.Add(30*time.Minute))})
	run()
	if held, reason := harness.autoHold(nodeB); !held || reason != ReasonDisabledPeriod {
		t.Fatalf("window: held=%v reason=%q", held, reason)
	}
	harness.autoDisable(nodeB, map[string]any{"disabled_periods": window(local.Add(time.Hour), local.Add(2*time.Hour))})
	run()
	if held, reason := harness.autoHold(nodeB); held || reason != ReasonPeriodEnded {
		t.Fatalf("window end: held=%v reason=%q", held, reason)
	}
	var events int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM node_serving_events WHERE source='auto_disable'`).Scan(&events); err != nil || events != 6 {
		t.Fatalf("auto-disable events = %d %v", events, err)
	}
	if got := harness.serving(groupID, revision); !got["192.0.2.1"] || !got["192.0.2.2"] {
		t.Fatalf("serving set after releases = %v", got)
	}
}

// deploy records one deployment of the harness scope to nodeID in state.
func (harness *servingHarness) deploy(nodeID uuid.UUID, state string, deadline time.Time) {
	harness.t.Helper()
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	command := []byte(deploymentID.String())
	digest := sha256.Sum256(command)
	harness.exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,$3,$4,'integration','1','releasable',$5,$6,now(),now())`,
		configID, harness.scopeID, command, digest[:], configID.String(), make([]byte, 32))
	harness.exec(`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
		request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
		created_at,queued_at,updated_at) VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$6,60000,60000,1,$7,now(),now(),now())`,
		rolloutID, harness.scopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New(), deadline)
	harness.exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
		command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
		VALUES($1,$2,$3,1,$4,'apply',$5,$6,$7,$8,$9,clock_timestamp()-interval '1 second',clock_timestamp()-interval '1 second',$10)`,
		deploymentID, rolloutID, nodeID, configID, state, uuid.New(), command, digest[:], deadline.Add(-time.Millisecond), harness.scopeID)
}

func (harness *servingHarness) syncHold(nodeID uuid.UUID) (bool, string) {
	harness.t.Helper()
	var held bool
	var reason string
	err := harness.pool.QueryRow(harness.ctx, `SELECT held,reason_code FROM node_serving_holds
		WHERE node_id=$1 AND source='config_sync'`, nodeID).Scan(&held, &reason)
	if err == pgx.ErrNoRows {
		return false, ""
	}
	if err != nil {
		harness.t.Fatal(err)
	}
	return held, reason
}

func (harness *servingHarness) disableFailedSyncNodes(enabled bool) {
	harness.t.Helper()
	settings := systemothersettings.DefaultSettings()
	settings.DisableFailedSyncNodes = enabled
	encoded, err := json.Marshal(settings)
	if err != nil {
		harness.t.Fatal(err)
	}
	harness.exec(`INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at)
		VALUES($1,1,$2,$3,now()) ON CONFLICT (platform_scope_id) DO UPDATE SET settings=EXCLUDED.settings,
		revision=platform_system_other_settings.revision+1`, harness.scopeID, string(encoded), harness.userID)
}

type syncRetrierStub struct{ calls []uuid.UUID }

func (stub *syncRetrierStub) RetryNodeSync(_ context.Context, nodeID, _ uuid.UUID, _ time.Time) (bool, error) {
	stub.calls = append(stub.calls, nodeID)
	return true, nil
}

// NF04: with "disable failed sync nodes" on, a node whose newest deployment
// failed leaves customer DNS (at most half of a line group), is retried after
// 30 minutes, and returns once its deployment is healthy.
func TestConfigSyncHoldRemovesFailedNodeFromDNSAndRestoresIt(t *testing.T) {
	harness := newServingHarness(t)
	healthy, failing, failingToo := harness.addNode(), harness.addNode(), harness.addNode()
	groupID, revision := harness.lineGroup(map[uuid.UUID]string{
		healthy: "192.0.2.51", failing: "192.0.2.52", failingToo: "192.0.2.53"})
	future := time.Now().Add(time.Hour)
	harness.deploy(healthy, "healthy", future)
	harness.deploy(failing, "failed", future)
	harness.deploy(failingToo, "failed", future)
	retrier := &syncRetrierStub{}
	evaluator := NewConfigSyncEvaluator(harness.store, retrier)
	run := func() {
		t.Helper()
		worker, err := NewWorker(harness.store, time.Second, nil, evaluator)
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}

	// The switch is off by default: failures change nothing.
	run()
	if held, _ := harness.syncHold(failing); held {
		t.Fatal("held with disable_failed_sync_nodes off")
	}

	harness.disableFailedSyncNodes(true)
	run()
	firstHeld, _ := harness.syncHold(failing)
	secondHeld, _ := harness.syncHold(failingToo)
	if firstHeld == secondHeld {
		t.Fatalf("exactly one of two failing nodes may be held in a three-node group: %v %v", firstHeld, secondHeld)
	}
	heldNode, otherNode, heldAddress := failing, failingToo, "192.0.2.52"
	if secondHeld {
		heldNode, otherNode, heldAddress = failingToo, failing, "192.0.2.53"
	}
	if serving := harness.serving(groupID, revision); serving[heldAddress] || !serving["192.0.2.51"] {
		t.Fatalf("serving after hold = %v", serving)
	}
	if _, reason := harness.syncHold(otherNode); reason != ReasonSyncLimitGuard && reason != "" {
		t.Fatalf("over-limit node reason = %q", reason)
	}

	// After 30 minutes the held node's failing scope is republished.
	run()
	if len(retrier.calls) != 0 {
		t.Fatalf("retried before 30 minutes: %v", retrier.calls)
	}
	// The hold trigger only allows revision steps; backdate with triggers off.
	if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(harness.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(harness.ctx, `UPDATE node_serving_holds SET held_since=held_since-interval '31 minutes',
			changed_at=changed_at-interval '31 minutes' WHERE node_id=$1 AND source='config_sync'`, heldNode)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	run()
	if len(retrier.calls) != 1 || retrier.calls[0] != heldNode {
		t.Fatalf("retry calls = %v, want %s", retrier.calls, heldNode)
	}

	// The retry succeeds: the node serves again.
	harness.deploy(heldNode, "healthy", future)
	run()
	if held, reason := harness.syncHold(heldNode); held || reason != ReasonSyncRecovered {
		t.Fatalf("hold after healthy deployment = %v %s", held, reason)
	}
	if serving := harness.serving(groupID, revision); !serving[heldAddress] {
		t.Fatalf("serving after recovery = %v", serving)
	}

	// The other failing node takes the freed slot; once it is healthy too,
	// a deployment past its deadline without a result counts as failed.
	if held, _ := harness.syncHold(otherNode); !held {
		t.Fatal("the second failing node was not held once the first recovered")
	}
	harness.deploy(otherNode, "healthy", future)
	harness.deploy(healthy, "delivered", time.Now().Add(time.Second))
	time.Sleep(1100 * time.Millisecond)
	run() // releases the recovered node; the cap still counts it as held this tick
	run()
	if held, reason := harness.syncHold(healthy); !held || reason != ReasonSyncFailed {
		t.Fatalf("timed-out deployment hold = %v %s", held, reason)
	}
}

// A failed IP library delivery (node-side artifact, migration 329) is not a
// failed configuration sync: it never takes the node out of DNS.
func TestConfigSyncHoldIgnoresFailedNodeArtifactDelivery(t *testing.T) {
	harness := newServingHarness(t)
	first, second, library := harness.addNode(), harness.addNode(), harness.addNode()
	harness.lineGroup(map[uuid.UUID]string{first: "192.0.2.61", second: "192.0.2.62", library: "192.0.2.63"})
	future := time.Now().Add(time.Hour)
	harness.deploy(first, "healthy", future)
	harness.deploy(second, "healthy", future)
	harness.deploy(library, "healthy", future)
	harness.deployNodeArtifact(library, "failed", future)
	harness.disableFailedSyncNodes(true)
	worker, err := NewWorker(harness.store, time.Second, nil, NewConfigSyncEvaluator(harness.store, &syncRetrierStub{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, reason := harness.syncHold(library); held {
		t.Fatalf("failed IP library delivery held the node (%s)", reason)
	}
}

// deployNodeArtifact is deploy for a configuration holding a node artifact
// set (artifacts are bound before the config is published).
func (harness *servingHarness) deployNodeArtifact(nodeID uuid.UUID, state string, deadline time.Time) {
	harness.t.Helper()
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	command := []byte(deploymentID.String())
	digest := sha256.Sum256(command)
	harness.exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,$4,'integration','1','building',$5,$6,now())`,
		configID, harness.scopeID, command, digest[:], configID.String(), make([]byte, 32))
	keyID := "nodeserving-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	harness.exec(`INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at) VALUES($1,'ed25519',$2,now())`,
		keyID, make([]byte, 32))
	wire := []byte("manifest")
	wireDigest := sha256.Sum256(wire)
	harness.exec(`INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,
		signing_key_id,signature_algorithm,compression,media_type,encryption_algorithm,created_at)
		VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none',$8,'none',now())`,
		uuid.New(), configID, wire, len(wire), wireDigest[:], make([]byte, 64), keyID, artifactset.MediaTypeSet)
	harness.exec(`UPDATE config_versions SET status='validating' WHERE id=$1`, configID)
	harness.exec(`UPDATE config_versions SET status='releasable',published_at=now() WHERE id=$1`, configID)
	harness.exec(`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
		request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
		created_at,queued_at,updated_at) VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$6,60000,60000,1,$7,now(),now(),now())`,
		rolloutID, harness.scopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New(), deadline)
	harness.exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
		command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id,queued_per_scope)
		VALUES($1,$2,$3,1,$4,'apply',$5,$6,$7,$8,$9,clock_timestamp(),clock_timestamp(),$10,true)`,
		deploymentID, rolloutID, nodeID, configID, state, uuid.New(), command, digest[:], deadline.Add(-time.Millisecond), harness.scopeID)
}
