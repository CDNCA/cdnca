//go:build integration

package nodeprobe

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type probeHarness struct {
	t       *testing.T
	ctx     context.Context
	pool    *pgxpool.Pool
	scopeID uuid.UUID
	userID  uuid.UUID
	config  *systemconfig.Service
	head    int64
	display int
}

func newProbeHarness(t *testing.T) *probeHarness {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "node_probe_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	harness := &probeHarness{t: t, ctx: ctx, pool: pool, scopeID: uuid.New(), userID: uuid.New()}
	roleID := uuid.New()
	harness.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, harness.scopeID)
	harness.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'probe-owner','Probe owner','test-only')`, harness.userID)
	harness.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, harness.scopeID, harness.userID)
	harness.exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, roleID, harness.scopeID)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.read'),
		($1,'system_configuration.manage'),($1,'platform.admin'),($1,'node_scheduling.manage')`, roleID)
	harness.exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, harness.scopeID, harness.userID, roleID)
	if harness.config, err = systemconfig.NewServiceWithDependencies(pool, audit.New(pool), time.Now); err != nil {
		t.Fatal(err)
	}
	return harness
}

func (harness *probeHarness) exec(query string, args ...any) {
	harness.t.Helper()
	if _, err := harness.pool.Exec(harness.ctx, query, args...); err != nil {
		harness.t.Fatal(err)
	}
}

func (harness *probeHarness) addNode(ipv4 string) uuid.UUID {
	harness.t.Helper()
	id := uuid.New()
	harness.display++
	harness.exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4)
		VALUES($1,$2,$3,'active',$4,$5,$6)`, id, harness.scopeID, id.String(), harness.userID, harness.display, ipv4)
	return id
}

// activate makes a platform monitoring policy active.
func (harness *probeHarness) activate(groups []string, ratio uint8, failureThreshold int) {
	harness.t.Helper()
	actor := systemconfig.Actor{UserID: harness.userID, ScopeID: harness.scopeID, ScopeKind: "platform"}
	key := "probe-" + uuid.NewString()
	configuration := systemconfig.ProjectBootstrapConfiguration()
	monitoring := systemconfig.EffectiveNodeMonitoring(configuration.NodeMonitoring)
	monitoring.ProbeIntervalMS, monitoring.ProbeTimeoutMS = 10_000, 1_000
	monitoring.FailureThreshold, monitoring.RecoveryThreshold = failureThreshold, 1
	monitoring.MonitorAction, monitoring.Protocol = "pause", "tcp"
	// No monitor_port: each endpoint is probed on its own port.
	monitoring.MonitorGroups, monitoring.FailureRatio, monitoring.MonitorPort = &groups, &ratio, nil
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
	if _, err := harness.config.Activate(harness.ctx, actor, systemconfig.ActivateRequest{
		Revision: draft.Revision, ExpectedActiveRevision: harness.head, IdempotencyKey: key + "-a", RequestID: key + "-a",
	}); err != nil {
		harness.t.Fatal(err)
	}
	harness.head = draft.Revision
}

type harnessEndpoint struct {
	node            uuid.UUID
	address         string
	port            int
	region, carrier string
}

// lineGroup seals revision 1 of a platform line group (policy thresholds
// failure 2, recovery 1, no debounce).
func (harness *probeHarness) lineGroup(endpoints []harnessEndpoint) uuid.UUID {
	harness.t.Helper()
	groupID := uuid.New()
	err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,'probe-group',1,$3,$3,now(),now())`,
			groupID, harness.scopeID, harness.userID); err != nil {
			return err
		}
		if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'probe-group','lg-'||replace($1::uuid::text,'-',''),10000,3000,2,1,0,0,$3,$4,$5,now()-interval '1 hour')`,
			groupID, harness.scopeID, len(endpoints), make([]byte, 32), harness.userID); err != nil {
			return err
		}
		for _, point := range endpoints {
			if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,
				config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,$5,4,$6,$7,$8,0,1,true)`, uuid.New(), point.node, harness.scopeID, groupID,
				point.address, point.port, point.region, point.carrier); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(harness.ctx, `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now()-interval '1 hour',1,now()-interval '1 hour',now()-interval '1 hour'
			FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`, harness.scopeID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(harness.ctx, `UPDATE node_line_group_revisions SET sealed_at=now()-interval '1 hour'
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, harness.scopeID, groupID)
		return err
	})
	if err != nil {
		harness.t.Fatal(err)
	}
	return groupID
}

func (harness *probeHarness) health(groupID uuid.UUID) map[string]string {
	harness.t.Helper()
	rows, err := harness.pool.Query(harness.ctx, `SELECT host(endpoint.address),health.status FROM node_line_endpoint_health health
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=health.tenant_scope_id AND endpoint.line_group_id=health.line_group_id
		 AND endpoint.config_revision=health.config_revision AND endpoint.id=health.endpoint_id
		WHERE health.line_group_id=$1`, groupID)
	if err != nil {
		harness.t.Fatal(err)
	}
	result := map[string]string{}
	for rows.Next() {
		var address, status string
		if err := rows.Scan(&address, &status); err != nil {
			harness.t.Fatal(err)
		}
		result[address] = status
	}
	return result
}

func (harness *probeHarness) externalHold(nodeID uuid.UUID) (bool, string) {
	harness.t.Helper()
	var held bool
	var reason string
	err := harness.pool.QueryRow(harness.ctx, `SELECT held,reason_code FROM node_serving_holds
		WHERE node_id=$1 AND source='external_probe'`, nodeID).Scan(&held, &reason)
	if err == pgx.ErrNoRows {
		return false, ""
	}
	if err != nil {
		harness.t.Fatal(err)
	}
	return held, reason
}

func (harness *probeHarness) serving(groupID uuid.UUID) map[string]bool {
	harness.t.Helper()
	rows, err := harness.pool.Query(harness.ctx, `SELECT host(address),serving FROM node_line_endpoint_serving
		WHERE line_group_id=$1`, groupID)
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

// peerRequester answers MARKET_PROBE commands for every peer with fixed
// results per target address.
type peerRequester struct {
	mu      sync.Mutex
	results map[string]agentv1.MarketProbeOutcome
	asked   map[string]int
}

func (requester *peerRequester) set(results map[string]agentv1.MarketProbeOutcome) {
	requester.mu.Lock()
	defer requester.mu.Unlock()
	requester.results = results
}

func (requester *peerRequester) Request(_ context.Context, nodeID string, payload []byte) ([]byte, error) {
	var command agentv1.MarketProbeCommand
	if err := proto.Unmarshal(payload, &command); err != nil {
		return nil, err
	}
	requester.mu.Lock()
	defer requester.mu.Unlock()
	requester.asked[nodeID]++
	result := &agentv1.MarketProbeResult{NodeId: nodeID, CommandEventId: command.Event.EventId}
	for _, target := range command.Targets {
		outcome, ok := requester.results[target.Ip]
		if !ok {
			outcome = agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED
		}
		result.Results = append(result.Results, &agentv1.MarketProbeTargetResult{TaskId: target.TaskId, Outcome: outcome})
	}
	return proto.Marshal(result)
}

func (harness *probeHarness) peerCapable(nodeID uuid.UUID) {
	harness.t.Helper()
	snapshot, err := proto.Marshal(&agentv1.AgentCapabilities{Features: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: 2}}})
	if err != nil {
		harness.t.Fatal(err)
	}
	// Session facts are seeded with triggers off: only the read side is tested.
	if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(harness.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(harness.ctx, `INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,'online',1,1,$2,$3,$4,now(),now(),now(),1,1,$2,$3,$4,now(),'running','running',100,50,0,now())`,
			nodeID, uuid.New(), uuid.New(), make([]byte, 32)); err != nil {
			return err
		}
		_, err := tx.Exec(harness.ctx, `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
			artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
			facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,1,$2,$3,'k',1,0,$4,$3,'\x00',$3,'gw','gw-1',now())`, nodeID, uuid.New(), make([]byte, 32), snapshot)
		return err
	}); err != nil {
		harness.t.Fatal(err)
	}
}

// TestExternalProbeRecordsHealthAndHoldsUnreachableNodes: the controller
// probes a real local listener (reachable) and a closed port (unreachable);
// verdicts reach line-group endpoint health through RecordProbe, a node
// whose every endpoint is unhealthy gets the external_probe hold and leaves
// the serving set, and recovers when its endpoint answers again.
func TestExternalProbeRecordsHealthAndHoldsUnreachableNodes(t *testing.T) {
	harness := newProbeHarness(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	openPort := listener.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	up, down := harness.addNode("127.0.0.1"), harness.addNode("127.0.0.2")
	harness.activate([]string{GroupDomestic}, 50, 2)
	group := harness.lineGroup([]harnessEndpoint{
		{node: up, address: "127.0.0.1", port: openPort},
		{node: down, address: "127.0.0.2", port: closedPort},
	})
	holds, err := nodeserving.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	loopback := func(address netip.Addr) bool { return !address.IsLoopback() }
	runner, err := NewRunner(Config{Pool: harness.pool, Recorder: nodescheduler.NewService(harness.pool, nil), Holds: holds,
		Controller: NewControllerProber(loopback)})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if health := harness.health(group); health["127.0.0.1"] != "healthy" || health["127.0.0.2"] != "unknown" {
		t.Fatalf("after one round health=%v (failure threshold 2)", health)
	}
	if err := runner.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if health := harness.health(group); health["127.0.0.2"] != "unhealthy" {
		t.Fatalf("after two rounds health=%v", health)
	}
	if held, reason := harness.externalHold(down); !held || reason != ReasonExternalUnreachable {
		t.Fatalf("down node hold=%v %q", held, reason)
	}
	if held, _ := harness.externalHold(up); held {
		t.Fatal("reachable node held")
	}
	if serving := harness.serving(group); serving["127.0.0.2"] || !serving["127.0.0.1"] {
		t.Fatalf("serving=%v", serving)
	}
	var events int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM audit_events WHERE action='node.serving.held'
		AND resource_id=$1`, down.String()).Scan(&events); err != nil || events != 1 {
		t.Fatalf("held audit=%d (%v)", events, err)
	}
	// The endpoint answers again: recovery threshold 1 releases the hold.
	reopened, err := net.Listen("tcp", "127.0.0.2:"+strings.TrimPrefix(closed.Addr().String(), "127.0.0.1:"))
	if err != nil {
		// macOS 的 lo0 只配 127.0.0.1（无 127.0.0.2 别名，需 `ifconfig lo0 alias 127.0.0.2`）；
		// Linux lo 是 127.0.0.0/8，可直接绑定。前面的不可达挂起断言已跑完，这里只跳过恢复段。
		t.Skipf("恢复段需要监听 127.0.0.2，本机回环无此地址（macOS 默认如此）: %v", err)
	}
	defer reopened.Close()
	go func() {
		for {
			connection, err := reopened.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	if err := runner.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, reason := harness.externalHold(down); held || reason != ReasonExternalRecovered {
		t.Fatalf("recovered hold=%v %q", held, reason)
	}
}

func (harness *probeHarness) peerLog(nodeID uuid.UUID) (rows int, failed int, total int, controller *bool, checkpoints []LogCheckpoint) {
	harness.t.Helper()
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM node_peer_probe_results WHERE node_id=$1`, nodeID).
		Scan(&rows); err != nil {
		harness.t.Fatal(err)
	}
	if rows == 0 {
		return
	}
	var raw []byte
	if err := harness.pool.QueryRow(harness.ctx, `SELECT failed_checks,total_checks,controller_ok,checkpoints
		FROM node_peer_probe_results WHERE node_id=$1 ORDER BY observed_at DESC LIMIT 1`, nodeID).
		Scan(&failed, &total, &controller, &raw); err != nil {
		harness.t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &checkpoints); err != nil {
		harness.t.Fatal(err)
	}
	return
}

// TestExternalProbePeerMajorityLogAndDNSPup: peers
// without a region/carrier are asked; with the controller unable to dial the
// documentation addresses the peers' majority decides; every failing round is
// logged with the peer details, an all-good round at most every LogEvery; a
// fresh dnspup verdict releases the hold (dnspup decides) while the peer log
// keeps going.
func TestExternalProbePeerMajorityLogAndDNSPup(t *testing.T) {
	harness := newProbeHarness(t)
	target := harness.addNode("198.51.100.10")
	peerA, peerB, peerC := harness.addNode("198.51.100.21"), harness.addNode("198.51.100.22"), harness.addNode("198.51.100.23")
	harness.activate([]string{GroupTelecom}, 50, 1)
	group := harness.lineGroup([]harnessEndpoint{
		{node: target, address: "198.51.100.10", port: 80},
		{node: peerA, address: "198.51.100.21", port: 80},
		{node: peerB, address: "198.51.100.22", port: 80, region: "广东", carrier: "电信"},
		{node: peerC, address: "198.51.100.23", port: 80},
	})
	for _, peer := range []uuid.UUID{target, peerA, peerB, peerC} {
		harness.peerCapable(peer)
	}
	requester := &peerRequester{asked: map[string]int{}, results: map[string]agentv1.MarketProbeOutcome{
		"198.51.100.10": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED,
		"198.51.100.21": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
		"198.51.100.22": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
		"198.51.100.23": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
	}}
	holds, err := nodeserving.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC()
	now := func() time.Time { return clock }
	runner, err := NewRunner(Config{Pool: harness.pool, Recorder: nodescheduler.NewService(harness.pool, now), Holds: holds,
		Controller: NewControllerProber(nil), Peers: NewPeerProber(requester, now), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // line group failure threshold 2
		if err := runner.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(30 * time.Second)
	}
	requester.mu.Lock()
	asked := len(requester.asked)
	requester.mu.Unlock()
	if asked != 4 {
		t.Fatalf("peers without region/carrier must be asked too: %d", asked)
	}
	if health := harness.health(group); health["198.51.100.10"] != "unhealthy" || health["198.51.100.21"] != "healthy" {
		t.Fatalf("health = %v", health)
	}
	if held, reason := harness.externalHold(target); !held || reason != ReasonExternalUnreachable {
		t.Fatalf("all peers failing: hold=%v %q", held, reason)
	}
	rows, failed, total, controller, checkpoints := harness.peerLog(target)
	if rows != 2 || failed != 3 || total != 3 || controller != nil || len(checkpoints) != 3 {
		t.Fatalf("failing rounds log rows=%d %d/%d controller=%v %+v", rows, failed, total, controller, checkpoints)
	}
	for _, checkpoint := range checkpoints {
		if checkpoint.ID == ControllerProberID || checkpoint.Name == "" || checkpoint.Address == "" || checkpoint.OK {
			t.Fatalf("peer checkpoint detail = %+v", checkpoint)
		}
	}
	// All-good rounds of peerA: one row, the next within LogEvery is skipped.
	if rows, _, _, _, _ := harness.peerLog(peerA); rows != 1 {
		t.Fatalf("all-good rounds within %s logged %d rows", LogEvery, rows)
	}
	clock = clock.Add(LogEvery)
	if err := runner.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if rows, _, _, _, _ := harness.peerLog(peerA); rows != 2 {
		t.Fatalf("all-good round after %s logged %d rows", LogEvery, rows)
	}
	// A minority of peers fails: reachable.
	requester.set(map[string]agentv1.MarketProbeOutcome{
		"198.51.100.10": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
		"198.51.100.21": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
		"198.51.100.22": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
		"198.51.100.23": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
	})
	clock = clock.Add(30 * time.Second)
	if err := runner.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, reason := harness.externalHold(target); held || reason != ReasonExternalRecovered {
		t.Fatalf("recovered hold=%v %q", held, reason)
	}
	// Failing again, but dnspup has a fresh verdict: dnspup decides, the
	// external probe holds nothing and still logs.
	requester.set(map[string]agentv1.MarketProbeOutcome{"198.51.100.10": agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED})
	harness.exec(`INSERT INTO node_dnspup_probe_states(node_id,failing,observed_at,fresh_until,updated_at)
		VALUES($1,false,now(),now()+interval '10 minutes',now())`, target)
	before, _, _, _, _ := harness.peerLog(target)
	for range 2 {
		clock = clock.Add(30 * time.Second)
		if err := runner.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if held, _ := harness.externalHold(target); held {
		t.Fatal("a fresh dnspup verdict must keep the external probe from holding")
	}
	if after, _, _, _, _ := harness.peerLog(target); after != before+2 {
		t.Fatalf("peer log with dnspup: %d -> %d rows", before, after)
	}
	// An operator turns external probing off on a peer: it is no longer asked.
	harness.exec(`UPDATE nodes SET management_settings=jsonb_set(management_settings,'{external_probe}','false') WHERE id=$1`, peerC)
	requester.mu.Lock()
	requester.asked = map[string]int{}
	requester.mu.Unlock()
	if err := runner.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	requester.mu.Lock()
	peerCAsked := requester.asked[peerC.String()]
	requester.mu.Unlock()
	if peerCAsked != 0 {
		t.Fatalf("peer with external_probe off was asked %d times", peerCAsked)
	}
}
