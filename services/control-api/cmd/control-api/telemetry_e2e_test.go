//go:build integration

package main

// Control half of tests/telemetry-e2e/run.sh: the dynroute-e2e processes (control-api ->
// NATS -> agent-gateway -> edge-agent in the node runtime image) with the node telemetry pipeline on, the gateway's
// telemetry transport and the control plane's analytics ingest runtime writing ClickHouse. One site with a CC
// policy (JS challenge on /cc-challenge, a 429 rate limit on /cc-limit) bound to a package subscription with a
// connection limit (subscription minute statistics).
//
// Asserts (each read from ClickHouse with FINAL / the count state, compared with what the node logged):
// ① access events = requests; ② the CC challenge pages and 429s are aggregated security lines whose event_count
// sum equals the requests (challenge, block); ③ the subscription minutes of the traffic exist with max_requests > 0;
// ④ with the gateway unreachable for TELEMETRY_E2E_OFFLINE (default 10m) while traffic continues, the spool keeps
// it; once reachable the spool drains and ClickHouse holds every event once (access rows = all requests, security
// counts = all challenge pages / 429s, no minute twice).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const (
	telemetryE2EHost      = "tele.telemetry-e2e.test"
	telemetryE2EEpoch     = "50000000-0000-4000-8000-000000000001"
	telemetryE2ELimitPath = "/cc-limit"
	// Requests per source within one minute before the 429s start (the rate limit rule).
	telemetryE2ELimitMax = 5
)

func TestTelemetryControlProcess(t *testing.T) {
	clickhouseURL := os.Getenv("TELEMETRY_E2E_CLICKHOUSE_URL")
	if clickhouseURL == "" || os.Getenv("DYNROUTE_E2E_DIR") == "" {
		t.Skip("TELEMETRY_E2E_CLICKHOUSE_URL and DYNROUTE_E2E_DIR are required; run tests/telemetry-e2e/run.sh")
	}
	offline := 10 * time.Minute
	if value := os.Getenv("TELEMETRY_E2E_OFFLINE"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			t.Fatal(err)
		}
		offline = parsed
	}
	var installationID string
	var ingest *analyticsIngestProcessRuntime
	hooks := &dynRouteControlHooks{
		beforeServe: func(connection *nats.Conn, js nats.JetStreamContext, pool *pgxpool.Pool,
			publisher *edgepublish.E2EPublisherForTest, runCtx context.Context) {
			if err := pool.QueryRow(t.Context(), `SELECT installation_id FROM control_installation_entitlement WHERE singleton`).
				Scan(&installationID); err != nil {
				t.Fatal(err)
			}
			addTelemetryCompanionStreams(t, js)
			ingest = startTelemetryIngest(t, runCtx, pool, connection, installationID, clickhouseURL)
		},
		identity: func(identity *stubNodeIdentity) {
			scopeID, pool, nodeID, tenantID := identity.tenantScopeForTest(t), identity.pool, identity.nodeID, identity.tenantID
			identity.installationID = installationID
			identity.telemetrySites = func(ctx context.Context, now time.Time) ([]nodeidentity.TelemetrySiteScope, error) {
				return nodeidentity.TelemetrySiteScopesForTest(ctx, pool, nodeID, scopeID, tenantID, now)
			}
		},
	}
	flow := startDynRouteControl(t, hooks)
	telemetry := telemetryFlow{dynRouteFlow: flow, clickhouse: clickhouseURL, ingest: ingest}
	telemetry.run(offline)
}

type telemetryFlow struct {
	*dynRouteFlow
	clickhouse string
	ingest     *analyticsIngestProcessRuntime
	site       uuid.UUID
	sent       int // requests to the site (each one access event)
	minutes    map[int64]bool
	// nodeSecurity: the node's security log at the last settle ("cc/challenge" -> lines, requests).
	nodeSecurity map[string][2]uint64
}

// tenantScopeForTest is the node's configuration scope (E2EPublisherForTest's tenant scope).
func (identity stubNodeIdentity) tenantScopeForTest(t *testing.T) uuid.UUID {
	t.Helper()
	var scopeID uuid.UUID
	if err := identity.pool.QueryRow(t.Context(), `SELECT scope_id FROM nodes WHERE id=$1`, identity.nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	return scopeID
}

// addTelemetryCompanionStreams: the CC coordination, connections and L4 telemetry streams the gateway's publisher
// requires (deploy/nats bootstrap; agent-gateway telemetry_nats_integration_test.go addTelemetryCompanionTestStreams).
func addTelemetryCompanionStreams(t *testing.T, js nats.JetStreamContext) {
	t.Helper()
	for _, stream := range []*nats.StreamConfig{
		{Name: "SECURITY_CC_COORDINATION_V1", Subjects: []string{"cdnca.security.cccoord.v1.*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 2_000_000, MaxBytes: 2 << 30,
			Discard: nats.DiscardNew, MaxAge: 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
			Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute},
		{Name: "CONNECTIONS_INGEST_V1", Subjects: []string{"cdnca.connections.v1.*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 1_000_000, MaxBytes: 2 << 30,
			Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: 1, DiscardNewPerSubject: true,
			MaxMsgSize: 64 << 10, Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute},
		{Name: "L4_SESSIONS_INGEST_V1", Subjects: []string{"cdnca.l4.sessions.v1.*.*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 5_000_000, MaxBytes: 5 << 30,
			Discard: nats.DiscardNew, MaxAge: 30 * 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
			Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute},
	} {
		if _, err := js.AddStream(stream); err != nil {
			t.Fatalf("add %s: %v", stream.Name, err)
		}
	}
}

// startTelemetryIngest opens the control plane's analytics ingest runtime (openAnalyticsIngestRuntime, as main.go)
// on a fresh history generation of the JetStream ingest stream it creates.
func startTelemetryIngest(t *testing.T, ctx context.Context, pool *pgxpool.Pool, connection *nats.Conn, installationID,
	clickhouseURL string) *analyticsIngestProcessRuntime {
	t.Helper()
	jetstreamConfig := analytics.DefaultJetStreamConfig()
	provider, err := analytics.NewAESGCMIsolationKeyProvider("telemetry-e2e", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	jetstreamConfig.IsolationKeyProvider = provider
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	// The isolation evidence bucket is provisioned with NATS, not by the runtime
	// (scripts/native-runtime/native-nats-profile.json KV_AIEVIDENCE_*; analytics expectedEvidenceStore).
	if _, err := js.AddStream(&nats.StreamConfig{Name: "KV_AIEVIDENCE_2dcd3c381ead92f3",
		Subjects: []string{"$KV.AIEVIDENCE_2dcd3c381ead92f3.>"}, Retention: nats.LimitsPolicy, MaxConsumers: -1, MaxMsgs: -1,
		MaxBytes: jetstreamConfig.IsolationMaxBytes, Discard: nats.DiscardNew, MaxMsgsPerSubject: 1, MaxMsgSize: 2162688,
		Storage: nats.FileStorage, Replicas: jetstreamConfig.Replicas, Duplicates: 2 * time.Minute,
		DenyDelete: true, AllowRollup: true, AllowDirect: true}); err != nil {
		t.Fatalf("evidence bucket: %v", err)
	}
	if err := analytics.EnsureIngestJetStream(t.Context(), connection, jetstreamConfig); err != nil {
		t.Fatalf("ingest JetStream: %v", err)
	}
	stream, err := js.StreamInfo(jetstreamConfig.Stream)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := js.ConsumerInfo(jetstreamConfig.Stream, jetstreamConfig.Durable)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// The generation analytics-history-bootstrap records for a new installation (no legacy baseline).
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_history_streams(
		installation_id,nats_domain,stream_name,durable_name,
		stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
		history_start_sequence,history_start_at,legacy_baseline_kind,
		broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,
		revision,last_reconciled_at,created_at,updated_at
	) VALUES($1,'',$2,$3,$4,$5,$6,1,$7,'none',0,0,0,1,$8,$8,$8)`,
		installationID, jetstreamConfig.Stream, jetstreamConfig.Durable, stream.Created.UnixNano(),
		consumer.Created.UnixNano(), telemetryE2EEpoch, consumer.Created.UTC(), now); err != nil {
		t.Fatalf("history generation: %v", err)
	}
	cfg := config.Config{ControlInstallationID: installationID, ShutdownPeriod: 10 * time.Second,
		AnalyticsIngest: config.AnalyticsIngestConfig{Enabled: true, NATSURL: connection.ConnectedUrl(),
			ClickHouseURL: clickhouseURL, ClickHouseDatabase: "default", ConnectTimeout: 5 * time.Second,
			WriteTimeout: 10 * time.Second, SupervisorBackoffMin: time.Second, SupervisorBackoffMax: 5 * time.Second,
			JetStream: jetstreamConfig}}
	runtime, err := openAnalyticsIngestRuntime(ctx, cfg, pool, nil, nats.Connect, nil)
	if err != nil {
		t.Fatalf("analytics ingest runtime: %v", err)
	}
	go func() {
		if err := runtime.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("analytics ingest runtime stopped: %v", err)
		}
	}()
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func (flow *telemetryFlow) run(offline time.Duration) {
	t := flow.t
	flow.minutes = map[int64]bool{}
	flow.waitFor("session declaring SITE_RUNTIME 9", func() bool {
		return flow.declares(agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, 9)
	})
	flow.site = flow.publisher.CreateSite(t, telemetryE2EHost, dynRouteE2ESitePort, "127.0.0.1", dynRouteE2EOriginPort)
	flow.bindPackage()
	flow.bindCCPolicy()
	if state := flow.publish("telemetry site"); state != "healthy" {
		t.Fatalf("telemetry site release: deployment %s", state)
	}
	flow.expect(telemetryE2EHost, "/", 200, "origin "+telemetryE2EHost)
	flow.sent++

	// ①②③ online
	challenge, limited := flow.traffic("127.0.0.71", "127.0.0.72")
	flow.settle("online")
	flow.assertClickHouse("online", challenge, limited)
	t.Logf("PASS ①②③ online: %d access events, CC challenge %d / 429 %d requests, %d subscription minutes in ClickHouse",
		flow.sent, challenge, limited, len(flow.minutes))

	// ④ gateway unreachable for offline, traffic continues, then reconnect
	flow.agentPost("/telemetry/offline")
	started := time.Now()
	before := flow.stats()
	sources := 0
	for time.Since(started) < offline {
		sources++
		c, l := flow.traffic(fmt.Sprintf("127.0.1.%d", sources), fmt.Sprintf("127.0.2.%d", sources))
		challenge, limited = challenge+c, limited+l
		if remaining := offline - time.Since(started); remaining > 0 {
			time.Sleep(min(remaining, 50*time.Second))
		}
	}
	during := flow.stats()
	if during.AckedSequence != before.AckedSequence || during.PendingEvents <= before.PendingEvents {
		t.Fatalf("offline for %s: spool acked %d -> %d, pending %d -> %d (the node must keep what it cannot send)",
			offline, before.AckedSequence, during.AckedSequence, before.PendingEvents, during.PendingEvents)
	}
	t.Logf("offline %s: spool pending %d (acked %d unchanged)", time.Since(started).Round(time.Second), during.PendingEvents, during.AckedSequence)
	flow.agentPost("/telemetry/online")
	flow.settle("after reconnect")
	flow.assertClickHouse("after reconnect", challenge, limited)
	t.Logf("PASS ④ offline %s then reconnect: no loss, no duplicate (%d access events, CC challenge %d / 429 %d, %d minutes)",
		offline, flow.sent, challenge, limited, len(flow.minutes))
}

// bindPackage puts the site on the publisher's package subscription with a connection limit: the site carries
// limits.connections and cdnca_limits keeps its minute statistics (sold_package_limits.go, cdnca_limits.lua).
func (flow *telemetryFlow) bindPackage() {
	t := flow.t
	// custom_cc: the package allows the site's CC policy (package_runtime.go ErrFeatureDenied).
	const spec = `{"limits":{"stream_ports":-1,"http_ports":-1,"root_domains":-1,"connections":1000,"custom_cc":true}}`
	if err := pgx.BeginFunc(t.Context(), flow.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET product_snapshot=jsonb_set(product_snapshot,'{spec}',$2::jsonb)
			WHERE tenant_scope_id=$1`, flow.publisher.ScopeID, spec); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscription_entitlement_versions SET product_snapshot=jsonb_set(product_snapshot,'{spec}',$2::jsonb)
			WHERE tenant_scope_id=$1`, flow.publisher.ScopeID, spec); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE sites SET package_subscription_id=s.id,package_id=s.product_id
			FROM package_subscriptions s WHERE s.tenant_scope_id=$1 AND sites.id=$2`, flow.publisher.ScopeID, flow.site)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// bindCCPolicy binds a CC policy to the site (seeded as edgepublish's security integration tests do): a JS
// challenge on /cc-challenge that never bans, and a fixed window 429 on /cc-limit.
func (flow *telemetryFlow) bindCCPolicy() {
	t := flow.t
	policy := securitypolicy.Policy{ID: uuid.New(), ScopeID: flow.publisher.ScopeID, Kind: securitypolicy.KindCC, Name: "telemetry-e2e",
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: []securitypolicy.Rule{
			{ID: uuid.New(), Name: "challenge", Priority: 1, Enabled: true, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/cc-challenge"}}},
				Action:     securitypolicy.ActionChallenge, ActionConfig: securitypolicy.ActionConfig{Challenge: &securitypolicy.ChallengeConfig{
					Type: "js", FailureWindowSeconds: 60, MaxFailures: 1000, PassSeconds: 600, LogOnly: true, PowBits: 8,
					ChallengeSeconds: 60, BindIPv4Prefix: 32, BindIPv6Prefix: 64, KeyRotateSeconds: 600}}},
			{ID: uuid.New(), Name: "limit", Priority: 2, Enabled: true, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{telemetryE2ELimitPath}}},
				Action:     securitypolicy.ActionRateLimit, ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{
					Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: telemetryE2ELimitMax, ResponseAction: "reject_429"}}},
		}}
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, flow.site)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(policy)
	rules, _ := json.Marshal(policy.Rules)
	bindingID, publicationID, now := uuid.New(), uuid.New(), time.Now().UTC()
	if err := pgx.BeginFunc(t.Context(), flow.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'cc','telemetry-e2e',true,'allow',$5,1,$4,$4,$6,$6)`,
				[]any{policy.ID, flow.publisher.ScopeID, flow.publisher.TenantID, flow.publisher.UserID, rules, now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`,
				[]any{policy.ID, document, flow.publisher.UserID, now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
				last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'cc',1,1,$5,1,$6,$6)`,
				[]any{bindingID, flow.publisher.ScopeID, flow.site, policy.ID, publicationID, now}},
			{`INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
				expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,request_digest,plan_request_digest,
				canonical_payload,canonical_payload_sha256,runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
				actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,'cc',1,0,1,0,$6,'telemetry-e2e',$7,$7,$8,$7,$9,$8,$7,
				'fixture-key',$10,$11,$3,$12,'telemetry-e2e',$10)`,
				[]any{publicationID, bindingID, flow.publisher.ScopeID, flow.site, policy.ID, uuid.New(), make([]byte, 32), document,
					runtime.SHA256[:], now, now.Add(time.Hour), flow.publisher.UserID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return fmt.Errorf("%s: %w", strings.Fields(statement.sql)[2], err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	flow.advanceSourceRevision()
}

// traffic sends, within one minute, plain requests and the CC triggers: challenge pages from challengeSource,
// limitSource over the rate limit. It returns the challenge pages (503) and 429s answered.
func (flow *telemetryFlow) traffic(challengeSource, limitSource string) (challenge, limited int) {
	t := flow.t
	for time.Now().Second() > 40 {
		time.Sleep(500 * time.Millisecond) // the CC aggregates of one source stay in one minute
	}
	flow.minutes[time.Now().UTC().Truncate(time.Minute).Unix()] = true
	plain := flow.burst("127.0.0.70", "/plain", 20)
	pages := flow.burst(challengeSource, "/cc-challenge", 10)
	limits := flow.burst(limitSource, telemetryE2ELimitPath, telemetryE2ELimitMax+8)
	if plain[200] != 20 || pages[503] != 10 || limits[200] != telemetryE2ELimitMax || limits[429] != 8 {
		t.Fatalf("traffic statuses: plain %v, challenge %v, limit %v", plain, pages, limits)
	}
	flow.sent += 20 + 10 + telemetryE2ELimitMax + 8
	return pages[503], limits[429]
}

func (flow *telemetryFlow) burst(source, path string, count int) map[int]int {
	flow.t.Helper()
	var statuses map[int]int
	flow.agentJSON("/telemetry/burst?"+url.Values{"host": {telemetryE2EHost}, "path": {path}, "source": {source},
		"count": {strconv.Itoa(count)}}.Encode(), &statuses)
	return statuses
}

type telemetryAgentStats struct {
	PendingEvents  int                  `json:"pending_events"`
	AckedSequence  uint64               `json:"acked_sequence"`
	NextSequence   uint64               `json:"next_sequence"`
	ExpiredEvents  uint64               `json:"expired_events"`
	WorkerRunning  bool                 `json:"worker_running"`
	WorkerDegraded bool                 `json:"worker_degraded"`
	WorkerError    string               `json:"worker_error"`
	AccessLines    int                  `json:"access_lines"`
	Security       map[string][2]uint64 `json:"security"`
	Error          string               `json:"error"`
}

func (flow *telemetryFlow) stats() telemetryAgentStats {
	var stats telemetryAgentStats
	flow.agentJSON("/telemetry/stats", &stats)
	if stats.Error != "" {
		flow.t.Fatalf("agent spool stats: %s", stats.Error)
	}
	return stats
}

// settle waits until the traffic's minutes are over (the CC aggregates and subscription minutes are written for
// finished minutes only: flush every 5 s, minutes taken every 15 s) and the node's spool is drained.
func (flow *telemetryFlow) settle(what string) {
	t := flow.t
	next := time.Now().UTC().Truncate(time.Minute).Add(time.Minute + 25*time.Second)
	time.Sleep(time.Until(next))
	deadline := time.Now().Add(5 * time.Minute)
	for {
		stats := flow.stats()
		if stats.PendingEvents == 0 && stats.AckedSequence+1 == stats.NextSequence {
			t.Logf("%s: spool drained (acked %d), node logged %d access lines, security %v", what, stats.AckedSequence,
				stats.AccessLines, stats.Security)
			if stats.AccessLines != flow.sent {
				t.Fatalf("%s: node access log %d lines, %d requests sent", what, stats.AccessLines, flow.sent)
			}
			flow.nodeSecurity = stats.Security
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: spool not drained: %+v", what, stats)
		}
		time.Sleep(2 * time.Second)
	}
}

// assertClickHouse compares ClickHouse with the traffic (waiting for the ingest to catch up).
func (flow *telemetryFlow) assertClickHouse(what string, challenge, limited int) {
	t := flow.t
	if node := flow.nodeSecurity; node["cc/challenge"][1] != uint64(challenge) || node["cc/block"][1] != uint64(limited) {
		t.Fatalf("%s: node security log %v, want cc/challenge %d and cc/block %d requests", what, node, challenge, limited)
	}
	site := flow.site.String()
	queries := map[string]string{
		"access":     fmt.Sprintf(`SELECT count() FROM access_events FINAL WHERE site_id='%s'`, site),
		"access_ids": fmt.Sprintf(`SELECT count(DISTINCT event_id) FROM access_events WHERE site_id='%s'`, site),
		"challenge":  fmt.Sprintf(`SELECT toUInt64(sum(event_count)) FROM security_events FINAL WHERE site_id='%s' AND event_type='cc' AND action='challenge'`, site),
		"block":      fmt.Sprintf(`SELECT toUInt64(sum(event_count)) FROM security_events FINAL WHERE site_id='%s' AND event_type='cc' AND action='block'`, site),
		"count_state": fmt.Sprintf(`SELECT toUInt64(sum(c)) FROM (SELECT argMaxMerge(latest_count_state) AS c FROM security_event_count_state_v1
			WHERE event_id IN (SELECT event_id FROM security_events WHERE site_id='%s' AND event_type='cc') GROUP BY tenant_id,event_id)`, site),
		"minutes":     fmt.Sprintf(`SELECT count() FROM subscription_minutes_v1 FINAL WHERE site_id='%s' AND max_requests>0`, site),
		"minute_rows": fmt.Sprintf(`SELECT count() FROM (SELECT minute FROM subscription_minutes_v1 FINAL WHERE site_id='%s' GROUP BY minute,node_id HAVING count()>1)`, site),
	}
	want := map[string]uint64{"access": uint64(flow.sent), "access_ids": uint64(flow.sent), "challenge": uint64(challenge),
		"block": uint64(limited), "count_state": uint64(challenge + limited), "minute_rows": 0}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		got := map[string]uint64{}
		for name, query := range queries {
			got[name] = flow.clickhouseCount(query)
		}
		ok := got["minutes"] >= uint64(len(flow.minutes))
		for name, value := range want {
			ok = ok && got[name] == value
		}
		if ok {
			t.Logf("%s ClickHouse: %v", what, got)
			return
		}
		if time.Now().After(deadline) {
			stats := flow.stats()
			t.Fatalf("%s ClickHouse %v, want %v and minutes >= %d (ingest %+v, node %+v)", what, got, want, len(flow.minutes),
				flow.ingest.Health(), stats)
		}
		time.Sleep(2 * time.Second)
	}
}

func (flow *telemetryFlow) clickhouseCount(query string) uint64 {
	flow.t.Helper()
	response, err := http.Post(flow.clickhouse+"/?default_format=TabSeparated", "text/plain", strings.NewReader(query))
	if err != nil {
		flow.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		flow.t.Fatalf("ClickHouse %s: %s", query, body)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		flow.t.Fatalf("ClickHouse %s: %q", query, body)
	}
	return value
}

func (flow *telemetryFlow) agentPost(path string) {
	flow.t.Helper()
	response, err := http.Post(flow.stateURL+path, "text/plain", nil)
	if err != nil {
		flow.t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		flow.t.Fatalf("agent %s: %s", path, response.Status)
	}
}

func (flow *telemetryFlow) agentJSON(path string, value any) {
	flow.t.Helper()
	response, err := http.Get(flow.stateURL + path)
	if err != nil {
		flow.t.Fatal(err)
	}
	defer response.Body.Close()
	encoded, _ := io.ReadAll(response.Body)
	if err := json.Unmarshal(encoded, value); err != nil {
		flow.t.Fatalf("agent %s: %s", path, encoded)
	}
}
