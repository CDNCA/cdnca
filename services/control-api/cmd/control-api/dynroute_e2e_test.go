//go:build integration

package main

// Control half of tests/dynroute-e2e/run.sh (D13-a3b ③, F1 S2): the production edgepublish service publishes site
// runtime v2 releases to a node that declares site_runtime 9 (site objects for the dynamic routing runtime); edge
// outbox -> NATS -> agent-gateway -> edge-agent (in the node runtime container) -> deployment status back through
// NATS -> edgestatus. The node has a real enrollment (Authorize + Complete, active artifact key): the releases are
// sealed to it. Rule pack mounts are published with rulepackcontrol and the mounted pack reaches the node as an item
// of its node artifact set (artifactsetdist reading artifactsync's RulePackSource). Only the gateway's
// authorization call is a stand-in (stubNodeIdentity: the gateway's test PKI is not the enrolled certificate).
//
// Scenarios: ① two v9 sites answer 200 through the dynamic routing runtime, an unknown host does not;
// ② a published mount whose pack is not on the node is refused by the agent precheck (deployment failed, the node
// keeps serving the previous release); ③ the pack arrives with the node artifact set, the release applies and the
// pack's rule r020 blocks /wp-admin on the mounted site only; the mount switched off at the site lets it through.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsetdist"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeoutbox"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Fixed in the agent half (agents/edge-agent/cmd/edge-agent/dynroute_e2e_test.go): the sites' port and the origin
// the agent process serves inside the container.
const (
	dynRouteE2ESitePort   = 18480
	dynRouteE2EOriginPort = 19480
)

func TestDynRouteControlProcess(t *testing.T) {
	flow := startDynRouteControl(t, nil)
	flow.run()
}

// dynRouteControlHooks lets another scenario on the same three processes (tests/telemetry-e2e) add its control
// plane parts before the gateway connects: beforeServe runs once the JetStream streams exist and before
// ControlInternal serves (the gateway checks its streams when it starts); identity adjusts the stand-in node
// identity.
type dynRouteControlHooks struct {
	beforeServe func(connection *nats.Conn, js nats.JetStreamContext, pool *pgxpool.Pool, publisher *edgepublish.E2EPublisherForTest,
		runCtx context.Context)
	identity func(*stubNodeIdentity)
}

// startDynRouteControl is the control half's setup: database, enrolled dynamic routing node, NATS streams, edge
// outbox and status runtime, ControlInternal, node artifact set distributor; it returns once the agent is ready.
func startDynRouteControl(t *testing.T, hooks *dynRouteControlHooks) *dynRouteFlow {
	t.Helper()
	directory, natsURL := os.Getenv("DYNROUTE_E2E_DIR"), os.Getenv("DYNROUTE_E2E_NATS_URL")
	agentURL := os.Getenv("DYNROUTE_E2E_AGENT_URL")
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if directory == "" || natsURL == "" || agentURL == "" || databaseURL == "" {
		t.Skip("DYNROUTE_E2E_DIR, DYNROUTE_E2E_NATS_URL, DYNROUTE_E2E_AGENT_URL and TEST_DATABASE_URL are required; " +
			"run tests/dynroute-e2e/run.sh")
	}
	ctx := t.Context()
	var pki artifactSetPKIFixture
	waitJSONFile(t, filepath.Join(directory, "pki.json"), &pki)
	nodeID := uuid.MustParse(pki.NodeID)
	pool, _, _ := controlE2EDatabase(t, databaseURL)
	publisher := edgepublish.NewE2EPublisherForTest(t, pool, e2eEdgeKeyID)
	artifactKey, artifactKeyID := publisher.AddDynamicRoutingNode(t, nodeID)
	pki.ArtifactKeyID = artifactKeyID

	connection, err := nats.Connect(natsURL, nats.Name("cdnca-dynroute-e2e-control"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []*nats.StreamConfig{
		{Name: "AGENT_COMMANDS", Subjects: []string{"cdnca.agent.commands.>"}, Retention: nats.WorkQueuePolicy,
			Storage: nats.FileStorage, Duplicates: time.Minute},
		{Name: edgestatus.DefaultStatusStream, Subjects: []string{edgestatus.DefaultSubjectPrefix + ".>"},
			Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Duplicates: time.Minute},
		{Name: "AGENT_HEARTBEATS", Subjects: []string{"cdnca.agent.heartbeats.>"}, Retention: nats.LimitsPolicy,
			Storage: nats.FileStorage, MaxAge: time.Hour},
	} {
		if _, err := js.AddStream(stream); err != nil {
			t.Fatal(err)
		}
	}
	statusConfig := edgestatus.DefaultNATSConsumerConfig()
	statusConfig.FetchTimeout, statusConfig.NakDelay = time.Second, 100*time.Millisecond
	if _, err := js.AddConsumer(statusConfig.Stream, &nats.ConsumerConfig{Durable: statusConfig.Durable,
		FilterSubjects: []string{statusConfig.SubjectPrefix + ".*", statusConfig.SubjectPrefix + ".generic-v2.*.*"},
		DeliverPolicy:  nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: statusConfig.AckWait,
		MaxDeliver: -1, ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: statusConfig.MaxAckPending,
		MaxWaiting: statusConfig.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: statusConfig.FetchTimeout}); err != nil {
		t.Fatal(err)
	}
	outboxConfig := edgeoutbox.DefaultConfig()
	outboxConfig.PollInterval = 100 * time.Millisecond
	outbox, err := edgeoutbox.New(pool, connection, outboxConfig)
	if err != nil {
		t.Fatal(err)
	}
	statusRuntime, err := edgestatus.NewRuntime(pool, connection, statusConfig, edgestatus.DefaultValidatorConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopRuntime := context.WithCancel(ctx)
	t.Cleanup(stopRuntime)
	for _, worker := range []runtimeWorker{outbox, statusRuntime} {
		go func() {
			if err := worker.Run(runCtx); err != nil && runCtx.Err() == nil {
				t.Errorf("control worker stopped: %v", err)
			}
		}()
	}
	identity := stubNodeIdentity{pool: pool, nodeID: nodeID, tenantID: publisher.TenantID, artifactKeyID: pki.ArtifactKeyID}
	if hooks != nil && hooks.beforeServe != nil {
		hooks.beforeServe(connection, js, pool, publisher, runCtx)
	}
	if hooks != nil && hooks.identity != nil {
		hooks.identity(&identity)
	}
	serveControlInternalWith(t, runCtx, directory, pki, identity)

	signer := publisher.Signer()
	trustFile := writeArtifactSetTrustFile(t, directory, signer.PublicKey())
	keyFile := filepath.Join(directory, "node-artifact-key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(artifactKey)), 0o400); err != nil {
		t.Fatal(err)
	}
	deployments, err := edgedeployment.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	distributor, err := artifactsetdist.New(artifactsetdist.Config{Pool: pool, Deployments: deployments,
		Source: artifactsync.NewStore(pool, time.Now), Signer: signer, RetryAfter: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	writeE2EJSON(t, directory, "control.json", map[string]string{"trust_file": trustFile,
		"artifact_key_id": artifactKeyID, "artifact_private_key_file": keyFile})
	var agent struct {
		Ready bool `json:"ready"`
	}
	waitJSONFile(t, filepath.Join(directory, "agent.json"), &agent)
	t.Cleanup(func() {
		// DYNROUTE_E2E_HOLD keeps a failed run's agent container up for inspection (docker exec).
		if !t.Failed() || os.Getenv("DYNROUTE_E2E_HOLD") == "" {
			_, _ = http.Post(agentURL+"/done", "text/plain", nil)
		}
		_ = os.WriteFile(filepath.Join(directory, "finished"), nil, 0o600)
	})
	return &dynRouteFlow{artifactSetFlow: artifactSetFlow{t: t, pool: pool, nodeID: nodeID, distributor: distributor,
		stateURL: agentURL}, publisher: publisher, natsConnection: connection}
}

type dynRouteFlow struct {
	artifactSetFlow
	publisher *edgepublish.E2EPublisherForTest
	published int
	// natsConnection: the control half's connection (site drop snapshots and receipts, DYNROUTE_E2E_SITE_DROP).
	natsConnection *nats.Conn
}

type dynRouteAnswer struct {
	Status     int    `json:"status"`
	Body       string `json:"body"`
	RetryAfter string `json:"retry_after"`
	Error      string `json:"error"`
}

func (flow *dynRouteFlow) run() {
	t := flow.t
	flow.waitFor("session declaring SITE_RUNTIME 9 and ARTIFACT_SET", func() bool {
		return flow.declares(agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, 9) &&
			flow.declares(agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, 1)
	})

	// ① two v9 sites
	shop := flow.publisher.CreateSite(t, "shop.dynroute-e2e.test", dynRouteE2ESitePort, "127.0.0.1", dynRouteE2EOriginPort)
	flow.publisher.CreateSite(t, "blog.dynroute-e2e.test", dynRouteE2ESitePort, "127.0.0.1", dynRouteE2EOriginPort)
	if state := flow.publish("v9 sites"); state != "healthy" {
		t.Fatalf("v9 release: deployment %s", state)
	}
	flow.expect("shop.dynroute-e2e.test", "/index.html", 200, "origin shop.dynroute-e2e.test /index.html")
	flow.expect("blog.dynroute-e2e.test", "/", 200, "origin blog.dynroute-e2e.test /")
	flow.expect("shop.dynroute-e2e.test", "/wp-admin/", 200, "origin shop.dynroute-e2e.test /wp-admin/")
	if answer := flow.get("unknown.dynroute-e2e.test", "/"); answer.Status == 200 {
		t.Fatalf("unknown host answered 200: %+v", answer)
	}
	t.Log("PASS ① v9 publish: two sites 200 through the dynamic routing runtime, unknown host refused")

	// ② mount published, pack not on the node yet: the control plane refuses and holds the release.
	packs := rulepackcontrol.NewService(flow.pool, time.Now)
	platform := rulepackcontrol.Actor{UserID: flow.publisher.PlatformUserID, ScopeID: flow.publisher.PlatformScopeID, ScopeKind: "platform"}
	tenant := rulepackcontrol.Actor{UserID: flow.publisher.UserID, ScopeID: flow.publisher.ScopeID, ScopeKind: "tenant"}
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-sqli.json"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := packs.Import(t.Context(), platform, content)
	if err != nil {
		t.Fatalf("import pack: %v", err)
	}
	put := func(input rulepackcontrol.OverrideInput) {
		t.Helper()
		if _, _, err := packs.PutOverride(t.Context(), platform, input); err != nil {
			t.Fatalf("override %+v: %v", input, err)
		}
	}
	put(rulepackcontrol.OverrideInput{Level: rulepack.LevelPlatform, PackID: pack.PackID, State: rulepack.StateDisabled, AllowLower: true})
	put(rulepackcontrol.OverrideInput{Level: rulepack.LevelSite, LevelObjectID: &shop, PackID: pack.PackID, State: rulepack.StateEnabled})
	published, err := packs.PublishSite(t.Context(), tenant, shop)
	if err != nil || published.Published == nil || len(published.Published.Security.Mounts) != 1 {
		t.Fatalf("publish mounts: %+v %v", published.Published, err)
	}
	packDigest := flow.mountedPackDigest(pack.PackID)
	// The control plane refuses (and holds) a release whose mounted pack the node has not applied (b01be8a71);
	// it never reaches the node.
	flow.published++
	_, err = flow.publisher.Publish(t.Context(), fmt.Sprintf("dynroute-e2e-%d", flow.published), flow.nodeID)
	var refusal *edgepublish.RulePackUnavailableError
	if !errors.As(err, &refusal) || refusal.NodeID != flow.nodeID || len(refusal.SHA256) != 1 || refusal.SHA256[0] != packDigest {
		t.Fatalf("release mounting a pack the node lacks: %v, want RulePackUnavailableError for %s", err, packDigest)
	}
	if !flow.exists(fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM edge_capability_publication_holds
		WHERE scope_id='%s' AND refused_node_ids @> ARRAY[$1::uuid])`, flow.publisher.ScopeID)) {
		t.Fatal("refused release not held for the node")
	}
	flow.expect("shop.dynroute-e2e.test", "/wp-admin/", 200, "origin shop.dynroute-e2e.test /wp-admin/")
	t.Logf("PASS ② mount %s@%s published, pack %s not on the node: control plane refused and held the release, previous release serves",
		pack.PackID, pack.CurrentVersion, packDigest)

	// ③ the pack reaches the node with its artifact set; the release applies and the mount enforces.
	flow.sweepUntil("rule pack item applied on the node", func() bool {
		return flow.exists(fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM node_artifact_applied_items
			WHERE node_id=$1 AND artifact_id='%s')`, artifactsetdist.RulePackArtifactID(packDigest)))
	})
	if state := flow.agentDynState(); !state.hasRulePack(packDigest) {
		t.Fatalf("agent artifact set after delivery: %+v", state)
	}
	flow.advanceSourceRevision()
	if state := flow.publish("mount with pack"); state != "healthy" {
		t.Fatalf("release mounting the delivered pack: deployment %s", state)
	}
	if answer := flow.get("shop.dynroute-e2e.test", "/wp-admin/"); answer.Status != 403 {
		t.Fatalf("mounted site /wp-admin/: %+v, want 403 (pack rule r020)", answer)
	}
	flow.expect("shop.dynroute-e2e.test", "/index.html", 200, "origin shop.dynroute-e2e.test /index.html")
	flow.expect("blog.dynroute-e2e.test", "/wp-admin/", 200, "origin blog.dynroute-e2e.test /wp-admin/")
	t.Log("PASS ③ pack delivered in the node artifact set, release applied: mounted site 403 on /wp-admin/, others pass")

	put(rulepackcontrol.OverrideInput{Level: rulepack.LevelSite, LevelObjectID: &shop, PackID: pack.PackID, State: rulepack.StateDisabled})
	if published, err = packs.PublishSite(t.Context(), tenant, shop); err != nil {
		t.Fatalf("publish mounts off: %v", err)
	}
	if state := flow.publish("mount off"); state != "healthy" {
		t.Fatalf("release without the mount: deployment %s", state)
	}
	flow.expect("shop.dynroute-e2e.test", "/wp-admin/", 200, "origin shop.dynroute-e2e.test /wp-admin/")
	t.Log("PASS ③ mount switched off at the site: /wp-admin/ passes again")
}

// publish publishes the scope's source revision and waits for the node's deployment to end; it returns the
// deployment's final state.
func (flow *dynRouteFlow) publish(what string) string {
	t := flow.t
	t.Helper()
	flow.published++
	result, err := flow.publisher.Publish(t.Context(), fmt.Sprintf("dynroute-e2e-%d", flow.published), flow.nodeID)
	if err != nil {
		t.Fatalf("publish %s: %v", what, err)
	}
	var state string
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if err := flow.pool.QueryRow(t.Context(), `SELECT state FROM node_deployments WHERE rollout_id=$1 AND node_id=$2`,
			result.RolloutID, flow.nodeID).Scan(&state); err == nil {
			switch state {
			case "healthy", "failed", "reverted", "rollback_failed", "cancelled":
				t.Logf("%s: config %s deployment %s %s", what, result.ConfigVersionID, state, flow.failure(result.RolloutID))
				if state != "healthy" && os.Getenv("DYNROUTE_E2E_DEBUG") != "" {
					if response, err := http.Get(flow.stateURL + "/debug"); err == nil {
						report, _ := io.ReadAll(response.Body)
						response.Body.Close()
						t.Logf("agent debug:\n%s", report)
					}
				}
				return state
			}
		}
		if time.Now().After(deadline) {
			var fetches, diag string
			_ = flow.pool.QueryRow(t.Context(), `SELECT d.state||' '||d.action||' '||c.status||' '||(d.deadline_at>now())::text FROM node_deployments d JOIN config_versions c ON c.id=d.config_version_id WHERE d.rollout_id=$1`, result.RolloutID).Scan(&diag)
			_ = flow.pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(status||':'||artifact_id::text,','),'')
				FROM artifact_fetch_requests WHERE node_id=$1`, flow.nodeID).Scan(&fetches)
			t.Fatalf("deployment of %s still %q (config %s, %s); artifact fetches: %s", what, state, result.ConfigVersionID, diag, fetches)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// failure is the node's reported error of the rollout's failed transition ("" none).
func (flow *dynRouteFlow) failure(rolloutID uuid.UUID) string {
	var payload []byte
	if err := flow.pool.QueryRow(flow.t.Context(), `SELECT event.payload FROM deployment_status_events event
		JOIN node_deployments deployment ON deployment.id=event.deployment_id AND deployment.attempt=event.attempt
		WHERE deployment.rollout_id=$1 AND event.state='failed' LIMIT 1`, rolloutID).Scan(&payload); err != nil {
		return ""
	}
	status := new(agentv1.DeploymentStatus)
	if proto.Unmarshal(payload, status) != nil {
		return "(undecodable status)"
	}
	return status.GetError().GetCode().String() + ": " + status.GetError().GetMessage()
}

// advanceSourceRevision gives the scope a new source revision (what any site change does), so the same sites can
// be published again after a refused release.
func (flow *dynRouteFlow) advanceSourceRevision() {
	flow.t.Helper()
	if _, err := flow.pool.Exec(flow.t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`,
		flow.publisher.ScopeID); err != nil {
		flow.t.Fatal(err)
	}
}

func (flow *dynRouteFlow) mountedPackDigest(packID string) string {
	flow.t.Helper()
	var digest string
	if err := flow.pool.QueryRow(flow.t.Context(), `SELECT artifact.sha256 FROM rule_pack_site_mount_artifacts mount
		JOIN rule_pack_artifacts artifact ON artifact.pack_id=mount.pack_id AND artifact.version=mount.version
		WHERE mount.pack_id=$1`, packID).Scan(&digest); err != nil {
		flow.t.Fatal(err)
	}
	return digest
}

// get asks the agent half to request host+path on the node runtime's site port (inside the container).
func (flow *dynRouteFlow) get(host, path string) dynRouteAnswer {
	flow.t.Helper()
	response, err := http.Get(flow.stateURL + "/get?" + url.Values{"host": {host}, "path": {path}}.Encode())
	if err != nil {
		flow.t.Fatal(err)
	}
	defer response.Body.Close()
	var answer dynRouteAnswer
	encoded, _ := io.ReadAll(response.Body)
	if err := json.Unmarshal(encoded, &answer); err != nil {
		flow.t.Fatalf("agent /get: %s", encoded)
	}
	return answer
}

func (flow *dynRouteFlow) expect(host, path string, status int, bodyPrefix string) {
	flow.t.Helper()
	if answer := flow.get(host, path); answer.Status != status || !strings.HasPrefix(answer.Body, bodyPrefix) {
		flow.t.Fatalf("%s%s: %+v, want %d %q", host, path, answer, status, bodyPrefix)
	}
}

type dynRouteAgentState struct {
	ArtifactSetRevision uint64   `json:"artifact_set_revision"`
	RulePacks           []string `json:"rule_packs"`
	Scopes              []string `json:"scopes"`
}

func (state dynRouteAgentState) hasRulePack(digest string) bool {
	for _, item := range state.RulePacks {
		if item == digest {
			return true
		}
	}
	return false
}

func (flow *dynRouteFlow) agentDynState() dynRouteAgentState {
	flow.t.Helper()
	response, err := http.Get(flow.stateURL + "/state")
	if err != nil {
		flow.t.Fatal(err)
	}
	defer response.Body.Close()
	var state dynRouteAgentState
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		flow.t.Fatal(err)
	}
	return state
}
