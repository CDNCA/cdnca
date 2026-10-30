package originfailover_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
	"github.com/cdnca/cdnca/services/control-api/internal/originfailover"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// addNode seeds an active online node of scope whose latest session
// advertises MARKET_PROBE at version (0: none).
func (value *fixture) addNode(t *testing.T, scope uuid.UUID, version uint32) string {
	t.Helper()
	id := uuid.New()
	var features []*agentv1.Capability
	if version != 0 {
		features = []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: version}}
	}
	snapshot, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: "1.0.35", Features: features})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	if err := pgx.BeginFunc(t.Context(), value.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`,
			id, scope, "of-"+id.String()[:8], value.owner); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,'online',1,1,$2,$3,$4,now(),now(),now(),1,1,$2,$3,$4,now(),'running','running',100,50,0,now())`,
			id, uuid.New(), uuid.New(), make([]byte, 32)); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
			certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
			capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,1,$2,$3,'x25519:test',1,0,$4,$3,'\x01',$3,'gw','gw-1',now())`, id, uuid.New(), digest[:], snapshot)
		return err
	}); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return id.String()
}

// recordingPeers answers the primary 192.0.2.10 with the node's outcome and
// every other origin up.
type recordingPeers struct {
	mu      sync.Mutex
	answer  map[string]*originfailover.Outcome
	asked   []string
	targets []originfailover.Target
}

var peerUp = &originfailover.Outcome{OK: true, Voted: true}

func (peers *recordingPeers) Probe(_ context.Context, nodeID string, targets []originfailover.Target) []*originfailover.Outcome {
	peers.mu.Lock()
	defer peers.mu.Unlock()
	peers.asked, peers.targets = append(peers.asked, nodeID), targets
	out := make([]*originfailover.Outcome, len(targets))
	for index, target := range targets {
		out[index] = peerUp
		if target.Host == "192.0.2.10" {
			out[index] = peers.answer[nodeID]
		}
	}
	return out
}

type countingController struct {
	mu     sync.Mutex
	probed int
}

func (controller *countingController) Probe(context.Context, originfailover.Target) originfailover.Outcome {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.probed++
	return originfailover.Outcome{OK: true, Voted: true}
}

func TestOriginProbeRunnerUsesTenantV3NodesWithTwoVotes(t *testing.T) {
	value := newFixture(t, "auto")
	down := &originfailover.Outcome{Voted: true, Reason: "connect"}
	// Only the tenant's own v3 nodes probe: a v2 node and another tenant's v3
	// node are never asked.
	v3a, v3b := value.addNode(t, value.scope, 3), value.addNode(t, value.scope, 3)
	v2 := value.addNode(t, value.scope, 2)
	otherTenant := uuid.New()
	otherScope := uuid.New()
	if _, err := value.pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'other')`, otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := value.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`,
		otherScope, otherTenant); err != nil {
		t.Fatal(err)
	}
	foreign := value.addNode(t, otherScope, 3)
	peers := &recordingPeers{answer: map[string]*originfailover.Outcome{v3a: down, v3b: down, v2: down, foreign: down}}
	controller := &countingController{}
	runner := originfailover.NewRunner(value.pool, value.store, controller, peers, nil)
	for range 3 {
		value.now = value.now.Add(30 * time.Second)
		peers.asked = nil
		if err := runner.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(peers.asked) != 2 {
			t.Fatalf("asked %v, want the two v3 nodes %s %s", peers.asked, v3a, v3b)
		}
		for _, node := range peers.asked {
			if node != v3a && node != v3b {
				t.Fatalf("asked %s (v2 %s, foreign %s)", node, v2, foreign)
			}
		}
	}
	// Two agreeing node votes decide: the control plane is not asked and the
	// primary (http on port 80, an IP origin) goes unhealthy after 3 rounds.
	if controller.probed != 0 {
		t.Fatalf("controller probed %d times", controller.probed)
	}
	if len(peers.targets) != 3 || peers.targets[0].Host != "192.0.2.10" || peers.targets[0].HTTPS || peers.targets[0].Port != 80 ||
		peers.targets[0].Path != "/healthz" || peers.targets[0].HostHeader != "failover.example.test" {
		t.Fatalf("targets %+v", peers.targets)
	}
	status := value.status(t)
	if status.Origins[0].Status != "unhealthy" || status.Origins[0].Reason != "connect" || status.ActiveLevel != 1 {
		t.Fatalf("status %+v", status)
	}
	// A split vote (1:1) is no verdict: the control plane probes that origin.
	peers.answer[v3a] = peerUp
	value.now = value.now.Add(30 * time.Second)
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if controller.probed != 1 {
		t.Fatalf("controller probed %d, want 1 after a split vote", controller.probed)
	}
	// One v3 node left (the other disabled): fewer than 2 possible votes, so
	// the node is not asked and the control plane probes.
	if _, err := value.pool.Exec(t.Context(), `UPDATE nodes SET admin_state='disabled' WHERE id=$1`, v3b); err != nil {
		t.Fatal(err)
	}
	peers.asked = nil
	value.now = value.now.Add(30 * time.Second)
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(peers.asked) != 0 || controller.probed != 4 {
		t.Fatalf("single node: asked %v, controller %d", peers.asked, controller.probed)
	}
}

// TestOriginProbeRunnerFallsBackFromDNSPupToTheControlPlane runs the real
// dnspupprobe source (settings in PG, the dnspup fake): with no v3 node,
// dnspup's checkpoints decide (each one vote), so the primary moves down
// after three failing rounds without the control plane; when dnspup's quota
// runs out the source pauses and the control plane takes over.
func TestOriginProbeRunnerFallsBackFromDNSPupToTheControlPlane(t *testing.T) {
	value := newFixture(t, "auto")
	// Host = the origin itself: dnspup's http probe can express these targets.
	if _, err := value.pool.Exec(t.Context(), `UPDATE site_origin_pools SET request_host_mode='origin' WHERE site_id=$1`,
		value.site); err != nil {
		t.Fatal(err)
	}
	fake, server := dnspuptest.New()
	defer server.Close()
	fake.Do(func(s *dnspuptest.Server) {
		s.PollsUntilDone = 0
		s.Answer = func(request dnspuptest.ProbeRequest) []dnspuptest.Result {
			status := 200
			if strings.Contains(request.Target, "192.0.2.10") {
				status = 502
			}
			return []dnspuptest.Result{{NodeID: "a", Region: "广东", ISP: "电信", Status: "ok", HTTPStatus: status},
				{NodeID: "b", Region: "北京", ISP: "联通", Status: "ok", HTTPStatus: status},
				{NodeID: "c", Region: "上海", ISP: "移动", Status: "unavailable"}}
		}
	})
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dnspup-probe-runner-kek", bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	features := featureSet{dnspupprobe.Feature: true}
	source, err := dnspupprobe.New(dnspupprobe.Config{Pool: value.pool, Cipher: cipher, Features: features,
		Now: func() time.Time { return value.now }})
	if err != nil {
		t.Fatal(err)
	}
	sealedID, sealed, err := cipher.Encrypt([]byte("cdnca-probe-dnspup-secret/v1\x00" + fake.Secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := value.pool.Exec(t.Context(), `UPDATE probe_dnspup_settings SET enabled=true,base_url=$1,api_key=$2,
		secret_key_id=$3,secret_ciphertext=$4,secret_fingerprint='0123456789abcdef',revision=1,updated_at=$5`,
		server.URL, fake.APIKey, sealedID, sealed, value.now); err != nil {
		t.Fatal(err)
	}
	controller := &countingController{}
	runner := originfailover.NewRunner(value.pool, value.store, controller, nil, nil).WithSources(source.Runtime)
	for range 3 {
		value.now = value.now.Add(30 * time.Second)
		if err := runner.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	status := value.status(t)
	if controller.probed != 0 || status.Origins[0].Status != "unhealthy" || status.Origins[0].Reason != "status_5xx" ||
		status.Origins[1].Status != "healthy" || status.ActiveLevel != 1 {
		t.Fatalf("dnspup rounds: controller %d status %+v", controller.probed, status)
	}
	// One charged job per origin and round (2 enabled origins … 3 levels, all enabled: 3 × 3).
	if fake.Creates != 9 || fake.MonthlyUsed != 9 {
		t.Fatalf("creates %d used %d", fake.Creates, fake.MonthlyUsed)
	}
	// Quota exhausted: the round falls back to the control plane and pauses dnspup.
	fake.Do(func(s *dnspuptest.Server) { s.MonthlyLimit = s.MonthlyUsed })
	value.now = value.now.Add(30 * time.Second)
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if controller.probed != 3 {
		t.Fatalf("quota round: controller probed %d", controller.probed)
	}
	var reason string
	if err := value.pool.QueryRow(t.Context(), `SELECT pause_reason FROM probe_dnspup_state`).Scan(&reason); err != nil ||
		reason != dnspupprobe.DegradeQuota {
		t.Fatalf("pause reason %q %v", reason, err)
	}
	// Paused: the next round does not call dnspup at all.
	requests := len(fake.Requests)
	value.now = value.now.Add(30 * time.Second)
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fake.Requests) != requests || controller.probed != 6 {
		t.Fatalf("paused round: dnspup requests %d→%d controller %d", requests, len(fake.Requests), controller.probed)
	}
}

type featureSet map[string]bool

func (set featureSet) ReadValidFeatures(context.Context, pgx.Tx) (map[string]bool, error) {
	return map[string]bool(set), nil
}
