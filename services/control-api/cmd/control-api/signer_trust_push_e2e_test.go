package main

// Control-api half of tests/signer-trust-push-e2e/run.sh (节点签名者吊销推送). Processes:
//   - authorization center download origin (tests/signer-trust-push-e2e/authority.go): HTTPS static files;
//   - this control-api: production buildEdgeSignerTrustRuntime from the installer environment (offline root pin,
//     EDGE_SIGNER_TRUST_URL, TLS CA, downloads directory) with the edge publication signer and edge NATS, so the
//     fetcher, PostgreSQL store, download refresh and the capability-gated distributor are production code;
//   - agent-gateway (TestSignerTrustGatewayProcess) and edge-agent (TestSignerTrustAgentAgainstControlProcess).
//
// The operator side is the production offline tool: run.sh generated the root with `signer-offline-root keygen`,
// this test drafts documents and signs them with `signer-offline-root sign-edge-trust` (SIGNER_PUSH_E2E_OFFLINE_TOOL),
// then publishes them by copying into the authority's downloads directory (runbook §5 step 3). The fetch tick is
// driven by calling the fetcher's FetchOnce (the production ticker interval is at least one minute).
//
// Stand-in: node rows and node_session_capabilities are inserted here. The capabilities snapshot is the one the
// gateway process reported in its session facts (session-capabilities.bin); recording it through nodeidentity needs
// a full enrollment (certificates, CA epochs) that this test does not exercise.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/signertrust"
	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgesignertrustsync"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const e2eEdgeKeyID = "edge-execution-e2e"

func waitJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		encoded, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(encoded, value) == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not ready: %v", filepath.Base(path), err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type signerPushAgentState struct {
	Revision     uint64                  `json:"revision"`
	Trusted      map[string]bool         `json:"trusted"`
	Receipt      edgesignertrust.Receipt `json:"receipt"`
	AppliedCount int                     `json:"applied_count"`
	Restarts     int                     `json:"restarts"`
}

func TestSignerTrustPushControlProcess(t *testing.T) {
	directory, databaseURL := os.Getenv("SIGNER_PUSH_E2E_DIR"), os.Getenv("TEST_DATABASE_URL")
	natsURL, tool, rootDir := os.Getenv("SIGNER_PUSH_E2E_NATS_URL"), os.Getenv("SIGNER_PUSH_E2E_OFFLINE_TOOL"),
		os.Getenv("SIGNER_PUSH_E2E_ROOT_DIR")
	if directory == "" || databaseURL == "" || natsURL == "" || tool == "" || rootDir == "" {
		t.Skip("run tests/signer-trust-push-e2e/run.sh")
	}
	defer func() { _ = os.WriteFile(filepath.Join(directory, "finished"), nil, 0o600) }()
	var authority struct {
		Origin       string `json:"origin"`
		CAFile       string `json:"ca_file"`
		DownloadsDir string `json:"downloads_dir"`
	}
	waitJSONFile(t, filepath.Join(directory, "authority.json"), &authority)
	var root struct {
		KeyID              string `json:"key_id"`
		Generation         uint64 `json:"generation"`
		PublicKeyBase64URL string `json:"public_key_base64url"`
	}
	waitJSONFile(t, filepath.Join(rootDir, "e2e-offline-root-g1.public.json"), &root)
	rootKey := filepath.Join(rootDir, "e2e-offline-root-g1.key.pem")

	// Keys: the control plane's edge publication key and three platform release keys.
	newKey := func() ed25519.PrivateKey {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return private
	}
	controlKey, releaseOld, releaseOther, releaseNew := newKey(), newKey(), newKey(), newKey()
	publicPEM := func(key ed25519.PrivateKey) string {
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	artifactTrust, _ := json.Marshal(map[string]any{"version": 1, "keys": []map[string]string{
		{"key_id": e2eEdgeKeyID, "public_key_pem": publicPEM(controlKey)},
		{"key_id": "release-old", "public_key_pem": publicPEM(releaseOld)},
		{"key_id": "release-other", "public_key_pem": publicPEM(releaseOther)}}})
	// The node's installed trust (artifact_trust_file) and this control plane's edge-agent download copy.
	trustFile := filepath.Join(directory, "node-artifacts.json")
	if err := os.WriteFile(trustFile, artifactTrust, 0o400); err != nil {
		t.Fatal(err)
	}
	controlDownloads := filepath.Join(directory, "control-downloads", "edge-agent")
	if err := os.MkdirAll(controlDownloads, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controlDownloads, "artifacts.json"), artifactTrust, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(map[string]string{"trust_file": trustFile})
	if err := os.WriteFile(filepath.Join(directory, "control.json.tmp"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "control.json.tmp"), filepath.Join(directory, "control.json")); err != nil {
		t.Fatal(err)
	}

	pool, _, _ := controlE2EDatabase(t, databaseURL)
	var gateway struct {
		NodeID string `json:"node_id"`
	}
	waitJSONFile(t, filepath.Join(directory, "gateway.json"), &gateway)
	nodeID, legacyNodeID := uuid.MustParse(gateway.NodeID), uuid.New()
	// The gateway reports the agent's first session facts once the agent connected.
	snapshotPath := filepath.Join(directory, "session-capabilities.bin")
	var snapshot []byte
	for deadline := time.Now().Add(2 * time.Minute); ; {
		if content, err := os.ReadFile(snapshotPath); err == nil {
			snapshot = content
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway did not report the agent's session facts")
		}
		time.Sleep(200 * time.Millisecond)
	}
	var declared agentv1.AgentCapabilities
	if err := proto.Unmarshal(snapshot, &declared); err != nil {
		t.Fatal(err)
	}
	legacy := proto.Clone(&declared).(*agentv1.AgentCapabilities)
	legacy.Features = nil
	for _, feature := range declared.Features {
		if feature.GetName() != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST {
			legacy.Features = append(legacy.Features, feature)
		}
	}
	if len(legacy.Features) == len(declared.Features) {
		t.Fatalf("agent did not declare EDGE_SIGNER_TRUST: %v", declared.Features)
	}
	legacySnapshot, _ := proto.MarshalOptions{Deterministic: true}.Marshal(legacy)
	seedSignerPushNodes(t, pool, map[uuid.UUID][]byte{nodeID: snapshot, legacyNodeID: legacySnapshot})
	t.Logf("node %s declared EDGE_SIGNER_TRUST; node %s (older agent) did not", nodeID, legacyNodeID)

	// Production runtime from the installer environment.
	t.Setenv("SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_KEY_ID", root.KeyID)
	t.Setenv("SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_GENERATION", "1")
	t.Setenv("SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_PUBLIC_KEY_BASE64", root.PublicKeyBase64URL)
	t.Setenv("SIGNER_REVOCATION_CONSUMER_TLS_CA_FILE", authority.CAFile)
	t.Setenv(edgeSignerTrustURLEnv, authority.Origin+edgesignertrustsync.DefaultDocumentPath)
	t.Setenv(edgeSignerTrustDownloads, controlDownloads)
	connection, err := nats.Connect(natsURL, nats.Name("cdnca-signer-push-e2e-control"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	signer := &edgePublishArtifactSigner{keyID: e2eEdgeKeyID, privateKey: controlKey}
	runtime, err := buildEdgeSignerTrustRuntime(pool, "", signer, connection)
	if err != nil || runtime == nil || runtime.distributor == nil {
		t.Fatalf("runtime=%v err=%v", runtime, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	distributorDone := make(chan error, 1)
	go func() { distributorDone <- runtime.distributor.Run(ctx) }()
	defer func() {
		cancel()
		<-distributorDone
	}()

	sign := func(revision uint64, previous string, trusted map[string]ed25519.PrivateKey, revoked ...map[string]string) string {
		t.Helper()
		draft := map[string]any{"schema": edgesignertrust.DocumentSchema, "revision": revision,
			"issued_at": edgesignertrust.CanonicalTime(time.Now()), "trusted_keys": []map[string]string{},
			"revoked_keys": revoked}
		for keyID, key := range trusted {
			draft["trusted_keys"] = append(draft["trusted_keys"].([]map[string]string),
				map[string]string{"key_id": keyID, "public_key_pem": publicPEM(key)})
		}
		in := filepath.Join(directory, "operator", "draft-"+uuid.NewString()+".json")
		out := filepath.Join(directory, "operator", "signer-trust-"+uuid.NewString()+".json")
		_ = os.MkdirAll(filepath.Dir(in), 0o700)
		content, _ := json.Marshal(draft)
		if err := os.WriteFile(in, content, 0o600); err != nil {
			t.Fatal(err)
		}
		arguments := []string{"sign-edge-trust", "-in", in, "-key", rootKey, "-key-id", root.KeyID, "-generation", "1", "-out", out}
		if previous != "" {
			arguments = append(arguments, "-previous", previous)
		}
		if output, err := exec.Command(tool, arguments...).CombinedOutput(); err != nil {
			t.Fatalf("signer-offline-root %v: %v\n%s", arguments, err, output)
		}
		return out
	}
	publish := func(signed string) {
		t.Helper()
		content, err := os.ReadFile(signed)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(authority.DownloadsDir, "edge-agent", "signer-trust.json")
		if err := os.WriteFile(target+".tmp", content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(target+".tmp", target); err != nil {
			t.Fatal(err)
		}
	}
	var agent struct {
		StateURL string `json:"state_url"`
	}
	waitJSONFile(t, filepath.Join(directory, "agent.json"), &agent)
	defer func() { _, _ = http.Post(agent.StateURL+"/done", "application/json", nil) }()
	keys := url.Values{"key": {"release-old", "release-other", "release-new", e2eEdgeKeyID}}.Encode()
	state := func(path string) signerPushAgentState {
		t.Helper()
		method, target := http.MethodGet, agent.StateURL+path+"?"+keys
		if path == "/restart" {
			method = http.MethodPost
		}
		request, _ := http.NewRequest(method, target, nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		var result signerPushAgentState
		if response.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil {
			t.Fatalf("agent %s status=%d body=%s", path, response.StatusCode, body)
		}
		return result
	}
	await := func(label string, accept func(signerPushAgentState) bool) signerPushAgentState {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			current := state("/state")
			if accept(current) {
				t.Logf("PASS %s: node revision=%d trusted=%v receipt=%s/%s applied=%d", label, current.Revision,
					current.Trusted, current.Receipt.Result, current.Receipt.Reason, current.AppliedCount)
				return current
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not converge: %+v", label, current)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	enforced := func(revision uint64) {
		t.Helper()
		var stored int64
		var result string
		if err := pool.QueryRow(t.Context(), `SELECT enforced_revision,result FROM edge_signer_trust_node_state WHERE node_id=$1`,
			nodeID).Scan(&stored, &result); err != nil || uint64(stored) != revision || result != edgesignertrust.ResultApplied {
			t.Fatalf("control node state = %d %s %v, want %d applied", stored, result, err, revision)
		}
	}

	// 1. Nothing published yet: the fetcher keeps the (empty) LKG and nothing reaches the node.
	if reason := runtime.fetcher.FetchOnce(t.Context()); reason != edgesignertrustsync.ReasonNotPublished {
		t.Fatalf("empty origin: %s", reason)
	}

	// 2. Revision 1 revokes release-old: fetched, stored, pushed, applied, receipted, download trust refreshed.
	first := sign(1, "", nil, map[string]string{"key_id": "release-old", "revoked_at": edgesignertrust.CanonicalTime(time.Now()),
		"reason": "signer_compromise"})
	publish(first)
	if reason := runtime.fetcher.FetchOnce(t.Context()); reason != edgesignertrustsync.ReasonAccepted {
		t.Fatalf("revision 1: %s", reason)
	}
	await("revision 1 pushed and applied", func(current signerPushAgentState) bool {
		return current.Revision == 1 && !current.Trusted["release-old"] && current.Trusted["release-other"] &&
			current.Trusted[e2eEdgeKeyID] && current.Receipt.Result == edgesignertrust.ResultApplied
	})
	waitFor(t, "control recorded the receipt", func() bool {
		var count int
		_ = pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_signer_trust_node_state WHERE node_id=$1 AND enforced_revision=1`,
			nodeID).Scan(&count)
		return count == 1
	})
	enforced(1)
	downloads, _ := os.ReadFile(filepath.Join(controlDownloads, "artifacts.json"))
	if strings.Contains(string(downloads), `"release-old"`) || !strings.Contains(string(downloads), `"release-other"`) {
		t.Fatalf("control downloads artifacts.json not refreshed: %s", downloads)
	}
	if published, _ := os.ReadFile(filepath.Join(controlDownloads, "signer-trust.json")); len(published) == 0 {
		t.Fatal("control downloads signer-trust.json missing")
	}
	t.Log("PASS control downloads: artifacts.json without release-old, signer-trust.json published")
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	pending := func(node uuid.UUID) uint64 {
		info, err := js.StreamInfo(signertrust.CommandStream, &nats.StreamInfoRequest{SubjectsFilter: signertrust.CommandSubjectPrefix + ".>"})
		if err != nil {
			t.Fatal(err)
		}
		return info.State.Subjects[signertrust.CommandSubjectPrefix+"."+node.String()]
	}
	if count := pending(legacyNodeID); count != 0 {
		t.Fatalf("older agent got %d bundles", count)
	}
	// The gateway acknowledges right after publishing the receipt.
	waitFor(t, "capable node bundle settled", func() bool { return pending(nodeID) == 0 })
	t.Log("PASS gating: no bundle for the node without EDGE_SIGNER_TRUST; the delivered one was settled")

	// 3. Deployments paused + agent restart: the node restores revision 1 from disk and still receives pushes.
	if err := os.WriteFile(filepath.Join(directory, "deployments-paused"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := state("/restart")
	if restarted.Revision != 1 || restarted.Trusted["release-old"] || restarted.Restarts != 1 {
		t.Fatalf("restart lost the revocation: %+v", restarted)
	}
	t.Log("PASS agent restart: revision 1 restored from <journal>/signer-trust/state.json before connecting")

	// 4. Revision 2 adds release-new and revokes release-other by fingerprint only (another key ID).
	otherPrint, _ := edgesignertrust.PublicKeySHA256(releaseOther.Public())
	second := sign(2, first, map[string]ed25519.PrivateKey{"release-new": releaseNew},
		map[string]string{"key_id": "release-old", "revoked_at": edgesignertrust.CanonicalTime(time.Now()), "reason": "signer_compromise"},
		map[string]string{"key_id": "release-other-renamed", "public_key_sha256": otherPrint,
			"revoked_at": edgesignertrust.CanonicalTime(time.Now()), "reason": "key_rotation"})
	publish(second)
	if reason := runtime.fetcher.FetchOnce(t.Context()); reason != edgesignertrustsync.ReasonAccepted {
		t.Fatalf("revision 2: %s", reason)
	}
	await("revision 2 pushed while deployments are paused", func(current signerPushAgentState) bool {
		return current.Revision == 2 && !current.Trusted["release-old"] && !current.Trusted["release-other"] &&
			current.Trusted["release-new"] && current.Receipt.Result == edgesignertrust.ResultApplied
	})
	waitFor(t, "control recorded revision 2", func() bool {
		var count int
		_ = pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_signer_trust_node_state WHERE node_id=$1 AND enforced_revision=2`,
			nodeID).Scan(&count)
		return count == 1
	})
	enforced(2)

	// 5. The origin rolls back to revision 1: control rejects it, nothing is pushed, the node keeps revision 2.
	publish(first)
	if reason := runtime.fetcher.FetchOnce(t.Context()); reason != edgesignertrustsync.ReasonStale {
		t.Fatalf("rollback: %s", reason)
	}
	time.Sleep(2 * time.Second)
	if current := state("/state"); current.Revision != 2 || current.Trusted["release-other"] {
		t.Fatalf("rollback reached the node: %+v", current)
	}
	var rejected int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_signer_trust_events WHERE reason='stale_revision'`).
		Scan(&rejected); err != nil || rejected == 0 {
		t.Fatalf("rollback not audited: %d %v", rejected, err)
	}
	enforced(2)
	t.Log("PASS rollback: origin served revision 1 again; control rejected it (stale_revision), node stays at 2")
}

func waitFor(t *testing.T, label string, condition func() bool) {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); !condition(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s: timed out", label)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// seedSignerPushNodes creates active nodes and their latest session capabilities (see the file comment).
func seedSignerPushNodes(t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, nodes map[uuid.UUID][]byte) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	scopeID, userID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`SET LOCAL session_replication_role = replica`, nil},
		{`INSERT INTO access_scopes (id,kind) VALUES ($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,'signer-push-e2e','signer push','unused')`, []any{userID}},
		{`INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($1,1,now())`, []any{scopeID}},
	}
	for id, snapshot := range nodes {
		digest := sha256.Sum256(snapshot)
		statements = append(statements, struct {
			query string
			args  []any
		}{`WITH allocated AS (UPDATE node_display_id_sequences SET next_value=next_value+1, updated_at=now()
				WHERE scope_id=$2 RETURNING next_value-1 AS display_id)
			INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id)
			SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`,
			[]any{id, scopeID, "signer-push-" + id.String()[:8], userID}}, struct {
			query string
			args  []any
		}{`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,artifact_key_id,
				selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,facts_snapshot,
				facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,1,$2,$3,'x25519:test',1,0,$4,$3,'\x01',$3,'gw','gateway-signer-push-e2e',now())`,
			[]any{id, uuid.New(), digest[:], snapshot}})
	}
	for _, statement := range statements {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(statement.query)[0], err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}
