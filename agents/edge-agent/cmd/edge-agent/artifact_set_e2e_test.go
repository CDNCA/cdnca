package main

// Edge-agent half of tests/artifact-set-e2e/run.sh (PA-01). It runs the production gateway client over mTLS
// against the agent-gateway process (gateway.json), the production artifact trust store loader (control.json
// trust_file) and the production node artifact set runtime (assembleArtifactSetRuntime: object store, set executor,
// IP intelligence installer below a deployment root). Segment and set deployments arrive on the Connect stream; the
// receipt goes back on the set's terminal status. The OWASP CRS engine module item is installed by the production
// wafengine installer, trusting only the test platform release key E2EPlatformReleaseSeed (as artifact_trust_file
// would). Only the site deployment manager is a no-op.
//
// HTTP for the control half: GET /state (active set revision, library readiness and revision), POST
// /tamper?digest=<sha256> (replace a stored object's bytes, as an operator or disk fault would), POST /done.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/wafengine"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// The test platform release key both halves derive (test only; the control half signs engine modules with it).
const (
	E2EPlatformReleaseSeed  = "artifact-set-e2e platform release key"
	E2EPlatformReleaseKeyID = "platform-e2e"
)

type artifactSetGatewayFixture struct {
	Address               string `json:"address"`
	ServerName            string `json:"server_name"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientPrivateKeyFile  string `json:"client_private_key_file"`
	NodeID                string `json:"node_id"`
	ArtifactKeyID         string `json:"artifact_key_id"`
}

func TestArtifactSetAgentAgainstControlProcess(t *testing.T) {
	directory := os.Getenv("ARTIFACT_SET_E2E_DIR")
	if directory == "" {
		t.Skip("ARTIFACT_SET_E2E_DIR is not set; run tests/artifact-set-e2e/run.sh")
	}
	var gateway artifactSetGatewayFixture
	waitJSON(t, filepath.Join(directory, "gateway.json"), &gateway)
	var control struct {
		TrustFile string `json:"trust_file"`
	}
	waitJSON(t, filepath.Join(directory, "control.json"), &control)
	trust, err := gatewayclient.LoadTrustStore(control.TrustFile)
	if err != nil {
		t.Fatal(err)
	}
	deploymentRoot := filepath.Join(directory, "agent-deployments")
	if err := os.Mkdir(deploymentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.Open(filepath.Join(deploymentRoot, objectStoreDir))
	if err != nil {
		t.Fatal(err)
	}
	releaseSeed := sha256.Sum256([]byte(E2EPlatformReleaseSeed))
	release := ed25519.NewKeyFromSeed(releaseSeed[:])
	engine, err := wafengine.NewManager(wafengine.Config{Root: filepath.Join(deploymentRoot, "extensions", "waf-crs"),
		StateRoot: deploymentRoot, OpenRestyVersion: enginemoduletest.DefaultOpenResty, Architecture: "amd64",
		Trust: wafengine.Trust{Release: map[string]ed25519.PublicKey{E2EPlatformReleaseKeyID: release.Public().(ed25519.PublicKey)}}})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := assembleArtifactSetRuntime(deploymentRoot, gateway.NodeID, objects, engine, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := gatewayclient.NewMTLSDialer(gatewayclient.MTLSDialerConfig{Address: gateway.Address,
		ServerName: gateway.ServerName, RootCAFile: gateway.RootCAFile, ClientCertificateFile: gateway.ClientCertificateFile,
		ClientPrivateKeyFile: gateway.ClientPrivateKeyFile, MaximumReceiveBytes: 8 << 20, MaximumSendBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(directory, "agent-journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	config := gatewayclient.DefaultConfig()
	config.NodeID, config.BootID, config.ArtifactEncryptionKeyID = gateway.NodeID, uuid.NewString(), gateway.ArtifactKeyID
	config.JournalDir = journal
	// The gateway reports session facts (what the distributor reads) only for a complete agent identity.
	config.Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.35-e2e", BuildId: "artifact-set-e2e",
		OperatingSystem: "linux", Architecture: "amd64", OpenrestyVersion: enginemoduletest.DefaultOpenResty,
		Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1}}}
	config.InitialBackoff, config.MaximumBackoff = 100*time.Millisecond, time.Second
	client, err := gatewayclient.New(config, dialer, e2eNoDeployments{}, trust, gatewayclient.WithArtifactSetRuntime(runtime))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(ctx) }()

	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/done":
			close(done)
			response.WriteHeader(http.StatusNoContent)
		case "/tamper":
			digest := request.URL.Query().Get("digest")
			if request.Method != http.MethodPost || !artifactset.ValidDigest(digest) || !objects.Has(digest) {
				http.Error(response, "unknown object", http.StatusBadRequest)
				return
			}
			// Objects are read-only files in an owner-writable directory.
			path := objects.Path(digest)
			if err := os.Remove(path); err != nil {
				http.Error(response, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(path, []byte("altered on the node"), 0o400); err != nil {
				http.Error(response, err.Error(), http.StatusInternalServerError)
				return
			}
			response.WriteHeader(http.StatusNoContent)
		case "/state":
			state := map[string]any{"active_revision": 0, "ip_intel_ready": runtime.IPIntelReady(), "library_revision": 0}
			if active := runtime.executor.Active(); active != nil {
				state["active_revision"] = active.Revision
			}
			if library, err := runtime.ipIntel.Current(); err == nil && library != nil {
				state["library_revision"] = library.Revision
			}
			state["engine_artifact_id"], state["engine_version"] = engine.Installed()
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(state)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	encoded, _ := json.Marshal(map[string]string{"state_url": server.URL})
	if err := os.WriteFile(filepath.Join(directory, "agent.json.tmp"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "agent.json.tmp"), filepath.Join(directory, "agent.json")); err != nil {
		t.Fatal(err)
	}
	t.Logf("edge-agent gateway client running for node %s against %s", gateway.NodeID, gateway.Address)
	select {
	case <-done:
	case err := <-clientDone:
		t.Fatalf("gateway client stopped: %v", err)
	case <-time.After(30 * time.Minute):
		t.Fatal("control half did not finish")
	}
}
