package main

// Edge-agent half of tests/signer-trust-push-e2e/run.sh: the production gateway client over mTLS against the
// agent-gateway process (gateway.json), the production artifact trust store loader (control.json trust_file) and
// the production SignerTrustRuntime persisted under the journal directory, assembled as the daemon does (restore
// before connecting, WithSignerTrustRuntime). Only the deployment manager is a no-op.
//
// GET /state?key=<id>... reports the applied revision, which keys are trusted, the last receipt and the restart
// count; POST /restart closes the client and assembles a new one from disk (trust file + persisted state), like a
// daemon restart; POST /done ends the process.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// e2eControlFixture is control.json: the artifact trust file the control half signs with.
type e2eControlFixture struct {
	TrustFile string `json:"trust_file"`
}

// e2eGatewayFixture is gateway.json: the agent-gateway process's mTLS endpoint and this node's identity.
type e2eGatewayFixture struct {
	Address               string `json:"address"`
	ServerName            string `json:"server_name"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientPrivateKeyFile  string `json:"client_private_key_file"`
	NodeID                string `json:"node_id"`
	ArtifactKeyID         string `json:"artifact_key_id"`
}

type e2eNoDeployments struct{}

func (e2eNoDeployments) Process(context.Context, deployment.Command) (deployment.Result, error) {
	return deployment.Result{}, nil
}
func (e2eNoDeployments) Pointers() (deployment.Pointers, error) { return deployment.Pointers{}, nil }

func waitJSON(t *testing.T, path string, value any) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Minute)
	for {
		encoded, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(encoded, value) == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not published: %v", filepath.Base(path), err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type recordingSignerTrust struct {
	runtime *gatewayclient.SignerTrustRuntime
	mu      sync.Mutex
	last    edgesignertrust.Receipt
	count   int
}

func (recording *recordingSignerTrust) Apply(encoded []byte) edgesignertrust.Receipt {
	receipt := recording.runtime.Apply(encoded)
	recording.mu.Lock()
	recording.last, recording.count = receipt, recording.count+1
	recording.mu.Unlock()
	return receipt
}

type signerTrustAgent struct {
	trust     *gatewayclient.TrustStore
	recording *recordingSignerTrust
	cancel    context.CancelFunc
	done      chan error
	client    *gatewayclient.Client
}

func TestSignerTrustAgentAgainstControlProcess(t *testing.T) {
	directory := os.Getenv("SIGNER_PUSH_E2E_DIR")
	if directory == "" {
		t.Skip("SIGNER_PUSH_E2E_DIR is not set; run tests/signer-trust-push-e2e/run.sh")
	}
	var gateway e2eGatewayFixture
	waitJSON(t, filepath.Join(directory, "gateway.json"), &gateway)
	var control e2eControlFixture
	waitJSON(t, filepath.Join(directory, "control.json"), &control)
	journal := filepath.Join(directory, "agent-journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	start := func() *signerTrustAgent {
		t.Helper()
		trust, err := gatewayclient.LoadTrustStore(control.TrustFile)
		if err != nil {
			t.Fatal(err)
		}
		runtime, err := gatewayclient.NewSignerTrustRuntime(filepath.Join(journal, "signer-trust"), gateway.NodeID, trust, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Restore(); err != nil {
			t.Fatal(err)
		}
		dialer, err := gatewayclient.NewMTLSDialer(gatewayclient.MTLSDialerConfig{Address: gateway.Address,
			ServerName: gateway.ServerName, RootCAFile: gateway.RootCAFile, ClientCertificateFile: gateway.ClientCertificateFile,
			ClientPrivateKeyFile: gateway.ClientPrivateKeyFile, MaximumReceiveBytes: 4 << 20, MaximumSendBytes: 4 << 20})
		if err != nil {
			t.Fatal(err)
		}
		config := gatewayclient.DefaultConfig()
		config.NodeID, config.BootID, config.ArtifactEncryptionKeyID = gateway.NodeID, uuid.NewString(), gateway.ArtifactKeyID
		config.JournalDir = journal
		// Complete identity fields: the gateway reports session facts only for a complete hello.
		config.Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "e2e",
			OperatingSystem: goruntime.GOOS, Architecture: goruntime.GOARCH, Features: []*agentv1.Capability{
				{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1}}}
		config.InitialBackoff, config.MaximumBackoff = 100*time.Millisecond, time.Second
		recording := &recordingSignerTrust{runtime: runtime}
		client, err := gatewayclient.New(config, dialer, e2eNoDeployments{}, trust, gatewayclient.WithSignerTrustRuntime(recording))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		agent := &signerTrustAgent{trust: trust, recording: recording, cancel: cancel, done: make(chan error, 1), client: client}
		go func() { agent.done <- client.Run(ctx) }()
		return agent
	}
	stop := func(agent *signerTrustAgent) {
		agent.cancel()
		<-agent.done
		_ = agent.client.Close()
	}
	var mu sync.Mutex
	current, restarts := start(), 0
	defer func() { stop(current) }()

	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch request.URL.Path {
		case "/done":
			close(finished)
			response.WriteHeader(http.StatusNoContent)
			return
		case "/restart":
			stop(current)
			current, restarts = start(), restarts+1
		case "/state":
		default:
			http.NotFound(response, request)
			return
		}
		trusted := map[string]bool{}
		for _, keyID := range request.URL.Query()["key"] {
			_, trusted[keyID] = current.trust.Ed25519Key(keyID)
		}
		current.recording.mu.Lock()
		state := map[string]any{"revision": current.trust.SignerTrustRevision(), "trusted": trusted,
			"receipt": current.recording.last, "applied_count": current.recording.count, "restarts": restarts}
		current.recording.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(state)
	}))
	defer server.Close()
	encoded, _ := json.Marshal(map[string]string{"state_url": server.URL})
	if err := os.WriteFile(filepath.Join(directory, "agent.json.tmp"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "agent.json.tmp"), filepath.Join(directory, "agent.json")); err != nil {
		t.Fatal(err)
	}
	t.Logf("edge-agent gateway client running for node %s against %s", gateway.NodeID, gateway.Address)
	select {
	case <-finished:
	case <-time.After(30 * time.Minute):
		t.Fatal("control half did not finish")
	}
}
