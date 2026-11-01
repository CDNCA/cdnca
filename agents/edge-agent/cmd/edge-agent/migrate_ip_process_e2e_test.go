package main

// Node stand-in of tests/control-migrate-e2e/run.sh: the
// installed node's configuration (config.json read by loadConfig) and the
// daemon's Gateway dialer chain — the persisted active endpoint
// (SwitchingDialer over gateway-journal/gateway-endpoint), the FailoverDialer
// with the persisted GatewayHello list (gateway-endpoints.json) and the
// GatewayHello learner — around the production gatewayclient. Only the
// deployment manager and the artifact trust are stand-ins (no OpenResty in
// the container). run.sh stops and restarts it to model an offline node and
// `edge-agent set-gateway`.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// TestMigrateIPAgentConfig writes the installed node's config.json
// (MIGRATE_IP_E2E_AGENT_CONFIG) for MIGRATE_IP_E2E_NODE_ID, dialing the
// Gateway at MIGRATE_IP_E2E_GATEWAY (an IP:port; server name = the IP).
func TestMigrateIPAgentConfig(t *testing.T) {
	path, nodeID, gateway := os.Getenv("MIGRATE_IP_E2E_AGENT_CONFIG"), os.Getenv("MIGRATE_IP_E2E_NODE_ID"), os.Getenv("MIGRATE_IP_E2E_GATEWAY")
	if path == "" || nodeID == "" || gateway == "" {
		t.Skip("MIGRATE_IP_E2E_AGENT_CONFIG, MIGRATE_IP_E2E_NODE_ID and MIGRATE_IP_E2E_GATEWAY are not set")
	}
	host, _, err := net.SplitHostPort(gateway)
	if err != nil {
		t.Fatal(err)
	}
	// One directory per node: config.json and tls/ next to each other, the
	// state below MIGRATE_IP_E2E_STATE (several nodes share a container).
	etc, state := filepath.Dir(path), os.Getenv("MIGRATE_IP_E2E_STATE")
	if state == "" {
		t.Fatal("MIGRATE_IP_E2E_STATE is required")
	}
	config := validFileConfig()
	config.NodeID, config.ArtifactEncryptionKeyID = nodeID, "artifact-key"
	config.ArtifactTrustFile = etc + "/trust/artifacts.json"
	config.DeploymentRoot, config.JournalDir = state+"/deployments", state+"/gateway-journal"
	config.CertificateRuntime.StateRoot = state + "/certificates"
	config.Gateway.Address, config.Gateway.ServerName, config.Gateway.EnrollmentAddress = gateway, host, net.JoinHostPort(host, DefaultEnrollmentPort)
	config.Gateway.RootCAFile = etc + "/tls/ca.pem"
	config.Gateway.ClientCertificate, config.Gateway.ClientPrivateKeyFile = etc+"/tls/client.pem", etc+"/tls/client-key.pem"
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeConfig(encoded); err != nil {
		t.Fatalf("node configuration: %v", err)
	}
	for _, directory := range []string{filepath.Dir(path), config.JournalDir, config.DeploymentRoot, config.CertificateRuntime.StateRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateIPAgentProcess(t *testing.T) {
	path := os.Getenv("MIGRATE_IP_E2E_AGENT_CONFIG")
	if path == "" {
		t.Skip("MIGRATE_IP_E2E_AGENT_CONFIG is not set; started by tests/control-migrate-e2e")
	}
	config, timeouts, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	dialerConfig := gatewayclient.MTLSDialerConfig{Address: config.Gateway.Address, ServerName: config.Gateway.ServerName,
		RootCAFile: config.Gateway.RootCAFile, ClientCertificateFile: config.Gateway.ClientCertificate,
		ClientPrivateKeyFile: config.Gateway.ClientPrivateKeyFile, MaximumReceiveBytes: 4 << 20, MaximumSendBytes: 4 << 20}
	factory, err := gatewayclient.NewEndpointMTLSDialerFactory(dialerConfig)
	if err != nil {
		t.Fatal(err)
	}
	store, err := gatewayclient.NewFileGatewayEndpointStateStore(filepath.Join(config.JournalDir, "gateway-endpoint"),
		gatewayclient.GatewayEndpointState{Address: config.Gateway.Address, ServerName: config.Gateway.ServerName})
	if err != nil {
		t.Fatal(err)
	}
	switching, err := gatewayclient.NewSwitchingDialer(store, factory)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := gatewayclient.NewFailoverDialer(switching, dialerConfig, nil, filepath.Join(config.JournalDir, "gateway-endpoints.json"))
	if err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := gatewayclient.NewTrustStore(map[string]crypto.PublicKey{"e2e": public})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := gatewayclient.DefaultConfig()
	clientConfig.NodeID, clientConfig.BootID, clientConfig.ArtifactEncryptionKeyID = config.NodeID, uuid.NewString(), config.ArtifactEncryptionKeyID
	clientConfig.JournalDir = config.JournalDir
	clientConfig.Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "e2e",
		OperatingSystem: goruntime.GOOS, Architecture: goruntime.GOARCH}
	clientConfig.HandshakeTimeout = timeouts.Handshake
	// Short backoff keeps the run fast; the endpoint order is the daemon's.
	clientConfig.InitialBackoff, clientConfig.MaximumBackoff = 200*time.Millisecond, 2*time.Second
	client, err := gatewayclient.New(clientConfig, dialer, e2eNoDeployments{}, trust, gatewayclient.WithGatewayEndpointLearner(dialer.Learn))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	t.Logf("node %s dials %s (%s)", config.NodeID, store.Active().Address, store.Active().ServerName)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
}
