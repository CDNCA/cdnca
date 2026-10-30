package main

// Node half of tests/gateway-cdn-e2e/run.sh (GW-03): the production
// gatewayclient dials an OpenResty "CDN" over the WebSocket tunnel (the CDN
// terminates TLS with its own certificate and pulls from the Gateway's
// shared port). Phase 1: a session with heartbeats and the node address
// resolved from the CDN header. Phase 2: run.sh restarts the CDN; the node
// reconnects on its own.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

type gatewayCDNFixture struct {
	e2eGatewayFixture
	TunnelAudience string `json:"tunnel_audience"`
}

type gatewayCDNSessions struct {
	Sessions   int    `json:"sessions"`
	Heartbeats int    `json:"heartbeats"`
	PeerIP     string `json:"peer_ip"`
	PeerSource string `json:"peer_source"`
}

func TestGatewayCDNAgentProcess(t *testing.T) {
	directory, cdn := os.Getenv("GATEWAY_CDN_E2E_DIR"), os.Getenv("GATEWAY_CDN_E2E_ADDRESS")
	if directory == "" || cdn == "" {
		t.Skip("GATEWAY_CDN_E2E_DIR and GATEWAY_CDN_E2E_ADDRESS are not set; run tests/gateway-cdn-e2e/run.sh")
	}
	var gateway gatewayCDNFixture
	waitJSON(t, filepath.Join(directory, "gateway.json"), &gateway)
	journal := filepath.Join(directory, "agent-journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	dialer, err := gatewayclient.NewMTLSDialer(gatewayclient.MTLSDialerConfig{Address: cdn, ServerName: gateway.ServerName,
		RootCAFile: gateway.RootCAFile, ClientCertificateFile: gateway.ClientCertificateFile, ClientPrivateKeyFile: gateway.ClientPrivateKeyFile,
		MaximumReceiveBytes: 4 << 20, MaximumSendBytes: 4 << 20,
		Transport: "ws", TunnelHost: "cdn.e2e.test", TunnelAudience: gateway.TunnelAudience})
	if err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := gatewayclient.NewTrustStore(map[string]crypto.PublicKey{"e2e": public})
	if err != nil {
		t.Fatal(err)
	}
	config := gatewayclient.DefaultConfig()
	config.NodeID, config.BootID, config.ArtifactEncryptionKeyID = gateway.NodeID, uuid.NewString(), gateway.ArtifactKeyID
	config.JournalDir = journal
	config.Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "e2e",
		OperatingSystem: goruntime.GOOS, Architecture: goruntime.GOARCH}
	config.InitialBackoff, config.MaximumBackoff = 100*time.Millisecond, time.Second
	client, err := gatewayclient.New(config, dialer, e2eNoDeployments{}, trust)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	defer func() { cancel(); <-done; _ = client.Close() }()

	read := func() gatewayCDNSessions {
		var sessions gatewayCDNSessions
		if encoded, err := os.ReadFile(filepath.Join(directory, "sessions.json")); err == nil {
			_ = json.Unmarshal(encoded, &sessions)
		}
		return sessions
	}
	waitFor := func(what string, timeout time.Duration, ok func(gatewayCDNSessions) bool) gatewayCDNSessions {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for {
			sessions := read()
			if ok(sessions) {
				return sessions
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %+v", what, sessions)
			}
			select {
			case err := <-done:
				t.Fatalf("agent stopped: %v", err)
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	first := waitFor("session through the CDN", time.Minute, func(s gatewayCDNSessions) bool { return s.Sessions >= 1 && s.Heartbeats >= 3 })
	if first.PeerSource != "trusted_proxy" || first.PeerIP == "" || first.PeerIP == "127.0.0.1" {
		t.Fatalf("node address not taken from the CDN header: %+v", first)
	}
	t.Logf("phase 1: %+v", first)
	if err := os.WriteFile(filepath.Join(directory, "phase1-done"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "cdn-restarted")); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	second := waitFor("reconnect after the CDN restart", 2*time.Minute, func(s gatewayCDNSessions) bool {
		return s.Sessions > first.Sessions && s.Heartbeats >= first.Heartbeats+3
	})
	t.Logf("phase 2: %+v", second)
}
