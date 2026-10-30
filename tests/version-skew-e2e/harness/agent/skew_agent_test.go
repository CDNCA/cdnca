//go:build versionskew

package main

// Edge-agent half of tests/version-skew-e2e/run.sh. run.sh copies this file into cmd/edge-agent of the tree under
// test (released baseline or candidate). It runs the production gateway client with the production capability set
// of that tree (agentCapabilitiesWithFirewall + SITE_RUNTIME + HTTP/3 + drain, and an upgrade
// runtime so EDGE_UPGRADE is offered) against the gateway half over mTLS, records every GatewayHello and requires
// that the session ends up with edge upgrades enabled: a node that cannot negotiate EDGE_UPGRADE can no longer be
// upgraded or rolled back from the console.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/http3runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type skewGatewayFixture struct {
	Address               string `json:"address"`
	ServerName            string `json:"server_name"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientPrivateKeyFile  string `json:"client_private_key_file"`
	NodeID                string `json:"node_id"`
	ArtifactKeyID         string `json:"artifact_key_id"`
}

type e2eSkewNoDeployments struct{}

func (e2eSkewNoDeployments) Process(context.Context, deployment.Command) (deployment.Result, error) {
	return deployment.Result{}, nil
}
func (e2eSkewNoDeployments) Pointers() (deployment.Pointers, error) { return deployment.Pointers{}, nil }

type e2eSkewUpgradeRuntime struct{}

func (e2eSkewUpgradeRuntime) Ready() bool                                 { return true }
func (e2eSkewUpgradeRuntime) Recover(context.Context) error               { return nil }
func (e2eSkewUpgradeRuntime) AcceptCommand(context.Context, []byte) error { return nil }
func (e2eSkewUpgradeRuntime) PendingStatuses(context.Context) ([]updater.QueuedUpgradeStatus, error) {
	return nil, nil
}
func (e2eSkewUpgradeRuntime) AcknowledgeStatus(context.Context, string, string, string) (bool, error) {
	return false, nil
}

// e2eSkewRecorder keeps the enabled capabilities of every GatewayHello the production client received.
type e2eSkewRecorder struct {
	mu       sync.Mutex
	sessions [][]int32
	offered  [][]int32
}

func (r *e2eSkewRecorder) hello(hello *agentv1.GatewayHello) {
	enabled := []int32{}
	for _, capability := range hello.GetEnabledCapabilities() {
		enabled = append(enabled, int32(capability.GetName()))
	}
	r.mu.Lock()
	r.sessions = append(r.sessions, enabled)
	r.mu.Unlock()
}

func (r *e2eSkewRecorder) agentHello(hello *agentv1.AgentHello) {
	offered := []int32{}
	for _, capability := range hello.GetCapabilities().GetFeatures() {
		offered = append(offered, int32(capability.GetName()))
	}
	r.mu.Lock()
	r.offered = append(r.offered, offered)
	r.mu.Unlock()
}

func (r *e2eSkewRecorder) upgradeEnabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sessions) == 0 {
		return false
	}
	for _, name := range r.sessions[len(r.sessions)-1] {
		if name == int32(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE) {
			return true
		}
	}
	return false
}

type e2eSkewDialer struct {
	inner    gatewayclient.Dialer
	recorder *e2eSkewRecorder
}

func (d e2eSkewDialer) Dial(ctx context.Context) (gatewayclient.Connection, error) {
	connection, err := d.inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return e2eSkewConnection{Connection: connection, recorder: d.recorder}, nil
}

type e2eSkewConnection struct {
	gatewayclient.Connection
	recorder *e2eSkewRecorder
}

func (c e2eSkewConnection) Client() agentv1.AgentGatewayServiceClient {
	return e2eSkewServiceClient{AgentGatewayServiceClient: c.Connection.Client(), recorder: c.recorder}
}

type e2eSkewServiceClient struct {
	agentv1.AgentGatewayServiceClient
	recorder *e2eSkewRecorder
}

func (c e2eSkewServiceClient) Connect(ctx context.Context, options ...grpc.CallOption) (grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], error) {
	stream, err := c.AgentGatewayServiceClient.Connect(ctx, options...)
	if err != nil {
		return nil, err
	}
	return &e2eSkewStream{BidiStreamingClient: stream, recorder: c.recorder}, nil
}

type e2eSkewStream struct {
	grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse]
	recorder *e2eSkewRecorder
}

func (s *e2eSkewStream) Send(request *agentv1.ConnectRequest) error {
	if hello := request.GetHello(); hello != nil {
		s.recorder.agentHello(hello)
	}
	return s.BidiStreamingClient.Send(request)
}

func (s *e2eSkewStream) Recv() (*agentv1.ConnectResponse, error) {
	response, err := s.BidiStreamingClient.Recv()
	if err == nil && os.Getenv("SKEW_E2E_TRACE") != "" {
		fmt.Fprintf(os.Stderr, "recv %T\n", response.GetPayload())
	}
	if err == nil {
		if hello := response.GetHello(); hello != nil {
			s.recorder.hello(hello)
		}
	}
	return response, err
}

func e2eSkewWaitJSON(t *testing.T, path string, value any) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		encoded, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(encoded, value) == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not published: %v", filepath.Base(path), err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestVersionSkewAgentProcess(t *testing.T) {
	directory := os.Getenv("SKEW_E2E_DIR")
	if directory == "" {
		t.Skip("SKEW_E2E_DIR is not set; run tests/version-skew-e2e/run.sh")
	}
	defer func() { _ = os.WriteFile(filepath.Join(directory, "finished"), nil, 0o600) }()
	var gateway skewGatewayFixture
	e2eSkewWaitJSON(t, filepath.Join(directory, "gateway.json"), &gateway)
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := gatewayclient.NewTrustStore(map[string]crypto.PublicKey{"skew": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := gatewayclient.NewMTLSDialer(gatewayclient.MTLSDialerConfig{Address: gateway.Address,
		ServerName: gateway.ServerName, RootCAFile: gateway.RootCAFile, ClientCertificateFile: gateway.ClientCertificateFile,
		ClientPrivateKeyFile: gateway.ClientPrivateKeyFile, MaximumReceiveBytes: 4 << 20, MaximumSendBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &e2eSkewRecorder{}
	journal := filepath.Join(directory, "agent-journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	config := gatewayclient.DefaultConfig()
	config.NodeID, config.BootID, config.ArtifactEncryptionKeyID = gateway.NodeID, uuid.NewString(), gateway.ArtifactKeyID
	config.JournalDir = journal
	// The production capability set of this tree, as daemon.go assembles it on a fully provisioned node. Node
	// monitoring is left out: it is negotiated symmetrically and needs a bridge on both halves. The OpenResty
	// version is the one this tree's HTTP/3 runtime pins (edge/openresty/runtime.env of that tree).
	config.Capabilities = agentCapabilitiesWithFirewall(http3runtime.RuntimeVersionOpenResty, true, securityRuntimeStatus{WAFReady: true, CCReady: true})
	addSiteRuntimeV3Capability(config.Capabilities, true)
	for _, name := range []agentv1.CapabilityName{
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_3,
		agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL,
	} {
		config.Capabilities.Features = append(config.Capabilities.Features, &agentv1.Capability{Name: name, ApiVersion: 1})
	}
	config.InitialBackoff, config.MaximumBackoff = 100*time.Millisecond, time.Second
	client, err := gatewayclient.New(config, e2eSkewDialer{inner: inner, recorder: recorder}, e2eSkewNoDeployments{}, trust,
		gatewayclient.WithUpgradeRuntime(e2eSkewUpgradeRuntime{}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(ctx) }()

	deadline := time.After(20 * time.Second)
	enabled := false
	var stopped error
	for !enabled {
		select {
		case stopped = <-clientDone:
			goto report
		case <-deadline:
			enabled = recorder.upgradeEnabled()
			if !enabled {
				goto report
			}
		case <-time.After(100 * time.Millisecond):
			enabled = recorder.upgradeEnabled()
		}
	}
report:
	recorder.mu.Lock()
	result, _ := json.Marshal(map[string]any{"offered": recorder.offered, "enabled": recorder.sessions, "upgrade_enabled": enabled})
	recorder.mu.Unlock()
	_ = os.WriteFile(filepath.Join(directory, "agent-result.json"), result, 0o600)
	t.Logf("agent result: %s", result)
	if stopped != nil {
		t.Fatalf("gateway client stopped: %v", stopped)
	}
	if !enabled {
		t.Fatal("the gateway never enabled EDGE_UPGRADE: this node could not be upgraded or rolled back from the console")
	}
}
