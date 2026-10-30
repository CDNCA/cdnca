package main

// Edge-agent half of tests/cert-recovery-e2e/run.sh (ADR 0013 GW-02), run inside the node runtime image with
// OpenResty. It is the daemon's identity wiring (daemon.go: config version 2): enrollment.Run with a real enrollment
// token, LoadIdentityAllowingExpired, the switching mTLS dialer (re-reads client.pem on every dial), the production
// gateway client with WithCertificateRenewer(enrollment.NewRenewer) and WithCertificateRecoverer(enrollment.Recoverer
// over RecoveryDial to the enrollment listener). OpenResty serves a health page next to it and is probed every 200 ms
// for the whole run: the certificate's lifecycle must never interrupt it.
//
// HTTP for the control half (published port): GET /state, POST /done.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/enrollment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
)

const certRecoveryE2EHealthPort = 18490

// certRecoveryRecorder wraps the production recoverer to count outcomes for the control half.
type certRecoveryRecorder struct {
	*enrollment.Recoverer
	mu        sync.Mutex
	recovered int
	refused   int
	lastError string
}

func (recorder *certRecoveryRecorder) Recover(ctx context.Context) (bool, string, error) {
	recovered, digest, err := recorder.Recoverer.Recover(ctx)
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recovered {
		recorder.recovered++
	}
	if errors.Is(err, enrollment.ErrRecoveryRefused) {
		recorder.refused++
	}
	if err != nil {
		recorder.lastError = err.Error()
	}
	return recovered, digest, err
}

type certRecoveryProbe struct {
	mu          sync.Mutex
	probes      int
	failures    int
	lastFailure string
}

func (probe *certRecoveryProbe) run(ctx context.Context) {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		failure := ""
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", certRecoveryE2EHealthPort))
		if err != nil {
			failure = err.Error()
		} else {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 256))
			response.Body.Close()
			if response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
				failure = fmt.Sprintf("status %d body %q", response.StatusCode, body)
			}
		}
		probe.mu.Lock()
		probe.probes++
		if failure != "" {
			probe.failures++
			probe.lastFailure = time.Now().UTC().Format(time.RFC3339) + " " + failure
		}
		probe.mu.Unlock()
	}
}

func TestCertRecoveryAgentProcess(t *testing.T) {
	directory, listen := os.Getenv("CERT_RECOVERY_E2E_DIR"), os.Getenv("CERT_RECOVERY_E2E_AGENT_LISTEN")
	openresty, gatewayHost := os.Getenv("CERT_RECOVERY_E2E_OPENRESTY"), os.Getenv("CERT_RECOVERY_E2E_GATEWAY_HOST")
	if directory == "" || listen == "" || openresty == "" || gatewayHost == "" {
		t.Skip("CERT_RECOVERY_E2E_* are not set; run tests/cert-recovery-e2e/run.sh (inside the node runtime image)")
	}
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	// OpenResty: the node's data plane, independent of the agent's gateway session.
	nginxRoot := filepath.Join(stateRoot, "openresty")
	for _, sub := range []string{"logs", "conf"} {
		if err := os.MkdirAll(filepath.Join(nginxRoot, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	nginxConfig := fmt.Sprintf(`worker_processes 1;
error_log %[1]s/logs/error.log;
pid %[1]s/logs/nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  server {
    listen 127.0.0.1:%[2]d;
    location = /healthz { default_type text/plain; return 200 "ok\n"; }
  }
}
`, nginxRoot, certRecoveryE2EHealthPort)
	if err := os.WriteFile(filepath.Join(nginxRoot, "conf", "nginx.conf"), []byte(nginxConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	nginx := exec.Command(openresty, "-p", nginxRoot, "-c", filepath.Join(nginxRoot, "conf", "nginx.conf"), "-g", "daemon off;")
	nginx.Stdout, nginx.Stderr = os.Stderr, os.Stderr
	if err := nginx.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nginx.Process.Kill(); _ = nginx.Wait() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe := &certRecoveryProbe{}
	waitHealthy := time.Now().Add(30 * time.Second)
	for {
		response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", certRecoveryE2EHealthPort))
		if err == nil {
			response.Body.Close()
			break
		}
		if time.Now().After(waitHealthy) {
			t.Fatalf("OpenResty did not serve: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	go probe.run(ctx)

	var gateway struct {
		EnrollmentPort  string `json:"enrollment_port"`
		MTLSPort        string `json:"mtls_port"`
		ServerName      string `json:"server_name"`
		RootCAFile      string `json:"root_ca_file"`
		EnrollmentToken string `json:"enrollment_token"`
		NodeID          string `json:"node_id"`
		TrustFile       string `json:"trust_file"`
	}
	waitJSON(t, filepath.Join(directory, "gateway.json"), &gateway)
	rootCA := copyOwnerOnly(t, gateway.RootCAFile, filepath.Join(stateRoot, "gateway", "ca.pem"), 0o600)
	trust, err := gatewayclient.LoadTrustStore(copyOwnerOnly(t, gateway.TrustFile, filepath.Join(stateRoot, "gateway", "trust.json"), 0o400))
	if err != nil {
		t.Fatal(err)
	}
	machineID := filepath.Join(stateRoot, "machine-id")
	if err := os.WriteFile(machineID, []byte(strings.ReplaceAll(uuid.NewString(), "-", "")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(stateRoot, "identity")
	enrollmentAddress := net.JoinHostPort(gatewayHost, gateway.EnrollmentPort)
	capabilities := agentCapabilities("")
	capabilities.AgentVersion, capabilities.BuildId = "1.0.35-e2e", "cert-recovery-e2e"
	versions := &commonv1.ProtocolVersionRange{Minimum: &commonv1.ProtocolVersion{Major: 1}, Maximum: &commonv1.ProtocolVersion{Major: 1}}
	enrollCtx, cancelEnroll := context.WithTimeout(ctx, time.Minute)
	result, err := enrollment.Run(enrollCtx, enrollment.Config{Address: enrollmentAddress, ServerName: gateway.ServerName,
		RootCAFile: rootCA, IdentityDir: identityDir, MachineIDFile: machineID, SupportedVersions: versions,
		Capabilities: capabilities}, []byte(gateway.EnrollmentToken))
	cancelEnroll()
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if result.NodeID != gateway.NodeID {
		t.Fatalf("enrolled node %s, want %s", result.NodeID, gateway.NodeID)
	}
	identity, err := enrollment.LoadIdentityAllowingExpired(identityDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	mtlsAddress := net.JoinHostPort(gatewayHost, gateway.MTLSPort)
	factory, err := gatewayclient.NewEndpointMTLSDialerFactory(gatewayclient.MTLSDialerConfig{Address: mtlsAddress,
		ServerName: gateway.ServerName, RootCAFile: rootCA, ClientCertificateFile: identity.ClientCertificateFile,
		ClientPrivateKeyFile: identity.ClientPrivateKeyFile, MaximumReceiveBytes: 8 << 20, MaximumSendBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(stateRoot, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	endpoints, err := gatewayclient.NewFileGatewayEndpointStateStore(filepath.Join(journal, "gateway-endpoint"),
		gatewayclient.GatewayEndpointState{Address: mtlsAddress, ServerName: gateway.ServerName})
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := gatewayclient.NewSwitchingDialer(endpoints, factory)
	if err != nil {
		t.Fatal(err)
	}
	renewer, err := enrollment.NewRenewer(identityDir)
	if err != nil {
		t.Fatal(err)
	}
	production, err := enrollment.NewRecoverer(enrollment.RecoverConfig{IdentityDir: identityDir,
		Dial: enrollment.RecoveryDial(enrollment.Config{Address: enrollmentAddress, ServerName: gateway.ServerName, RootCAFile: rootCA})})
	if err != nil {
		t.Fatal(err)
	}
	recoverer := &certRecoveryRecorder{Recoverer: production}
	clientConfig := gatewayclient.DefaultConfig()
	clientConfig.NodeID, clientConfig.BootID = identity.NodeID, uuid.NewString()
	clientConfig.ArtifactEncryptionKeyID, clientConfig.ArtifactDecryptionPrivateKey = identity.ArtifactEncryptionKeyID, identity.ArtifactEncryptionPrivateKey
	clientConfig.JournalDir, clientConfig.Capabilities = journal, capabilities
	clientConfig.InitialBackoff, clientConfig.MaximumBackoff = 100*time.Millisecond, 2*time.Second
	client, err := gatewayclient.New(clientConfig, dialer, e2eNoDeployments{}, trust,
		gatewayclient.WithCertificateRenewer(renewer, nil), gatewayclient.WithCertificateRecoverer(recoverer))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var clientErr error
	clientDone := make(chan struct{})
	go func() { clientErr = client.Run(ctx); close(clientDone) }()

	done := make(chan struct{})
	handler := http.NewServeMux()
	handler.HandleFunc("/done", func(response http.ResponseWriter, _ *http.Request) {
		select {
		case <-done:
		default:
			close(done)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("/state", func(response http.ResponseWriter, _ *http.Request) {
		state := map[string]any{"client_running": true}
		select {
		case <-clientDone:
			state["client_running"], state["client_error"] = false, fmt.Sprint(clientErr)
		default:
		}
		if encoded, err := os.ReadFile(identity.ClientCertificateFile); err == nil {
			if block, _ := pem.Decode(encoded); block != nil {
				if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
					digest := sha256.Sum256(leaf.Raw)
					state["certificate_sha256"], state["certificate_serial"] = hex.EncodeToString(digest[:]), strings.ToLower(leaf.SerialNumber.Text(16))
					state["not_after"] = leaf.NotAfter
				}
			}
		}
		probe.mu.Lock()
		state["probes"], state["probe_failures"], state["last_probe_failure"] = probe.probes, probe.failures, probe.lastFailure
		probe.mu.Unlock()
		recoverer.mu.Lock()
		state["recovered"], state["recovery_refused"], state["last_recovery_error"] = recoverer.recovered, recoverer.refused, recoverer.lastError
		recoverer.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(state)
	})
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	encoded, _ := json.Marshal(map[string]bool{"ready": true})
	if err := os.WriteFile(filepath.Join(directory, "agent.json.tmp"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "agent.json.tmp"), filepath.Join(directory, "agent.json")); err != nil {
		t.Fatal(err)
	}
	t.Logf("node %s enrolled through %s, gateway client against %s, OpenResty health on 127.0.0.1:%d",
		identity.NodeID, enrollmentAddress, mtlsAddress, certRecoveryE2EHealthPort)
	select {
	case <-done:
	case <-clientDone:
		t.Fatalf("gateway client stopped: %v", clientErr)
	case <-time.After(55 * time.Minute):
		t.Fatal("control half did not finish")
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.failures != 0 {
		t.Fatalf("OpenResty probe failures: %d of %d (last %s)", probe.failures, probe.probes, probe.lastFailure)
	}
	t.Logf("OpenResty answered all %d probes", probe.probes)
}
