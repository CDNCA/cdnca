package gateway

// Gateway half of tests/artifact-set-e2e/run.sh (PA-01): the production Connect service and the production NATS
// command bus (commands from the control plane outbox, deployment status back to it) against a real JetStream
// server, and the production generated ControlInternal client over mTLS to the control half, which authorizes the
// node and serves the node artifact set configurations from PostgreSQL. Nothing on the delivery path is a stand-in.
// The PKI is issued here: the node's client certificate (gateway.json, for the edge-agent half), the gateway's
// control client certificate and the control server certificate (pki.json, for the control half).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const artifactSetGatewayWorkloadURI = "spiffe://cdn-platform/gateway/control"

type artifactSetPKIFixture struct {
	CAFile                string `json:"ca_file"`
	ServerCertificateFile string `json:"server_certificate_file"`
	ServerPrivateKeyFile  string `json:"server_private_key_file"`
	GatewayWorkloadURI    string `json:"gateway_workload_uri"`
	NodeID                string `json:"node_id"`
	ArtifactKeyID         string `json:"artifact_key_id"`
}

func TestArtifactSetGatewayProcess(t *testing.T) {
	directory, natsURL := os.Getenv("ARTIFACT_SET_E2E_DIR"), os.Getenv("ARTIFACT_SET_E2E_NATS_URL")
	if directory == "" || natsURL == "" {
		t.Skip("ARTIFACT_SET_E2E_DIR and ARTIFACT_SET_E2E_NATS_URL are not set; run tests/artifact-set-e2e/run.sh")
	}
	serveE2EGateway(t, directory, natsURL, "127.0.0.1:0", "x25519:artifact-set-e2e")
}

// serveE2EGateway issues the PKI, serves the production gateway on listen (pki.json, gateway.json in directory)
// until the control half writes "finished". artifactKeyID goes to both halves as the node's artifact key ID
// ("": the control half names the key itself, from the node identity it seeds).
func serveE2EGateway(t *testing.T, directory, natsURL, listen, artifactKeyID string) {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	nodeCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(2*time.Hour))
	gatewayCertificate := pki.client(t, 11, artifactSetGatewayWorkloadURI, now.Add(-time.Hour), now.Add(2*time.Hour))
	identity := filepath.Join(directory, "gateway-identity")
	if err := os.Mkdir(identity, 0o700); err != nil {
		t.Fatal(err)
	}
	writePEM := func(name, kind string, der []byte) string {
		path := filepath.Join(identity, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	privateKey := func(certificate tls.Certificate) []byte {
		encoded, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	caFile := writePEM("ca.pem", "CERTIFICATE", pki.caCertificate.Raw)
	writeArtifactSetJSON(t, directory, "pki.json", artifactSetPKIFixture{CAFile: caFile,
		ServerCertificateFile: writePEM("control.pem", "CERTIFICATE", pki.server.Certificate[0]),
		ServerPrivateKeyFile:  writePEM("control-key.pem", "PRIVATE KEY", privateKey(pki.server)),
		GatewayWorkloadURI:    artifactSetGatewayWorkloadURI, NodeID: testNodeID, ArtifactKeyID: artifactKeyID})

	// The control half writes its ControlInternal address once it serves.
	var address string
	deadline := time.Now().Add(3 * time.Minute)
	for address == "" {
		if encoded, err := os.ReadFile(filepath.Join(directory, "control-address")); err == nil {
			address = strings.TrimSpace(string(encoded))
		}
		if time.Now().After(deadline) {
			t.Fatal("control half did not serve ControlInternal")
		}
		time.Sleep(200 * time.Millisecond)
	}
	dialCtx, cancelDial := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelDial()
	controlConnection, err := grpc.DialContext(dialCtx, address, grpc.WithBlock(), grpc.WithReturnConnectionError(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{gatewayCertificate},
			RootCAs: pki.rootPool, ServerName: "localhost", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer controlConnection.Close()

	connection, err := nats.Connect(natsURL, nats.Name("cdnca-artifact-set-e2e-gateway"), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	bus, err := NewNATSCommandBus(connection, DefaultNATSCommandBusConfig())
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	// ControlInternal requires a canonical UUID instance ID.
	config.GatewayInstanceID, config.GatewayVersion = "6d0b5f8e-2c3a-4e71-9a44-1f2e3d4c5b6a", "e2e"
	service, err := NewWithDurableMessaging(config,
		GeneratedControlClient{Client: controlv1.NewControlInternalServiceClient(controlConnection)},
		NewMemorySessionCoordinator(), bus, bus)
	if err != nil {
		t.Fatal(err)
	}
	// tests/telemetry-e2e: the production telemetry transport (cmd/agent-gateway runtime.go), publishing to the
	// streams the control half created before it wrote control-address.
	if os.Getenv("DYNROUTE_E2E_TELEMETRY") == "1" {
		telemetryConfig := DefaultTelemetryConfig()
		publisherConfig := DefaultNATSTelemetryPublisherConfig()
		publisherConfig.OperationTimeout = telemetryConfig.PublishTimeout
		publisher, err := NewNATSTelemetryPublisher(connection, publisherConfig)
		if err != nil {
			t.Fatal(err)
		}
		if err := publisher.Check(t.Context()); err != nil {
			t.Fatalf("telemetry streams: %v", err)
		}
		if err := service.ConfigureTelemetry(telemetryConfig, publisher, NewMemorySessionCoordinator(), NewTelemetryHealth()); err != nil {
			t.Fatal(err)
		}
	}
	// tests/license-ban-e2e: the production installation ban bus (cmd/agent-gateway configureInstallationBan).
	if os.Getenv("DYNROUTE_E2E_INSTALLATION_BAN") == "1" {
		banBus, err := NewNATSInstallationBanBus(t.Context(), connection, DefaultNATSInstallationBanBusConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := service.ConfigureInstallationBan(banBus); err != nil {
			t.Fatal(err)
		}
	}
	// tests/dynroute-e2e DYNROUTE_E2E_SITE_DROP=1: the production site drop bus (cmd/agent-gateway configureSiteDrops).
	if os.Getenv("DYNROUTE_E2E_SITE_DROP") == "1" {
		siteDropBus, err := NewNATSSiteDropBus(t.Context(), connection, DefaultNATSSiteDropBusConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := service.ConfigureSiteDrops(siteDropBus); err != nil {
			t.Fatal(err)
		}
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(listener) }()
	defer servers.MTLS.Stop()
	writeArtifactSetJSON(t, directory, "gateway.json", map[string]string{"address": listener.Addr().String(),
		"server_name": "localhost", "root_ca_file": caFile,
		"client_certificate_file": writePEM("node.pem", "CERTIFICATE", nodeCertificate.Certificate[0]),
		"client_private_key_file": writePEM("node-key.pem", "PRIVATE KEY", privateKey(nodeCertificate)),
		"node_id":                 testNodeID, "artifact_key_id": artifactKeyID})
	t.Logf("agent gateway serving node %s on %s (ControlInternal %s, NATS command bus)", testNodeID, listener.Addr(), address)
	deadline = time.Now().Add(45 * time.Minute)
	for {
		if _, err := os.Stat(filepath.Join(directory, "finished")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("control half did not finish")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func writeArtifactSetJSON(t *testing.T, directory, name string, value any) {
	t.Helper()
	encoded, _ := json.Marshal(value)
	if err := os.WriteFile(filepath.Join(directory, name+".tmp"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, name+".tmp"), filepath.Join(directory, name)); err != nil {
		t.Fatal(err)
	}
}
