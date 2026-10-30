package gateway

// Gateway half of tests/signer-trust-push-e2e/run.sh: the production Connect service and the production NATS signer
// trust bus against a real JetStream server. Control-plane authorization is a stand-in: the node is active; it allows
// deployments until <dir>/deployments-paused exists (signer trust must still be delivered), and it writes the
// capabilities of the session facts the gateway reports (the exact capabilities_snapshot control-api stores in
// node_session_capabilities) to <dir>/session-capabilities.bin for the control half.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// e2eGatewayFixture is gateway.json: the mTLS endpoint and node identity the edge-agent half connects with.
type e2eGatewayFixture struct {
	Address               string `json:"address"`
	ServerName            string `json:"server_name"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientPrivateKeyFile  string `json:"client_private_key_file"`
	NodeID                string `json:"node_id"`
	ArtifactKeyID         string `json:"artifact_key_id"`
}

type signerTrustE2EControl struct {
	*fakeControl
	directory string
}

func (control signerTrustE2EControl) GetNodeAuthorization(ctx context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	response, err := control.fakeControl.GetNodeAuthorization(ctx, request)
	if response != nil {
		_, paused := os.Stat(filepath.Join(control.directory, "deployments-paused"))
		response.DeploymentsAllowed = paused != nil
	}
	if facts := request.GetSessionFacts(); facts != nil {
		snapshot, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(facts.Capabilities)
		if marshalErr == nil {
			temporary := filepath.Join(control.directory, "session-capabilities.bin.tmp")
			if os.WriteFile(temporary, snapshot, 0o600) == nil {
				_ = os.Rename(temporary, filepath.Join(control.directory, "session-capabilities.bin"))
			}
		}
	}
	return response, err
}

func TestSignerTrustGatewayProcess(t *testing.T) {
	directory, natsURL := os.Getenv("SIGNER_PUSH_E2E_DIR"), os.Getenv("SIGNER_PUSH_E2E_NATS_URL")
	if directory == "" || natsURL == "" {
		t.Skip("SIGNER_PUSH_E2E_DIR and SIGNER_PUSH_E2E_NATS_URL are not set; run tests/signer-trust-push-e2e/run.sh")
	}
	connection, err := nats.Connect(natsURL, nats.Name("cdnca-signer-push-e2e-gateway"), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(2*time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-signer-push-e2e", "e2e"
	service, err := New(config, signerTrustE2EControl{fakeControl: defaultFakeControl(), directory: directory},
		NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	bus, err := NewNATSSignerTrustBus(t.Context(), connection, DefaultNATSSignerTrustBusConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureSignerTrust(bus); err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(listener) }()
	defer servers.MTLS.Stop()

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
	key, err := x509.MarshalPKCS8PrivateKey(clientCertificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture := e2eGatewayFixture{Address: listener.Addr().String(), ServerName: "localhost",
		RootCAFile:            writePEM("ca.pem", "CERTIFICATE", pki.caCertificate.Raw),
		ClientCertificateFile: writePEM("client.pem", "CERTIFICATE", clientCertificate.Certificate[0]),
		ClientPrivateKeyFile:  writePEM("client-key.pem", "PRIVATE KEY", key),
		NodeID:                testNodeID, ArtifactKeyID: "artifact-key"}
	encoded, _ := json.Marshal(fixture)
	if err := os.WriteFile(filepath.Join(directory, "gateway.json.tmp"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "gateway.json.tmp"), filepath.Join(directory, "gateway.json")); err != nil {
		t.Fatal(err)
	}
	t.Logf("agent gateway serving node %s on %s with the NATS signer trust bus", testNodeID, fixture.Address)
	deadline := time.Now().Add(30 * time.Minute)
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
