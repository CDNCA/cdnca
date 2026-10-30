//go:build versionskew

package gateway

// Gateway half of tests/version-skew-e2e/run.sh. run.sh copies this file into the agent-gateway package of the
// tree under test (the released baseline or the candidate), so it may only use helpers that exist in both trees.
// The control plane is a stand-in that behaves like the control-api of the same tree: it commits session facts
// only when every capability name is known to this tree's proto (nodeidentity.canonicalCapabilities), and answers
// with the facts digest so the production Gateway can enable edge upgrades.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const e2eSkewInstallationID = "7a1f6c3e-2b4d-4e8f-9a0b-1c2d3e4f5a6b"

type e2eSkewFactsRecord struct {
	Present  bool    `json:"present"`
	Rejected bool    `json:"rejected"`
	Features []int32 `json:"features"`
}

type e2eSkewControl struct {
	*fakeControl
	mu      sync.Mutex
	path    string
	records []e2eSkewFactsRecord
}

func (c *e2eSkewControl) GetNodeAuthorization(ctx context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	response, err := c.fakeControl.GetNodeAuthorization(ctx, request)
	if err != nil {
		return nil, err
	}
	response.DeploymentsAllowed = true
	response.InstallationId = e2eSkewInstallationID
	facts := request.GetSessionFacts()
	if facts == nil {
		return response, nil
	}
	record := e2eSkewFactsRecord{Present: true}
	for _, feature := range facts.GetCapabilities().GetFeatures() {
		record.Features = append(record.Features, int32(feature.GetName()))
		if _, known := agentv1.CapabilityName_name[int32(feature.GetName())]; !known {
			record.Rejected = true
		}
	}
	c.record(record)
	if record.Rejected {
		// Same answer as this tree's control-api: unknown capability names are invalid session facts.
		return nil, status.Error(codes.InvalidArgument, "invalid session facts")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(facts)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	response.SessionFactsSha256 = digest[:]
	response.SnapshotExpirationTime = timestamppb.New(time.Now().Add(time.Hour))
	return response, nil
}

func (c *e2eSkewControl) record(record e2eSkewFactsRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
	encoded, _ := json.Marshal(c.records)
	_ = os.WriteFile(c.path+".tmp", encoded, 0o600)
	_ = os.Rename(c.path+".tmp", c.path)
}

type e2eSkewUpgradeBus struct{}

func (e2eSkewUpgradeBus) SubscribeUpgrade(context.Context, string) (UpgradeCommandSubscription, error) {
	return e2eSkewUpgradeSubscription{}, nil
}

func (e2eSkewUpgradeBus) PublishUpgradeStatus(context.Context, string, []byte) (UpgradeStatusPublication, error) {
	return UpgradeStatusPublication{Stream: "EDGE_UPGRADE_STATUS", Sequence: 1}, nil
}

type e2eSkewUpgradeSubscription struct{}

func (e2eSkewUpgradeSubscription) Next(ctx context.Context) (UpgradeCommandDelivery, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (e2eSkewUpgradeSubscription) Close() error { return nil }

type e2eSkewGatewayFixture struct {
	Address               string `json:"address"`
	ServerName            string `json:"server_name"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientPrivateKeyFile  string `json:"client_private_key_file"`
	NodeID                string `json:"node_id"`
	ArtifactKeyID         string `json:"artifact_key_id"`
}

func TestVersionSkewGatewayProcess(t *testing.T) {
	directory := os.Getenv("SKEW_E2E_DIR")
	if directory == "" {
		t.Skip("SKEW_E2E_DIR is not set; run tests/version-skew-e2e/run.sh")
	}
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(2*time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-skew-e2e", "skew"
	control := &e2eSkewControl{fakeControl: defaultFakeControl(), path: filepath.Join(directory, "gateway-facts.json")}
	service, err := New(config, control, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureUpgradeMessaging(e2eSkewUpgradeBus{}); err != nil {
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
	fixture := e2eSkewGatewayFixture{Address: listener.Addr().String(), ServerName: "localhost",
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
	t.Logf("gateway serving node %s on %s", testNodeID, fixture.Address)
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if _, err := os.Stat(filepath.Join(directory, "finished")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("agent half did not finish")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
