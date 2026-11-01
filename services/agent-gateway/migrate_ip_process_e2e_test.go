package gateway

// Gateway stand-in of tests/control-migrate-e2e/run.sh: the
// production Connect service (mTLS, GatewayHello endpoint list, heartbeats)
// started by the cdnca-agent-gateway systemd unit of the control host
// containers. It reads what the real Gateway reads on that host: the server
// certificate and the installation root under /etc/cdnca-control/keys/pki
// (RetargetGatewayHost re-signs it on the migration target), the agent port
// from gateway.env, and the node endpoint list in the order Publish builds it
// (CDNCA_GATEWAY_LOCAL_* from control.env, then agent_gateway_entrypoints).
// Like the real Gateway it learns the list at startup and serves it in every
// GatewayHello. Node presence goes to node_presence through psql; control
// plane authorization is the test fake (every node active).

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
)

type migrateIPNoHeartbeats struct{}

func (migrateIPNoHeartbeats) PersistHeartbeat(context.Context, string, *agentv1.Heartbeat) error {
	return nil
}

var migrateIPNodeID = regexp.MustCompile(`^[0-9a-f-]{36}$`)

func migrateIPPsql(t *testing.T, statement string) string {
	output, err := exec.Command("runuser", "-u", "postgres", "--", "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-d", "cdnca",
		"-c", statement).CombinedOutput()
	if err != nil {
		t.Logf("psql %q: %v %s", statement, err, output)
	}
	return strings.TrimSpace(string(output))
}

func migrateIPEnvironment(t *testing.T, path string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if name, value, found := strings.Cut(scanner.Text(), "="); found {
			values[name] = value
		}
	}
	return values
}

func TestMigrateIPGatewayProcess(t *testing.T) {
	config := os.Getenv("MIGRATE_IP_E2E_CONFIG_DIR")
	if config == "" {
		t.Skip("MIGRATE_IP_E2E_CONFIG_DIR is not set; started by tests/control-migrate-e2e")
	}
	pki := filepath.Join(config, "keys", "pki")
	server, err := tls.LoadX509KeyPair(filepath.Join(pki, "gateway-server.pem"), filepath.Join(pki, "gateway-server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(pki, "root-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("root-ca-cert.pem holds no certificate")
	}
	_, port, err := net.SplitHostPort(migrateIPEnvironment(t, filepath.Join(config, "gateway.env"))["CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT"])
	if err != nil {
		t.Fatal(err)
	}
	// Publish order: the co-located Gateway, then the page-edited entries;
	// a repeated address is dropped.
	control := migrateIPEnvironment(t, filepath.Join(config, "control.env"))
	endpoints := []*agentv1.GatewayEndpointV1{}
	seen := map[string]bool{}
	add := func(address, serverName, enrollment string) {
		if address != "" && !seen[address] {
			seen[address] = true
			endpoints = append(endpoints, &agentv1.GatewayEndpointV1{Address: address, ServerName: serverName,
				Transport: "grpc", EnrollmentAddress: enrollment})
		}
	}
	add(control["CDNCA_GATEWAY_LOCAL_ADDRESS"], control["CDNCA_GATEWAY_LOCAL_SERVER_NAME"], control["CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS"])
	for _, line := range strings.Split(migrateIPPsql(t, "SELECT address||' '||server_name FROM agent_gateway_entrypoints WHERE transport='grpc' ORDER BY position"), "\n") {
		if address, serverName, found := strings.Cut(line, " "); found {
			add(address, serverName, "")
		}
	}
	digest := sha256.New()
	for _, endpoint := range endpoints {
		fmt.Fprintf(digest, "%s\x00%s\x00grpc\x00\x00%s\n", endpoint.Address, endpoint.ServerName, endpoint.EnrollmentAddress)
	}
	nodeEndpoints := &NodeEndpoints{}
	nodeEndpoints.set(endpoints, hex.EncodeToString(digest.Sum(nil))[:32])

	gatewayConfig := DefaultConfig()
	gatewayConfig.GatewayInstanceID, gatewayConfig.GatewayVersion = "migrate-ip-e2e", "e2e"
	service, err := NewWithDurableMessaging(gatewayConfig, defaultFakeControl(), NewMemorySessionCoordinator(), &fakeCommandBus{}, migrateIPNoHeartbeats{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureNodeEndpoints(nodeEndpoints); err != nil {
		t.Fatal(err)
	}
	presence := func(stream grpc.ServerStream, status string) {
		identity, err := authenticatedNode(stream.Context())
		if err != nil || !migrateIPNodeID.MatchString(identity.NodeID) {
			return
		}
		migrateIPPsql(t, "UPDATE node_presence SET status='"+status+"', last_seen_at=now() WHERE node_id='"+identity.NodeID+"'")
		t.Logf("node %s %s", identity.NodeID, status)
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{server}},
		&tls.Config{Certificates: []tls.Certificate{server}, ClientCAs: roots},
		grpc.ChainStreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if info.FullMethod != agentv1.AgentGatewayService_Connect_FullMethodName {
				return handler(srv, stream)
			}
			presence(stream, "online")
			err := handler(srv, stream)
			presence(stream, "offline")
			return err
		}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		_ = http.ListenAndServe("0.0.0.0:8082", mux)
	}()
	var names []string
	for _, endpoint := range endpoints {
		names = append(names, endpoint.Address+"/"+endpoint.ServerName)
	}
	t.Logf("gateway :%s certificate %v %v, endpoint list %v", port, server.Leaf.DNSNames, server.Leaf.IPAddresses, names)
	if err := servers.MTLS.Serve(listener); err != nil {
		t.Fatal(err)
	}
}
