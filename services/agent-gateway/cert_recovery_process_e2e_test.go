package gateway

// Gateway half of tests/cert-recovery-e2e/run.sh (ADR 0013 GW-02): the production Connect service with both
// listeners (server-TLS enrollment listener carrying Enroll and RecoverCertificate, mTLS listener carrying Connect),
// the production generated ControlInternal client over mTLS and the production Redis session coordinator. The control
// half starts this process, kills it to take the gateway away from the node and starts it again with a new instance
// ID: the Redis session epoch keeps growing across restarts, as the control plane requires (session facts refuse an
// epoch that goes back).

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// certRecoveryGatewayConfig is gateway-config.json, written by the control half.
type certRecoveryGatewayConfig struct {
	ControlAddress         string `json:"control_address"`
	ServerCertificateFile  string `json:"server_certificate_file"`
	ServerPrivateKeyFile   string `json:"server_private_key_file"`
	TransportCAFile        string `json:"transport_ca_file"`
	NodeCAFile             string `json:"node_ca_file"`
	GatewayCertificateFile string `json:"gateway_certificate_file"`
	GatewayPrivateKeyFile  string `json:"gateway_private_key_file"`
	RedisAddress           string `json:"redis_address"`
	EnrollmentListen       string `json:"enrollment_listen"`
	MTLSListen             string `json:"mtls_listen"`
}

func TestCertRecoveryGatewayProcess(t *testing.T) {
	directory, instanceID := os.Getenv("CERT_RECOVERY_E2E_DIR"), os.Getenv("CERT_RECOVERY_E2E_GATEWAY_INSTANCE")
	if directory == "" || instanceID == "" {
		t.Skip("CERT_RECOVERY_E2E_DIR and CERT_RECOVERY_E2E_GATEWAY_INSTANCE are not set; run tests/cert-recovery-e2e/run.sh")
	}
	encoded, err := os.ReadFile(filepath.Join(directory, "gateway-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config certRecoveryGatewayConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	certificatePool := func(path string) *x509.CertPool {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(encoded) {
			t.Fatalf("%s holds no certificate", path)
		}
		return pool
	}
	server, err := tls.LoadX509KeyPair(config.ServerCertificateFile, config.ServerPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	gatewayCertificate, err := tls.LoadX509KeyPair(config.GatewayCertificateFile, config.GatewayPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	controlConnection, err := grpc.NewClient("passthrough:///"+config.ControlAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{gatewayCertificate},
			RootCAs: certificatePool(config.TransportCAFile), ServerName: "localhost", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer controlConnection.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: config.RedisAddress})
	defer redisClient.Close()
	sessions, err := NewRedisSessionCoordinator(t.Context(), redisClient, RedisSessionCoordinatorConfig{
		GatewayInstanceID: instanceID, KeyPrefix: "cdnca:cert-recovery-e2e", LeaseTTL: 15 * time.Second,
		RenewInterval: 5 * time.Second, OperationTimeout: 2 * time.Second, AcquireTimeout: 10 * time.Second,
		AcquireRetryInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	gatewayConfig := DefaultConfig()
	gatewayConfig.GatewayInstanceID, gatewayConfig.GatewayVersion = instanceID, "e2e"
	service, err := New(gatewayConfig, GeneratedControlClient{Client: controlv1.NewControlInternalServiceClient(controlConnection)}, sessions)
	if err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{server}},
		&tls.Config{Certificates: []tls.Certificate{server}, ClientCAs: certificatePool(config.NodeCAFile)})
	if err != nil {
		t.Fatal(err)
	}
	enrollmentListener, err := net.Listen("tcp", config.EnrollmentListen)
	if err != nil {
		t.Fatal(err)
	}
	mtlsListener, err := net.Listen("tcp", config.MTLSListen)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.Enrollment.Serve(enrollmentListener) }()
	go func() { _ = servers.MTLS.Serve(mtlsListener) }()
	defer servers.Enrollment.Stop()
	defer servers.MTLS.Stop()
	t.Logf("agent gateway %s: enrollment %s, mTLS %s, ControlInternal %s, Redis sessions %s",
		instanceID, enrollmentListener.Addr(), mtlsListener.Addr(), config.ControlAddress, config.RedisAddress)
	// The control half kills this process (gateway outage) or writes "finished".
	deadline := time.Now().Add(55 * time.Minute)
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
