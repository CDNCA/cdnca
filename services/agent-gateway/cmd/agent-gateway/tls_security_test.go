package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

const testGatewayWorkloadURI = "spiffe://cdn-platform/gateway/control"

func TestTLSRejectsGroupOrWorldReadablePrivateKeys(t *testing.T) {
	pki := createTestPKI(t)
	keyContents, err := os.ReadFile(pki.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			keyFile := filepath.Join(t.TempDir(), "do-not-log-private-key.pem")
			if err := os.WriteFile(keyFile, keyContents, mode); err != nil {
				t.Fatal(err)
			}
			cfg := tlsTestConfig(pki)
			cfg.serverKeyFile = keyFile
			_, _, err := loadListenerTLS(cfg)
			if err == nil {
				t.Fatal("Gateway server accepted an over-permissive private key")
			}
			assertTLSFailureSanitized(t, err, keyFile, keyContents)

			cfg = tlsTestConfig(pki)
			cfg.controlKeyFile = keyFile
			_, err = loadControlTLS(cfg)
			if err == nil {
				t.Fatal("Control client accepted an over-permissive private key")
			}
			assertTLSFailureSanitized(t, err, keyFile, keyContents)
		})
	}
}

func TestTLSAllowsWorldReadablePublicCertificates(t *testing.T) {
	pki := createTestPKI(t)
	for _, path := range []string{pki.serverCertificate, pki.controlCertificate, pki.caCertificate} {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := tlsTestConfig(pki)
	if _, _, err := loadListenerTLS(cfg); err != nil {
		t.Fatalf("public listener certificate permissions rejected: %v", err)
	}
	if _, err := loadControlTLS(cfg); err != nil {
		t.Fatalf("public Control certificate permissions rejected: %v", err)
	}
}

func TestTLSRejectsImplicitAnyOrMultipleExtendedUsages(t *testing.T) {
	pki := createTestPKI(t)
	workloadURI := mustParseTestURI(t, testGatewayWorkloadURI)
	tests := []struct {
		name   string
		usages []x509.ExtKeyUsage
	}{
		{name: "empty"},
		{name: "any", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{name: "multiple", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificateFile, keyFile := createTestLeafWithUsages(
				t, filepath.Dir(pki.caCertificate), "invalid-eku-"+test.name, int64(20+index),
				pki.ca, pki.caKey, test.usages, []*url.URL{workloadURI},
			)
			if _, err := loadCertificate(certificateFile, keyFile, x509.ExtKeyUsageClientAuth); err == nil {
				t.Fatal("Control client accepted a non-exact EKU")
			}
		})
	}
}

func TestLoadControlTLSRequiresSingleExactWorkloadURISAN(t *testing.T) {
	pki := createTestPKI(t)
	expected := mustParseTestURI(t, testGatewayWorkloadURI)
	other := mustParseTestURI(t, "spiffe://cdn-platform/gateway/other")
	tests := []struct {
		name string
		uris []*url.URL
	}{
		{name: "missing"},
		{name: "wrong", uris: []*url.URL{other}},
		{name: "multiple", uris: []*url.URL{expected, other}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificateFile, keyFile := createTestLeafWithUsages(
				t, filepath.Dir(pki.caCertificate), "invalid-uri-"+test.name, int64(30+index), pki.ca, pki.caKey,
				[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, test.uris,
			)
			cfg := tlsTestConfig(pki)
			cfg.controlCertificateFile = certificateFile
			cfg.controlKeyFile = keyFile
			_, err := loadControlTLS(cfg)
			if err == nil || err.Error() != "validate ControlInternal client workload identity" {
				t.Fatalf("workload URI error = %v", err)
			}
			if strings.Contains(err.Error(), testGatewayWorkloadURI) || strings.Contains(err.Error(), other.String()) {
				t.Fatalf("workload URI error leaked identity: %v", err)
			}
		})
	}
}

func TestLoadedControlTLSCompletesRealMutualTLS13Handshake(t *testing.T) {
	pki := createTestPKI(t)
	cfg := tlsTestConfig(pki)
	controlTLS, err := loadControlTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := loadCertificate(pki.serverCertificate, pki.serverKey, x509.ExtKeyUsageServerAuth)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots, err := loadCAPool(pki.caCertificate)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, ClientCAs: clientRoots,
		ClientAuth: tls.RequireAndVerifyClientCert,
	})))
	healthServer := health.NewServer()
	healthServer.SetServingStatus(controlv1.ControlInternalService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
		<-serveDone
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(
		ctx, listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(controlTLS)), grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("ControlInternal mTLS handshake failed: %v", err)
	}
	if err := verifyControlHealth(ctx, connection); err != nil {
		t.Fatalf("ControlInternal application health failed after mTLS: %v", err)
	}
	_ = connection.Close()
}

func TestClearBytesRemovesRawPrivateKeyPEM(t *testing.T) {
	contents := []byte("private-key-material")
	clearBytes(contents)
	for index, value := range contents {
		if value != 0 {
			t.Fatalf("private key byte %d was not cleared", index)
		}
	}
}

func tlsTestConfig(pki testPKIPaths) config {
	return config{
		serverCertificateFile:       pki.serverCertificate,
		serverKeyFile:               pki.serverKey,
		agentClientCAFile:           pki.caCertificate,
		controlCertificateFile:      pki.controlCertificate,
		controlKeyFile:              pki.controlKey,
		controlServerCAFile:         pki.caCertificate,
		controlServerName:           "localhost",
		controlClientWorkloadURISAN: testGatewayWorkloadURI,
	}
}

func assertTLSFailureSanitized(t *testing.T, err error, path string, material []byte) {
	t.Helper()
	if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), filepath.Dir(path)) || strings.Contains(err.Error(), string(material)) {
		t.Fatalf("TLS failure leaked a path or private key material: %v", err)
	}
}

func mustParseTestURI(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
