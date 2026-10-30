package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlinternal"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestOpenControlInternalRuntimeAuthenticatesExactGatewayWorkload(t *testing.T) {
	pki := newControlRuntimePKI(t)
	cfg := config.Config{
		ControlInternalGRPCAddr:    unusedControlAddress(t),
		ControlInternalServerCert:  pki.serverCertificate,
		ControlInternalServerKey:   pki.serverKey,
		ControlInternalGatewayCA:   pki.transportCA,
		ControlInternalGatewayURI:  controlinternal.DefaultGatewayWorkloadURISAN,
		NodeCACertificateChainFile: pki.nodeCA,
		NodeCAPrivateKeyFile:       pki.nodeCAKey,
		ShutdownPeriod:             2 * time.Second,
	}
	runtime, err := openControlInternalRuntime(context.Background(), cfg, new(pgxpool.Pool))
	if err != nil {
		t.Fatalf("openControlInternalRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- runtime.Serve(ctx) }()
	waitControlReady(t, runtime.Ready)

	trusted := dialControlRuntime(t, runtime.Address(), pki, pki.gatewayCertificate, pki.gatewayKey)
	callCtx, cancelCall := context.WithTimeout(context.Background(), 2*time.Second)
	healthResponse, err := healthv1.NewHealthClient(trusted).Check(callCtx, &healthv1.HealthCheckRequest{
		Service: controlv1.ControlInternalService_ServiceDesc.ServiceName,
	})
	if err != nil || healthResponse.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		cancelCall()
		t.Fatalf("ControlInternal health = (%v, %v)", healthResponse, err)
	}
	_, err = controlv1.NewControlInternalServiceClient(trusted).AuthorizeEnrollment(
		callCtx, &controlv1.AuthorizeEnrollmentRequest{},
	)
	cancelCall()
	_ = trusted.Close()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("trusted Gateway reached status %v, want InvalidArgument", status.Code(err))
	}

	wrong := dialControlRuntime(t, runtime.Address(), pki, pki.wrongGatewayCertificate, pki.wrongGatewayKey)
	callCtx, cancelCall = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = controlv1.NewControlInternalServiceClient(wrong).AuthorizeEnrollment(
		callCtx, &controlv1.AuthorizeEnrollmentRequest{},
	)
	cancelCall()
	_ = wrong.Close()
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong Gateway workload status = %v, want Unauthenticated", status.Code(err))
	}

	cancel()
	select {
	case err := <-serveDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() cancellation error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ControlInternal runtime did not stop within the bound")
	}
}

type controlRuntimePKI struct {
	transportCA             string
	serverCertificate       string
	serverKey               string
	gatewayCertificate      string
	gatewayKey              string
	wrongGatewayCertificate string
	wrongGatewayKey         string
	nodeCA                  string
	nodeCAKey               string
}

func newControlRuntimePKI(t *testing.T) controlRuntimePKI {
	t.Helper()
	directory := t.TempDir()
	now := time.Now().UTC()
	transportCertificate, transportKey := issueControlCertificate(t, nil, nil, controlCertificateTemplate{
		commonName: "control transport root", isCA: true,
		notBefore: now.Add(-time.Hour), notAfter: now.Add(96 * time.Hour),
	})
	serverCertificate, serverKey := issueControlCertificate(t, transportCertificate, transportKey, controlCertificateTemplate{
		commonName: "control.internal", dnsNames: []string{"localhost"},
		extendedUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		notBefore:     now.Add(-time.Hour), notAfter: now.Add(72 * time.Hour),
	})
	gatewayCertificate, gatewayKey := issueControlCertificate(t, transportCertificate, transportKey, controlCertificateTemplate{
		commonName: "agent gateway", uri: controlinternal.DefaultGatewayWorkloadURISAN,
		extendedUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore:     now.Add(-time.Hour), notAfter: now.Add(72 * time.Hour),
	})
	wrongGatewayCertificate, wrongGatewayKey := issueControlCertificate(t, transportCertificate, transportKey, controlCertificateTemplate{
		commonName: "wrong gateway", uri: "spiffe://cdn-platform/gateway/wrong",
		extendedUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore:     now.Add(-time.Hour), notAfter: now.Add(72 * time.Hour),
	})
	nodeCertificate, nodeKey := issueControlCertificate(t, nil, nil, controlCertificateTemplate{
		// 签发的节点证书有效期为 nodeidentity.DefaultCertificateTTL（GW-01 起 30 天），签发 CA 必须覆盖它
		commonName: "node issuer", isCA: true,
		notBefore: now.Add(-time.Hour), notAfter: now.Add(nodeidentity.DefaultCertificateTTL + 96*time.Hour),
	})

	return controlRuntimePKI{
		transportCA:             writeControlCertificate(t, directory, "transport-ca.pem", transportCertificate, 0o644),
		serverCertificate:       writeControlCertificate(t, directory, "server.pem", serverCertificate, 0o644),
		serverKey:               writeControlKey(t, directory, "server-key.pem", serverKey),
		gatewayCertificate:      writeControlCertificate(t, directory, "gateway.pem", gatewayCertificate, 0o644),
		gatewayKey:              writeControlKey(t, directory, "gateway-key.pem", gatewayKey),
		wrongGatewayCertificate: writeControlCertificate(t, directory, "wrong-gateway.pem", wrongGatewayCertificate, 0o644),
		wrongGatewayKey:         writeControlKey(t, directory, "wrong-gateway-key.pem", wrongGatewayKey),
		nodeCA:                  writeControlCertificate(t, directory, "node-ca.pem", nodeCertificate, 0o644),
		nodeCAKey:               writeControlKey(t, directory, "node-ca-key.pem", nodeKey),
	}
}

type controlCertificateTemplate struct {
	commonName    string
	isCA          bool
	dnsNames      []string
	uri           string
	extendedUsage []x509.ExtKeyUsage
	notBefore     time.Time
	notAfter      time.Time
}

func issueControlCertificate(
	t *testing.T,
	parent *x509.Certificate,
	parentKey crypto.Signer,
	input controlCertificateTemplate,
) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil || serial.Sign() == 0 {
		t.Fatal("generate certificate serial")
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: input.commonName},
		NotBefore: input.notBefore, NotAfter: input.notAfter,
		BasicConstraintsValid: true, IsCA: input.isCA,
		DNSNames: input.dnsNames, ExtKeyUsage: input.extendedUsage,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if input.isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if input.uri != "" {
		parsed, parseErr := url.Parse(input.uri)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		template.URIs = []*url.URL{parsed}
	}
	if parent == nil {
		parent = template
		parentKey = privateKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, privateKey
}

func writeControlCertificate(t *testing.T, directory, name string, certificate *x509.Certificate, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, encoded, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeControlKey(t *testing.T, directory, name string, key crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dialControlRuntime(t *testing.T, address string, pki controlRuntimePKI, certificateFile, keyFile string) *grpc.ClientConn {
	t.Helper()
	rootPEM, err := os.ReadFile(pki.transportCA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append transport root")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{certificate},
	})))
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func unusedControlAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitControlReady(t *testing.T, ready func() error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for ready() != nil {
		if time.Now().After(deadline) {
			t.Fatal("ControlInternal runtime did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
}
