package identityverificationissuerhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListenerRequiresVerifiedClientCertificateAndTLS13(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	serverCertificate, clientCertificate, roots, config := listenerPKI(t, now)
	listener, err := NewListener(t.Context(), config, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || request.URL.Path != IssuePath {
			http.Error(writer, "invalid verified request", http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- listener.Run(ctx) }()
	for deadline := time.Now().Add(time.Second); listener.Ready() != nil && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if err := listener.Ready(); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{clientCertificate}, Time: func() time.Time { return now },
	}}}
	response, err := client.Post("https://"+listener.Address()+IssuePath, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("verified response status = %d", response.StatusCode)
	}

	for name, tlsConfig := range map[string]*tls.Config{
		"no client certificate": {
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots,
			Time: func() time.Time { return now },
		},
		"TLS 1.2": {
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RootCAs: roots,
			Certificates: []tls.Certificate{clientCertificate}, Time: func() time.Time { return now },
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := &http.Client{Timeout: time.Second,
				Transport: &http.Transport{TLSClientConfig: tlsConfig}}
			if response, err := candidate.Post("https://"+listener.Address()+IssuePath, "application/json", nil); err == nil {
				_ = response.Body.Close()
				t.Fatal("untrusted request reached the HTTP handler")
			}
		})
	}

	if len(serverCertificate.Certificate) == 0 {
		t.Fatal("invalid server certificate fixture")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("listener shutdown error = %v", err)
	}
	if err := listener.Ready(); !errors.Is(err, ErrListenerNotReady) {
		t.Fatalf("listener ready after shutdown = %v", err)
	}
}

func TestListenerRejectsUnsafePrivateKeyAndDuplicateRun(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	_, _, _, config := listenerPKI(t, now)
	if err := os.Chmod(config.ServerPrivateKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if listener, err := NewListener(t.Context(), config, http.NotFoundHandler()); listener != nil ||
		!errors.Is(err, ErrListenerInvalidConfig) {
		t.Fatalf("unsafe key listener = (%T,%v)", listener, err)
	}
	if err := os.Chmod(config.ServerPrivateKeyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := NewListener(t.Context(), config, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- listener.Run(ctx) }()
	for deadline := time.Now().Add(time.Second); listener.Ready() != nil && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if err := listener.Run(ctx); !errors.Is(err, ErrListenerAlreadyRun) {
		t.Fatalf("duplicate run error = %v", err)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("listener shutdown error = %v", err)
	}
}

func listenerPKI(t *testing.T, now time.Time) (tls.Certificate, tls.Certificate, *x509.CertPool, ListenerConfig) {
	t.Helper()
	caKey := listenerRSAKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Identity Issuer Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := listenerRSAKey(t)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := listenerRSAKey(t)
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caPath := filepath.Join(directory, "client-ca.pem")
	serverCertPath := filepath.Join(directory, "server.pem")
	serverKeyPath := filepath.Join(directory, "server-key.pem")
	listenerWritePEM(t, caPath, "CERTIFICATE", caDER, 0o644)
	listenerWritePEM(t, serverCertPath, "CERTIFICATE", serverDER, 0o644)
	listenerWritePEM(t, serverKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey), 0o600)
	serverCertificate, err := tls.X509KeyPair(listenerPEM("CERTIFICATE", serverDER),
		listenerPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey)))
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := tls.X509KeyPair(listenerPEM("CERTIFICATE", clientDER),
		listenerPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey)))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return serverCertificate, clientCertificate, roots, ListenerConfig{
		ListenAddress: listenerUnusedAddress(t), ServerCertificateFile: serverCertPath,
		ServerPrivateKeyFile: serverKeyPath, ClientCAFile: caPath, Clock: func() time.Time { return now },
	}
}

func listenerRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func listenerPEM(blockType string, contents []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: contents})
}

func listenerWritePEM(t *testing.T, path, blockType string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, listenerPEM(blockType, contents), mode); err != nil {
		t.Fatal(err)
	}
}

func listenerUnusedAddress(t *testing.T) string {
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
