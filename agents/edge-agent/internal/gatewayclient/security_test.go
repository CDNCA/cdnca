package gatewayclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestMTLSDialerVerifiesBothPeers(t *testing.T) {
	directory := filepath.Join(secureTempDir(t), "pki")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, serverKey := issueTestCertificate(t, rootCertificate, rootKey, "gateway.test", []string{"gateway.test"}, x509.ExtKeyUsageServerAuth, 2)
	clientCertificate, clientKey := issueTestCertificate(t, rootCertificate, rootKey, "edge-agent", nil, x509.ExtKeyUsageClientAuth, 3)
	rootPath := writePEM(t, directory, "root.pem", "CERTIFICATE", rootDER)
	serverCertPath := writePEM(t, directory, "server.pem", "CERTIFICATE", serverCertificate)
	serverKeyPath := writeECPrivateKey(t, directory, "server.key", serverKey)
	clientCertPath := writePEM(t, directory, "client.pem", "CERTIFICATE", clientCertificate)
	clientKeyPath := writeECPrivateKey(t, directory, "client.key", clientKey)

	serverPair, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(rootCertificate)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	})))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	dialer, err := NewMTLSDialer(MTLSDialerConfig{
		Address: listener.Addr().String(), ServerName: "gateway.test", RootCAFile: rootPath,
		ClientCertificateFile: clientCertPath, ClientPrivateKeyFile: clientKeyPath,
		MaximumReceiveBytes: 1 << 20, MaximumSendBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatalf("mTLS Dial() error = %v", err)
	}
	_ = connection.Close()

	wrongName, err := NewMTLSDialer(MTLSDialerConfig{
		Address: listener.Addr().String(), ServerName: "wrong.test", RootCAFile: rootPath,
		ClientCertificateFile: clientCertPath, ClientPrivateKeyFile: clientKeyPath,
		MaximumReceiveBytes: 1 << 20, MaximumSendBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongCtx, wrongCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer wrongCancel()
	if connection, err := wrongName.Dial(wrongCtx); err == nil {
		_ = connection.Close()
		t.Fatal("Dial() accepted a certificate for the wrong server name")
	}
}

func TestSecurityFilesRejectWeakDirectoriesAndWritableTrust(t *testing.T) {
	directory := filepath.Join(secureTempDir(t), "weak")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "anchor.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustStore(path); err == nil {
		t.Fatal("LoadTrustStore() accepted a group/world-accessible directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustStore(path); err == nil {
		t.Fatal("LoadTrustStore() accepted an owner-writable trust anchor")
	}
}

func TestSecureDirectoriesRejectSymlinkedAncestors(t *testing.T) {
	root := secureTempDir(t)
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	existingDirectory := filepath.Join(realDirectory, "existing")
	if err := os.Mkdir(existingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := validateSecureDirectory(filepath.Join(linkedDirectory, "existing"), false); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("validateSecureDirectory(existing) error = %v, want invalid configuration", err)
	}
	if err := validateSecureDirectory(filepath.Join(linkedDirectory, "new", "journal"), true); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("validateSecureDirectory(create) error = %v, want invalid configuration", err)
	}
	if _, err := os.Lstat(filepath.Join(realDirectory, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlinked directory creation changed its target: %v", err)
	}

	securityFile := filepath.Join(realDirectory, "anchor.json")
	if err := os.WriteFile(securityFile, []byte(`{"version":1,"keys":[]}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := validateSecureRegularFile(filepath.Join(linkedDirectory, "anchor.json"), true); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("validateSecureRegularFile() error = %v, want invalid configuration", err)
	}
}

func TestArtifactSignatureFailClosed(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := &agentv1.ArtifactDescriptor{
		SigningKeyId: "key", SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Signature: make([]byte, ed25519.SignatureSize),
	}
	if err := verifyArtifactSignature(descriptor, []byte("tampered"), trust); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("verifyArtifactSignature() error = %v, want artifact integrity error", err)
	}
}

func TestECDSASignatureAndBoundedZSTD(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"p256": &privateKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("signed compressed configuration")
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	descriptor := &agentv1.ArtifactDescriptor{
		SigningKeyId: "p256", SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
		Signature: signature,
	}
	if err := verifyArtifactSignature(descriptor, payload, trust); err != nil {
		t.Fatalf("verifyArtifactSignature() error = %v", err)
	}
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed := encoder.EncodeAll(payload, nil)
	encoder.Close()
	decoded, err := decompressArtifact(agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD, compressed, int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded payload = %q, want %q", decoded, payload)
	}
	if _, err := decompressArtifact(agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD, compressed, int64(len(payload)-1)); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("bounded decompression error = %v, want artifact integrity error", err)
	}
}

func issueTestCertificate(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, commonName string, dnsNames []string, usage x509.ExtKeyUsage, serial int64) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func writePEM(t *testing.T, directory, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeECPrivateKey(t *testing.T, directory, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, directory, name, "EC PRIVATE KEY", der)
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
