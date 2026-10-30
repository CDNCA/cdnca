package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testToken = []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))

type rpcFunc func(context.Context, *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error)

func (function rpcFunc) Enroll(ctx context.Context, request *agentv1.EnrollRequest, _ ...grpc.CallOption) (*agentv1.EnrollResponse, error) {
	return function(ctx, request)
}

type testIssuer struct {
	root       *x509.Certificate
	rootKey    ed25519.PrivateKey
	rootPEM    []byte
	serverCert tls.Certificate
	now        time.Time
}

func TestRunPersistsOwnerOnlyIdentityWithoutToken(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.NodeID == "" || result.ProtocolMajor != 1 || !validArtifactKeyID(result.ArtifactEncryptionKeyID) {
		t.Fatalf("Run() result = %#v", result)
	}
	assertMode(t, config.IdentityDir, 0o700)
	for _, path := range []string{result.IdentityFile, result.ClientCertificateFile, result.ClientPrivateKeyFile, result.ArtifactPrivateKeyFile, config.IdentityDir + lockSuffix} {
		assertMode(t, path, 0o600)
	}
	if exists(config.IdentityDir + pendingSuffix) {
		t.Fatal("successful enrollment left a pending directory")
	}
	assertNoToken(t, filepath.Dir(config.IdentityDir), testToken)
	if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("second Run() error = %v, want ErrAlreadyEnrolled", err)
	}
	assertPersistedMTLS(t, fixture, result)
}

func TestLoadIdentityAcceptsEnrolledIdentity(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := LoadIdentity(config.IdentityDir, fixture.now)
	if err != nil {
		t.Fatalf("LoadIdentity() error = %v", err)
	}
	if identity.NodeID != result.NodeID || identity.ArtifactEncryptionKeyID != result.ArtifactEncryptionKeyID || len(identity.ArtifactEncryptionPrivateKey) != 32 {
		t.Fatalf("LoadIdentity() = %+v", identity)
	}
}

func TestLoadIdentityRejectsUnsafeOrMismatchedMaterial(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *fixture, Result)
	}{
		{name: "weak directory mode", change: func(t *testing.T, fixture *fixture, _ Result) {
			if err := os.Chmod(filepath.Join(fixture.secureDir, "identity"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "node ID does not match SPIFFE URI", change: func(t *testing.T, _ *fixture, result Result) {
			mutateIdentityState(t, result.IdentityFile, func(state *identityState) { state.NodeID = uuid.NewString() })
		}},
		{name: "client certificate and key mismatch", change: func(t *testing.T, _ *fixture, result Result) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(result.ClientPrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "artifact key ID mismatch", change: func(t *testing.T, _ *fixture, result Result) {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(result.ArtifactPrivateKeyFile, key.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "expired certificate", change: func(t *testing.T, fixture *fixture, result Result) {
			replaceIdentityLeaf(t, fixture, result, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, fixture.now.Add(-time.Minute))
		}},
		{name: "certificate lacks client auth", change: func(t *testing.T, fixture *fixture, result Result) {
			replaceIdentityLeaf(t, fixture, result, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, fixture.now.Add(time.Hour))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			config := fixture.config(t)
			config.Dial = fixture.fakeDial(nil)
			result, err := Run(context.Background(), config, testToken)
			if err != nil {
				t.Fatal(err)
			}
			test.change(t, fixture, result)
			if _, err := LoadIdentity(config.IdentityDir, fixture.now); !errors.Is(err, ErrInvalidIdentity) {
				t.Fatalf("LoadIdentity() error = %v, want ErrInvalidIdentity", err)
			}
		})
	}
}

func TestLoadIdentityRejectsSymlinkDirectory(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	if _, err := Run(context.Background(), config, testToken); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(fixture.secureDir, "identity-link")
	if err := os.Symlink(config.IdentityDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(link, fixture.now); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("LoadIdentity() error = %v, want ErrInvalidIdentity", err)
	}
}

func TestRunRecoversUncertainRPCWithIdenticalRequest(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	var first *agentv1.EnrollRequest
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			first = proto.Clone(request).(*agentv1.EnrollRequest)
			return nil, errors.New("connection lost after commit")
		}), io.NopCloser(bytes.NewReader(nil)), nil
	}
	if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("first Run() error = %v", err)
	}
	if !exists(config.IdentityDir+pendingSuffix) || exists(config.IdentityDir) {
		t.Fatal("uncertain RPC did not retain only recoverable state")
	}
	assertNoToken(t, filepath.Dir(config.IdentityDir), testToken)
	var replay *agentv1.EnrollRequest
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			replay = proto.Clone(request).(*agentv1.EnrollRequest)
			return fixture.response(t, request), nil
		}), io.NopCloser(bytes.NewReader(nil)), nil
	}
	if _, err := Run(context.Background(), config, testToken); err != nil {
		t.Fatalf("recovery Run() error = %v", err)
	}
	first.Request.SentTime, replay.Request.SentTime = nil, nil
	if !proto.Equal(first, replay) {
		t.Fatal("recovery changed the idempotent enrollment request")
	}
}

func TestRunFencesConcurrentEnrollment(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			once.Do(func() { close(started) })
			<-release
			return fixture.response(t, request), nil
		}), io.NopCloser(bytes.NewReader(nil)), nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), config, testToken)
		done <- err
	}()
	<-started
	if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrEnrollmentBusy) {
		t.Fatalf("concurrent Run() error = %v, want ErrEnrollmentBusy", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
}

func TestRunNeverReplacesAnIdentityCreatedDuringEnrollment(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	marker := []byte("preexisting identity")
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			if err := os.Mkdir(config.IdentityDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(config.IdentityDir, "marker"), marker, 0o600); err != nil {
				t.Fatal(err)
			}
			return fixture.response(t, request), nil
		}), io.NopCloser(bytes.NewReader(nil)), nil
	}
	if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("Run() error = %v, want ErrAlreadyEnrolled", err)
	}
	content, err := os.ReadFile(filepath.Join(config.IdentityDir, "marker"))
	if err != nil || !bytes.Equal(content, marker) {
		t.Fatalf("preexisting identity was replaced: %q, %v", content, err)
	}
}

func TestRunRejectsInvalidResponsesAndLeavesRecoverableState(t *testing.T) {
	tests := []struct {
		name   string
		change func(*agentv1.EnrollResponse)
	}{
		{name: "node", change: func(value *agentv1.EnrollResponse) { value.NodeId = "not-a-uuid" }},
		{name: "protocol", change: func(value *agentv1.EnrollResponse) { value.SelectedProtocolVersion.Major = 2 }},
		{name: "artifact binding", change: func(value *agentv1.EnrollResponse) {
			value.ArtifactEncryptionKeyId = "x25519:" + strings.Repeat("0", 64)
		}},
		{name: "spiffe", change: func(value *agentv1.EnrollResponse) { value.NodeId = uuid.NewString() }},
		{name: "certificate metadata", change: func(value *agentv1.EnrollResponse) { value.Certificate.SerialNumber = "deadbeef" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			config := fixture.config(t)
			config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
				return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
					response := fixture.response(t, request)
					test.change(response)
					return response, nil
				}), io.NopCloser(bytes.NewReader(nil)), nil
			}
			if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Run() error = %v, want ErrInvalidResponse", err)
			}
			if exists(config.IdentityDir) || !exists(config.IdentityDir+pendingSuffix) {
				t.Fatal("invalid response committed an identity or lost recovery state")
			}
			assertNoToken(t, filepath.Dir(config.IdentityDir), testToken)
		})
	}
}

func TestRunNetworkAndPersistenceFailuresDoNotCommitIdentity(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return nil, nil, errors.New("offline")
	}
	if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("network Run() error = %v", err)
	}
	if exists(config.IdentityDir) {
		t.Fatal("network failure committed identity")
	}

	fixture = newFixture(t)
	config = fixture.config(t)
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			if err := os.Chmod(config.IdentityDir+pendingSuffix, 0o500); err != nil {
				t.Fatal(err)
			}
			return fixture.response(t, request), nil
		}), io.NopCloser(bytes.NewReader(nil)), nil
	}
	_, err := Run(context.Background(), config, testToken)
	_ = os.Chmod(config.IdentityDir+pendingSuffix, 0o700)
	if !errors.Is(err, ErrPersistence) {
		t.Fatalf("write failure Run() error = %v, want ErrPersistence", err)
	}
	if exists(config.IdentityDir) {
		t.Fatal("write failure committed identity")
	}
}

func TestTokenAndMachineIdentityInputsAreStrict(t *testing.T) {
	fixture := newFixture(t)
	tokenFile := filepath.Join(fixture.secureDir, "token")
	if err := os.WriteFile(tokenFile, append(bytes.Clone(testToken), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadTokenFile(tokenFile)
	if err != nil || !bytes.Equal(loaded, testToken) {
		t.Fatalf("ReadTokenFile() = %q, %v", loaded, err)
	}
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(tokenFile); err == nil {
		t.Fatal("ReadTokenFile() accepted group/world access")
	}
	if _, err := ReadToken(bytes.NewReader(append(bytes.Clone(testToken), []byte("\nextra")...))); err == nil {
		t.Fatal("ReadToken() accepted multiple lines")
	}
	fingerprint, err := MachineFingerprint(fixture.machineIDFile)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("cdnca-machine-fingerprint-v1\x00machine-identity"))
	if !bytes.Equal(fingerprint, want[:]) {
		t.Fatalf("machine fingerprint = %x", fingerprint)
	}
	link := filepath.Join(fixture.secureDir, "machine-link")
	if err := os.Symlink(fixture.machineIDFile, link); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineFingerprint(link); err == nil {
		t.Fatal("MachineFingerprint() followed a symlink")
	}
	if err := os.Chmod(fixture.secureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Run() with weak identity parent error = %v", err)
	}
}

func TestDialUsesTLS13ServerAuthentication(t *testing.T) {
	fixture := newFixture(t)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{fixture.serverCert},
	})))
	agentv1.RegisterAgentGatewayServiceServer(server, &testEnrollmentServer{issuer: fixture.testIssuer})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	config := fixture.config(t)
	config.Address = listener.Addr().String()
	config.ServerName = "gateway.test"
	if _, err := Run(context.Background(), config, testToken); err != nil {
		t.Fatalf("Run() through real TLS endpoint error = %v", err)
	}
	wrong := fixture.config(t)
	wrong.Address, wrong.ServerName = listener.Addr().String(), "wrong.test"
	wrong.IdentityDir = filepath.Join(fixture.secureDir, "wrong-identity")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := Run(ctx, wrong, testToken); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("wrong-name Run() error = %v", err)
	}
}

type testEnrollmentServer struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	issuer *testIssuer
}

func (server *testEnrollmentServer) Enroll(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	return server.issuer.response(nil, request), nil
}

type fixture struct {
	*testIssuer
	secureDir     string
	rootCAFile    string
	machineIDFile string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := secureTempDir(t)
	secureDir := filepath.Join(root, "security")
	if err := os.Mkdir(secureDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	_, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	serverCert := issueServerCertificate(t, rootCertificate, rootKey, now)
	rootCAFile := filepath.Join(secureDir, "root.pem")
	if err := os.WriteFile(rootCAFile, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	machineIDFile := filepath.Join(secureDir, "machine-id")
	if err := os.WriteFile(machineIDFile, []byte("machine-identity\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &fixture{
		testIssuer: &testIssuer{root: rootCertificate, rootKey: rootKey, rootPEM: rootPEM, serverCert: serverCert, now: now},
		secureDir:  secureDir, rootCAFile: rootCAFile, machineIDFile: machineIDFile,
	}
}

func (fixture *fixture) config(t *testing.T) Config {
	t.Helper()
	return Config{
		Address: "127.0.0.1:9443", ServerName: "gateway.test", RootCAFile: fixture.rootCAFile,
		IdentityDir: filepath.Join(fixture.secureDir, "identity"), MachineIDFile: fixture.machineIDFile,
		SupportedVersions: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1}, Maximum: &commonv1.ProtocolVersion{Major: 1},
		},
		Capabilities: &agentv1.AgentCapabilities{AgentVersion: "test", BuildId: "test", OperatingSystem: "linux", Architecture: "amd64"},
		Now:          func() time.Time { return fixture.now },
	}
}

func (issuer *testIssuer) fakeDial(change func(*agentv1.EnrollResponse)) func(context.Context, Config) (RPC, io.Closer, error) {
	return func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			response := issuer.response(nil, request)
			if change != nil {
				change(response)
			}
			return response, nil
		}), io.NopCloser(bytes.NewReader(nil)), nil
	}
}

func (issuer *testIssuer) response(t *testing.T, request *agentv1.EnrollRequest) *agentv1.EnrollResponse {
	if t != nil {
		t.Helper()
	}
	csr, err := x509.ParseCertificateRequest(request.CertificateSigningRequestDer)
	if err != nil {
		panic(err)
	}
	nodeID := "018f47a2-5b9c-7d31-8a60-104c9c0b717f"
	spiffe, _ := url.Parse(nodeSPIFFEPrefix + nodeID)
	notBefore, notAfter := issuer.now.Add(-time.Minute), issuer.now.Add(time.Hour)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42), NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{spiffe},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer.root, csr.PublicKey, issuer.rootKey)
	if err != nil {
		panic(err)
	}
	artifactDigest := sha256.Sum256(request.ArtifactEncryptionPublicKey)
	return &agentv1.EnrollResponse{
		NodeId: nodeID, SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1},
		ArtifactEncryptionKeyId: "x25519:" + hex.EncodeToString(artifactDigest[:]),
		Certificate: &agentv1.CertificateBundle{
			LeafCertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			IssuingChainPem:    [][]byte{bytes.Clone(issuer.rootPEM)}, SerialNumber: "2a",
			NotBeforeTime: timestamppb.New(notBefore), ExpirationTime: timestamppb.New(notAfter),
			RenewalTime: timestamppb.New(notAfter.Add(-15 * time.Minute)),
		},
	}
}

func issueServerCertificate(t *testing.T, root *x509.Certificate, rootKey ed25519.PrivateKey, now time.Time) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"gateway.test"}, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func assertPersistedMTLS(t *testing.T, fixture *fixture, result Result) {
	t.Helper()
	certificatePEM, err := os.ReadFile(result.ClientCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, err := os.ReadFile(result.ClientPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(fixture.root)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{fixture.serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		serverDone <- connection.(*tls.Conn).Handshake()
	}()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.root)
	connection, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "gateway.test", RootCAs: roots,
		Certificates: []tls.Certificate{clientPair},
	})
	if err != nil {
		t.Fatalf("persisted identity mTLS dial error = %v", err)
	}
	connection.Close()
	if err := <-serverDone; err != nil {
		t.Fatalf("persisted identity mTLS server error = %v", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), info.Mode().Perm(), want)
	}
}

func assertNoToken(t *testing.T, root string, token []byte) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, token) {
			return errors.New("token persisted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func mutateIdentityState(t *testing.T, path string, change func(*identityState)) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state identityState
	if err := json.Unmarshal(content, &state); err != nil {
		t.Fatal(err)
	}
	change(&state)
	content, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceIdentityLeaf(t *testing.T, fixture *fixture, result Result, usages []x509.ExtKeyUsage, notAfter time.Time) {
	t.Helper()
	privatePEM, err := os.ReadFile(result.ClientPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		t.Fatal("missing client private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("client private key is not Ed25519")
	}
	spiffe, err := url.Parse(nodeSPIFFEPrefix + result.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(77), NotBefore: fixture.now.Add(-2 * time.Hour), NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, URIs: []*url.URL{spiffe},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, fixture.root, privateKey.Public(), fixture.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), fixture.rootPEM...)
	if err := os.WriteFile(result.ClientCertificateFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestArtifactPrivateKeyIsIndependentFromMTLSKey(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	var request *agentv1.EnrollRequest
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, value *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			request = proto.Clone(value).(*agentv1.EnrollRequest)
			return fixture.response(t, value), nil
		}), io.NopCloser(bytes.NewReader(nil)), nil
	}
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := os.ReadFile(result.ArtifactPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	artifactKey, err := ecdh.X25519().NewPrivateKey(artifactBytes)
	if err != nil || !bytes.Equal(artifactKey.PublicKey().Bytes(), request.ArtifactEncryptionPublicKey) {
		t.Fatal("persisted X25519 key does not match enrollment binding")
	}
	privatePEM, _ := os.ReadFile(result.ClientPrivateKeyFile)
	block, _ := pem.Decode(privatePEM)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, sameType := parsed.(*ecdh.PrivateKey); sameType {
		t.Fatal("mTLS and artifact keys were not independent key types")
	}
}
