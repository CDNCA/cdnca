package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type recoveryRPCFunc func(context.Context, *agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error)

func (function recoveryRPCFunc) RecoverCertificate(ctx context.Context, request *agentv1.RecoverCertificateRequest, _ ...grpc.CallOption) (*agentv1.RecoverCertificateResponse, error) {
	return function(ctx, request)
}

// Shared with control-api internal/nodeidentity recovery_test.go.
const recoveryMessageVector = "cdnca/node-certificate-recovery/v1\n" +
	"request_id=0192f0e0-0000-7000-8000-000000000001\n" +
	"sent_time=2026-10-21T08:00:00.5Z\n" +
	"node_id=0192f0e0-0000-7000-8000-0000000000aa\n" +
	"certificate_sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n" +
	"csr_sha256=cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34\n" +
	"nonce=0101010101010101010101010101010101010101010101010101010101010101"

func TestRecoveryMessageMatchesControlPlaneVector(t *testing.T) {
	nonce, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	got := RecoveryMessage("0192f0e0-0000-7000-8000-000000000001", time.Date(2026, 10, 21, 8, 0, 0, 5e8, time.UTC),
		"0192f0e0-0000-7000-8000-0000000000aa", []byte("abc"), []byte("def"), nonce)
	if string(got) != recoveryMessageVector {
		t.Fatalf("RecoveryMessage =\n%s", got)
	}
}

// GW-02: before the fix an agent with an expired certificate could not even
// load its identity ("load enrollment identity"), so it never started.
func TestLoadIdentityAllowingExpiredCertificate(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	expiredAt := fixture.now.Add(2 * time.Hour)
	if _, err := LoadIdentity(config.IdentityDir, expiredAt); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("LoadIdentity(expired) = %v, want ErrInvalidIdentity", err)
	}
	identity, err := LoadIdentityAllowingExpired(config.IdentityDir, expiredAt)
	if err != nil || !identity.CertificateExpired || identity.NodeID != result.NodeID {
		t.Fatalf("LoadIdentityAllowingExpired(expired) = %+v, %v", identity, err)
	}
	if identity, err := LoadIdentityAllowingExpired(config.IdentityDir, fixture.now); err != nil || identity.CertificateExpired {
		t.Fatalf("LoadIdentityAllowingExpired(valid) = %+v, %v", identity, err)
	}
	// An expired leaf with the wrong usage is still refused: the other checks stay on.
	replaceIdentityLeaf(t, fixture, result, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, fixture.now.Add(time.Hour))
	if _, err := LoadIdentityAllowingExpired(config.IdentityDir, expiredAt); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("LoadIdentityAllowingExpired(wrong usage) = %v", err)
	}
}

func recoveredResponse(t *testing.T, fixture *fixture, nodeID string, request *agentv1.RecoverCertificateRequest, now time.Time) *agentv1.RecoverCertificateResponse {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(request.GetCertificateSigningRequestDer())
	if err != nil || csr.CheckSignature() != nil {
		t.Fatal("invalid recovery CSR")
	}
	spiffe, _ := url.Parse(nodeSPIFFEPrefix + nodeID)
	notBefore, notAfter := now.Add(-time.Minute), now.Add(10*time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(99), NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{spiffe},
	}, fixture.root, csr.PublicKey, fixture.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.RecoverCertificateResponse{Certificate: &agentv1.CertificateBundle{
		LeafCertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		IssuingChainPem:    [][]byte{bytes.Clone(fixture.rootPEM)}, SerialNumber: "63",
		NotBeforeTime: timestamppb.New(notBefore), ExpirationTime: timestamppb.New(notAfter),
		RenewalTime: timestamppb.New(now.Add(5 * time.Hour)),
	}}
}

func TestRecovererReplacesExpiredCertificateWithSameKey(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now.Add(30 * time.Minute)
	var requests []*agentv1.RecoverCertificateRequest
	var reply func(*agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error)
	recoverer, err := NewRecoverer(RecoverConfig{IdentityDir: config.IdentityDir, Now: func() time.Time { return now },
		Dial: func(context.Context) (RecoveryRPC, io.Closer, error) {
			return recoveryRPCFunc(func(_ context.Context, request *agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error) {
				requests = append(requests, proto.Clone(request).(*agentv1.RecoverCertificateRequest))
				return reply(request)
			}), io.NopCloser(bytes.NewReader(nil)), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if recoverer.RecoveryDue() {
		t.Fatal("RecoveryDue() with a valid certificate")
	}
	if recovered, _, err := recoverer.Recover(context.Background()); recovered || err != nil || len(requests) != 0 {
		t.Fatalf("Recover(valid) = %v, %v, %d calls", recovered, err, len(requests))
	}

	now = fixture.now.Add(2 * time.Hour)
	if !recoverer.RecoveryDue() {
		t.Fatal("RecoveryDue() after expiry = false")
	}
	reply = func(*agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error) {
		return nil, status.Error(codes.Unavailable, "gateway down")
	}
	if recovered, _, err := recoverer.Recover(context.Background()); recovered || !errors.Is(err, ErrRecoveryUnavailable) {
		t.Fatalf("Recover(unavailable) = %v, %v", recovered, err)
	}
	// Backoff: no call before 30 seconds.
	now = now.Add(29 * time.Second)
	if recovered, _, err := recoverer.Recover(context.Background()); recovered || err != nil || len(requests) != 1 {
		t.Fatalf("Recover(backing off) = %v, %v, %d calls", recovered, err, len(requests))
	}
	now = now.Add(2 * time.Second)
	reply = func(request *agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error) {
		return recoveredResponse(t, fixture, result.NodeID, request, now), nil
	}
	recovered, certificateSHA, err := recoverer.Recover(context.Background())
	if err != nil || !recovered || len(certificateSHA) != 64 {
		t.Fatalf("Recover() = %v, %q, %v", recovered, certificateSHA, err)
	}
	first, second := requests[0], requests[1]
	if first.GetRequest().GetRequestId() != second.GetRequest().GetRequestId() || !bytes.Equal(first.GetNonce(), second.GetNonce()) ||
		!bytes.Equal(first.GetSignature(), second.GetSignature()) {
		t.Fatal("retried recovery changed its persisted request")
	}
	expired, err := x509.ParseCertificate(first.GetExpiredCertificateDer())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(first.GetCertificateSigningRequestDer())
	if err != nil || !bytes.Equal(csr.PublicKey.(ed25519.PublicKey), expired.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("recovery CSR does not carry the expired certificate's key")
	}
	message := RecoveryMessage(first.GetRequest().GetRequestId(), first.GetRequest().GetSentTime().AsTime(), result.NodeID,
		first.GetExpiredCertificateDer(), first.GetCertificateSigningRequestDer(), first.GetNonce())
	if !ed25519.Verify(expired.PublicKey.(ed25519.PublicKey), message, first.GetSignature()) {
		t.Fatal("recovery signature does not verify with the certificate key")
	}
	if exists(filepath.Join(config.IdentityDir, recoveryStateFileName)) {
		t.Fatal("successful recovery left its request state")
	}
	identity, err := LoadIdentity(config.IdentityDir, now)
	if err != nil || identity.NodeID != result.NodeID || identity.CertificateExpired {
		t.Fatalf("recovered identity = %+v, %v", identity, err)
	}
	if recoverer.RecoveryDue() {
		t.Fatal("RecoveryDue() after recovery")
	}
}

func TestRecovererRefusedLeavesCertificate(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Dial = fixture.fakeDial(nil)
	result, err := Run(context.Background(), config, testToken)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(result.ClientCertificateFile)
	now := fixture.now.Add(2 * time.Hour)
	recoverer, err := NewRecoverer(RecoverConfig{IdentityDir: config.IdentityDir, Now: func() time.Time { return now },
		Dial: func(context.Context) (RecoveryRPC, io.Closer, error) {
			return recoveryRPCFunc(func(context.Context, *agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error) {
				return nil, status.Error(codes.PermissionDenied, "node certificate recovery is not authorized")
			}), io.NopCloser(bytes.NewReader(nil)), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if recovered, _, err := recoverer.Recover(context.Background()); recovered || !errors.Is(err, ErrRecoveryRefused) {
		t.Fatalf("Recover(refused) = %v, %v", recovered, err)
	}
	after, _ := os.ReadFile(result.ClientCertificateFile)
	if !bytes.Equal(before, after) {
		t.Fatal("refused recovery replaced the certificate")
	}
}
