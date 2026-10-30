package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestAuthenticatedNodeUsesCanonicalHexCertificateSerial(t *testing.T) {
	serial, ok := new(big.Int).SetString("0000ABCDEF0123456789ABCDEF0123456789", 16)
	if !ok {
		t.Fatal("invalid serial fixture")
	}
	leaf, root := issueNodeIdentityLeaf(t, serial)
	identity, err := authenticatedNode(verifiedNodeContext(leaf, root))
	if err != nil {
		t.Fatal(err)
	}
	const wantSerial = "abcdef0123456789abcdef0123456789"
	if serial.String() == wantSerial {
		t.Fatal("serial fixture does not distinguish decimal and hexadecimal encodings")
	}
	if identity.NodeID != testNodeID || identity.SerialNumber != wantSerial {
		t.Fatalf("authenticated identity = %+v, want node %q serial %q", identity, testNodeID, wantSerial)
	}
	wantDigest := sha256.Sum256(leaf.Raw)
	if identity.CertificateSHA256 != wantDigest {
		t.Fatalf("authenticated certificate digest = %x, want %x", identity.CertificateSHA256, wantDigest)
	}
}

func TestAuthenticatedNodeRejectsNonPositiveCertificateSerial(t *testing.T) {
	leaf, root := issueNodeIdentityLeaf(t, big.NewInt(1))
	for _, test := range []struct {
		name   string
		serial *big.Int
	}{
		{name: "missing", serial: nil},
		{name: "zero", serial: big.NewInt(0)},
		{name: "negative", serial: big.NewInt(-1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalidLeaf := *leaf
			invalidLeaf.SerialNumber = test.serial
			_, err := authenticatedNode(verifiedNodeContext(&invalidLeaf, root))
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("authenticatedNode error = %v, want Unauthenticated", err)
			}
		})
	}
}

func TestAuthenticatedNodeRequiresVerifiedCertificateChain(t *testing.T) {
	leaf, _ := issueNodeIdentityLeaf(t, big.NewInt(1))
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}},
	}})
	_, err := authenticatedNode(ctx)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("authenticatedNode error = %v, want Unauthenticated", err)
	}
}

func issueNodeIdentityLeaf(t *testing.T, serial *big.Int) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	pki := newTestPKI(t)
	key := newECDSAKey(t)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).Set(serial),
		Subject:      pkix.Name{CommonName: testNodeID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{mustParseURL(t, nodeSPIFFEPrefix+testNodeID)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.caCertificate, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, pki.caCertificate
}

func verifiedNodeContext(leaf, root *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, root}}},
	}})
}
