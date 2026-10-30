package nodeca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
)

type managedTestKey struct {
	id  string
	key ed25519.PrivateKey
}

func (key managedTestKey) KeyID() string            { return key.id }
func (key managedTestKey) Public() crypto.PublicKey { return key.key.Public() }
func (key managedTestKey) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	return key.key.Sign(random, digest, options)
}

func TestManagedSignerUsesOpaqueKeyIdentityWithoutPrivateMaterial(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	issuer := newSelfSignedCA(t, privateKey, now.Add(-time.Hour), now.Add(24*time.Hour), nil)
	managed := managedTestKey{id: "hsm:node-ca:7", key: privateKey}

	signer, err := NewManagedSigner(managed, "hsm:node-ca:7", issuer, []*x509.Certificate{issuer})
	if err != nil {
		t.Fatalf("NewManagedSigner() error = %v", err)
	}
	nodeID := uuid.MustParse("6eec767a-d2ce-4aa5-9a13-803bf51f51e2")
	csr, _ := newCSR(t, "ed25519", nil)
	if _, err := signer.SignNodeCertificate(context.Background(), validRequest(now, nodeID, csr)); err != nil {
		t.Fatalf("SignNodeCertificate() error = %v", err)
	}
	if _, err := NewManagedSigner(managed, "hsm:node-ca:8", issuer, []*x509.Certificate{issuer}); err == nil {
		t.Fatal("mismatched managed key identity was accepted")
	}
}
