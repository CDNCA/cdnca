package gatewayclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// The artifact trust document may carry ECDSA P-256 anchors next to the
// Ed25519 release keys; the Ed25519-only consumers get the Ed25519 subset
// instead of failing on the mix.
func TestEd25519SubsetSkipsECDSAAnchors(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustStore(map[string]crypto.PublicKey{"release-ed25519": public, "publisher-p256": &ecdsaKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Ed25519Keys(); err == nil {
		t.Fatal("control: the strict accessor rejects a mixed store")
	}
	subset := store.Ed25519Subset()
	if len(subset) != 1 || !subset["release-ed25519"].Equal(public) {
		t.Fatalf("subset = %v", subset)
	}
	subset["release-ed25519"][0] ^= 1
	if again := store.Ed25519Subset(); !again["release-ed25519"].Equal(public) {
		t.Fatal("subset aliases the store")
	}
	if len((*TrustStore)(nil).Ed25519Subset()) != 0 {
		t.Fatal("nil store")
	}
}
