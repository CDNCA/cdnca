package entitlementguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestApplyVerifiedKeysRejectsInvalidPointWithoutChangingTrust(t *testing.T) {
	root, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	previous, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustStore([]VerificationKey{{KeyID: "root", PublicKey: root}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyVerifiedKeys([]VerificationKey{
		{KeyID: "root", PublicKey: root},
		{KeyID: "previous", PublicKey: previous},
	}); err != nil {
		t.Fatal(err)
	}
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	if err := store.ApplyVerifiedKeys([]VerificationKey{
		{KeyID: "root", PublicKey: root},
		{KeyID: "candidate", PublicKey: identity},
	}); !errors.Is(err, ErrInvalidTrustStore) {
		t.Fatalf("invalid ApplyVerifiedKeys error = %v", err)
	}
	got, found := store.PublicKey("previous")
	if !found || !bytes.Equal(got, previous) {
		t.Fatal("failed ApplyVerifiedKeys changed existing trust")
	}
	if _, found := store.PublicKey("candidate"); found {
		t.Fatal("failed ApplyVerifiedKeys installed candidate")
	}
}
