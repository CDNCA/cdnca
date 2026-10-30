package entitlement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"filippo.io/edwards25519"
)

func TestValidateEd25519PublicKeyRejectsNonCanonicalAndNonPrimeSubgroupPoints(t *testing.T) {
	valid, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEd25519PublicKey(valid); err != nil {
		t.Fatalf("generated key rejected: %v", err)
	}

	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	nonCanonicalIdentity := append(ed25519.PublicKey(nil), identity...)
	nonCanonicalIdentity[31] = 0x80
	orderTwo := bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)
	orderTwo[0], orderTwo[31] = 0xec, 0x7f
	orderFour := make(ed25519.PublicKey, ed25519.PublicKeySize)
	orderEight := mustPublicKeyHex(t, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
	torsion, err := new(edwards25519.Point).SetBytes(orderEight)
	if err != nil {
		t.Fatal(err)
	}
	basePlusTorsion := new(edwards25519.Point).Add(edwards25519.NewGeneratorPoint(), torsion).Bytes()

	for name, publicKey := range map[string]ed25519.PublicKey{
		"wrong length":      valid[:ed25519.PublicKeySize-1],
		"non canonical":     nonCanonicalIdentity,
		"identity":          identity,
		"order two":         orderTwo,
		"order four":        orderFour,
		"order eight":       orderEight,
		"base plus torsion": basePlusTorsion,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateEd25519PublicKey(publicKey); err == nil {
				t.Fatal("invalid public key accepted")
			}
		})
	}
}

func TestKeyRingAddRejectsInvalidPointWithoutChangingExistingKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	if err := ring.Add("stable-key", publicKey); err != nil {
		t.Fatal(err)
	}
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	if err := ring.Add("stable-key", identity); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("identity key error = %v", err)
	}
	if err := ring.Add("stable-key", publicKey); err != nil {
		t.Fatalf("failed Add changed existing key: %v", err)
	}
}

func mustPublicKeyHex(t *testing.T, value string) ed25519.PublicKey {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("decode public key %q: %v", value, err)
	}
	return ed25519.PublicKey(decoded)
}
