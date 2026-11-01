package entitlement

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// KeyRing.VerifyDetached lets consumers outside control-api
// check ipintel releases with the license key ring they already load.
func TestKeyRingVerifyDetached(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	ring := NewKeyRing()
	if err := ring.Add("license-k1", private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"revision":1}`)
	signature := ed25519.Sign(private, payload)
	now := time.Unix(1_800_000_000, 0)
	if err := ring.VerifyDetached("license-k1", payload, signature, now, now); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	if err := ring.VerifyDetached("other", payload, signature, now, now); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	if err := ring.VerifyDetached("license-k1", []byte(`{"revision":2}`), signature, now, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered payload: %v", err)
	}
	if err := ring.VerifyDetached("license-k1", payload, signature[:10], now, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("short signature: %v", err)
	}
	var empty *KeyRing
	if err := empty.VerifyDetached("license-k1", payload, signature, now, now); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("nil ring: %v", err)
	}
}
