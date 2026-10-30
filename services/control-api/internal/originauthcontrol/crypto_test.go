package originauthcontrol

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestKeyringRotationTamperAndUnknownKeyFailClosed(t *testing.T) {
	keys := map[string][]byte{
		"old": bytes.Repeat([]byte{0x11}, 32),
		"new": bytes.Repeat([]byte{0x22}, 32),
	}
	oldRing, err := newKeyring("old", keys, bytes.NewReader(bytes.Repeat([]byte{0x31}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	credentialID := uuid.MustParse("018f9d7e-4a1b-7a2c-8d3e-111111111111")
	aad := credentialAAD(credentialID, 1, ProviderS3)
	oldEnvelope, err := oldRing.seal([]byte("old-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	newRing, err := newKeyring("new", keys, bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := newRing.open(oldEnvelope.keyID, oldEnvelope.ciphertext, aad)
	if err != nil || string(plaintext) != "old-secret" {
		t.Fatalf("old envelope after rotation = %q, %v", plaintext, err)
	}
	newEnvelope, err := newRing.seal([]byte("new-secret"), aad)
	if err != nil || newEnvelope.keyID != "new" {
		t.Fatalf("new envelope key = %q, %v", newEnvelope.keyID, err)
	}
	tampered := append([]byte(nil), newEnvelope.ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := newRing.open("new", tampered, aad); !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("tampered ciphertext error = %v", err)
	}
	if _, err := newRing.open("missing", newEnvelope.ciphertext, aad); !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("unknown key error = %v", err)
	}
	otherAAD := credentialAAD(uuid.New(), 1, ProviderS3)
	if _, err := newRing.open("new", newEnvelope.ciphertext, otherAAD); !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("swapped credential AAD error = %v", err)
	}
}

func TestKeyringRequiresAES256AndActiveKey(t *testing.T) {
	for name, test := range map[string]struct {
		active string
		keys   map[string][]byte
	}{
		"missing active": {active: "new", keys: map[string][]byte{"old": bytes.Repeat([]byte{1}, 32)}},
		"short key":      {active: "new", keys: map[string][]byte{"new": bytes.Repeat([]byte{1}, 31)}},
		"unsafe key ID":  {active: "new key", keys: map[string][]byte{"new key": bytes.Repeat([]byte{1}, 32)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewKeyring(test.active, test.keys); !errors.Is(err, ErrEncryptionUnavailable) {
				t.Fatalf("NewKeyring() error = %v", err)
			}
		})
	}
}
