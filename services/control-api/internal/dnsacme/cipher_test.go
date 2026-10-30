package dnsacme

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestAESGCMCredentialCipherUsesRandomNonce(t *testing.T) {
	cipher, err := NewAESGCMCredentialCipher("dns-key-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("NewAESGCMCredentialCipher() error = %v", err)
	}
	plaintext := []byte(`{"token":"secret"}`)
	keyID1, first, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt(first) error = %v", err)
	}
	keyID2, second, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt(second) error = %v", err)
	}
	if keyID1 != "dns-key-v1" || keyID2 != keyID1 || bytes.Equal(first, second) {
		t.Fatalf("randomized ciphertext requirement failed: key IDs %q/%q equal=%t", keyID1, keyID2, bytes.Equal(first, second))
	}
	decrypted, err := cipher.Decrypt(keyID1, first)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt() = (%q, %v)", decrypted, err)
	}
	first[len(first)-1] ^= 1
	if _, err := cipher.Decrypt(keyID1, first); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("Decrypt(tampered) error = %v", err)
	}
	firstDigest := cipher.IdempotencyDigest(plaintext)
	secondDigest := cipher.IdempotencyDigest(plaintext)
	plainDigest := sha256.Sum256(plaintext)
	otherCipher, _ := NewAESGCMCredentialCipher("dns-key-v2", bytes.Repeat([]byte{8}, 32))
	if firstDigest != secondDigest || firstDigest == plainDigest || firstDigest == otherCipher.IdempotencyDigest(plaintext) {
		t.Fatal("credential idempotency digest is not stable, keyed, and distinct from raw SHA-256")
	}
}

func TestAESGCMCredentialCipherRejectsMissingKey(t *testing.T) {
	if _, err := NewAESGCMCredentialCipher("", make([]byte, 32)); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("missing key ID error = %v", err)
	}
	if _, err := NewAESGCMCredentialCipher("v1", make([]byte, 31)); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("short key error = %v", err)
	}
}

func TestAESGCMCredentialKeyringUsesActiveAndRetainsPreviousForDecryption(t *testing.T) {
	previous := CredentialKey{ID: "dns-key-v1", Material: bytes.Repeat([]byte{1}, 32)}
	active := CredentialKey{ID: "dns-key-v2", Material: bytes.Repeat([]byte{2}, 32)}

	oldCipher, err := NewAESGCMCredentialKeyring(previous)
	if err != nil {
		t.Fatal(err)
	}
	oldKeyID, oldCiphertext, err := oldCipher.Encrypt([]byte("old-secret"))
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := NewAESGCMCredentialKeyring(active, previous)
	if err != nil {
		t.Fatal(err)
	}
	newKeyID, newCiphertext, err := rotated.Encrypt([]byte("new-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if newKeyID != active.ID {
		t.Fatalf("new credential key ID = %q, want active %q", newKeyID, active.ID)
	}
	for _, test := range []struct {
		keyID      string
		ciphertext []byte
		want       string
	}{
		{keyID: oldKeyID, ciphertext: oldCiphertext, want: "old-secret"},
		{keyID: newKeyID, ciphertext: newCiphertext, want: "new-secret"},
	} {
		plaintext, decryptErr := rotated.Decrypt(test.keyID, test.ciphertext)
		if decryptErr != nil || string(plaintext) != test.want {
			t.Fatalf("Decrypt(%q) = (%q, %v), want %q", test.keyID, plaintext, decryptErr, test.want)
		}
	}
	if _, err := rotated.Decrypt("dns-key-unknown", oldCiphertext); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("unknown key ID error = %v", err)
	}
}
