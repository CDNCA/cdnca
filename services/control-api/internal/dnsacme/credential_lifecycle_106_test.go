package dnsacme

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

func TestCredentialLifecycle106KeyRotationAndRevocationFence(t *testing.T) {
	old := CredentialKey{ID: "dns-kek-v1", Material: bytes.Repeat([]byte{1}, 32)}
	active := CredentialKey{ID: "dns-kek-v2", Material: bytes.Repeat([]byte{2}, 32)}
	legacy, err := NewAESGCMCredentialKeyring(old)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	keyID, envelope, err := legacy.Encrypt([]byte(`{"token":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewAESGCMCredentialKeyring(active, old)
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	if legacy.IdempotencyDigest([]byte("same-request")) != rotated.IdempotencyDigest([]byte("same-request")) {
		t.Fatal("credential digest changed across a complete rotation chain")
	}
	plaintext, err := rotated.Decrypt(keyID, envelope)
	if err != nil || string(plaintext) != `{"token":"secret"}` {
		t.Fatalf("old envelope decrypt=(%q,%v)", plaintext, err)
	}
	newID, newEnvelope, err := rotated.Encrypt([]byte("new-secret"))
	if err != nil || newID != active.ID {
		t.Fatalf("active envelope=(%q,%v)", newID, err)
	}
	if _, err := legacy.Decrypt(newID, newEnvelope); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("retired key accepted active envelope: %v", err)
	}
	if bytes.Contains(newEnvelope, []byte("new-secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	if len(newEnvelope) < 5 || string(newEnvelope[:4]) != credentialEnvelopeMagic ||
		newEnvelope[4] != credentialEnvelopeVersion {
		t.Fatalf("new envelope header=%x", newEnvelope)
	}
	legacyEnvelope := sealLegacyCredential106(t, old, []byte("legacy-secret"))
	legacyPlaintext, err := rotated.Decrypt(old.ID, legacyEnvelope)
	if err != nil || string(legacyPlaintext) != "legacy-secret" {
		t.Fatalf("legacy decrypt=(%q,%v)", legacyPlaintext, err)
	}
	for _, invalid := range [][]byte{
		nil,
		[]byte(credentialEnvelopeMagic),
		append([]byte(nil), newEnvelope[:len(newEnvelope)-1]...),
	} {
		if _, err := rotated.Decrypt(newID, invalid); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatalf("invalid envelope error=%v", err)
		}
	}
	tampered := append([]byte(nil), newEnvelope...)
	tampered[len(tampered)/2] ^= 0x80
	if _, err := rotated.Decrypt(newID, tampered); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("tampered envelope error=%v", err)
	}
}

func TestCredentialLifecycle106DigestAfterCloseIsZero(t *testing.T) {
	cipher, err := NewAESGCMCredentialCipher("dns-kek-v1", bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	before := cipher.IdempotencyDigest([]byte("secret"))
	if before == ([32]byte{}) {
		t.Fatal("active cipher returned zero digest")
	}
	if err := cipher.Close(); err != nil {
		t.Fatal(err)
	}
	if after := cipher.IdempotencyDigest([]byte("secret")); after != ([32]byte{}) {
		t.Fatalf("closed cipher digest=%x, want zero", after)
	}
}

func TestCredentialLifecycle106RollbackOnlyForDeterministicCredentialRejection(t *testing.T) {
	for _, err := range []error{
		ErrProviderCredentialsInvalid,
		ErrProviderTokenInactive,
		ErrProviderCredentialsRejected,
	} {
		if !credentialRollbackEligible(err) {
			t.Fatalf("deterministic rejection %v is not rollback eligible", err)
		}
	}
	for _, err := range []error{
		ErrProviderVerificationUnsupported,
		ErrProviderDisabled,
		ErrProviderVerificationRateLimited,
		ErrProviderVerificationUnavailable,
		ErrProviderVerificationTimeout,
	} {
		if credentialRollbackEligible(err) {
			t.Fatalf("non-credential or transient error %v is rollback eligible", err)
		}
	}
}

func sealLegacyCredential106(t *testing.T, key CredentialKey, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x44}, aead.NonceSize())
	return append(nonce, aead.Seal(nil, nonce, plaintext, []byte(key.ID))...)
}
