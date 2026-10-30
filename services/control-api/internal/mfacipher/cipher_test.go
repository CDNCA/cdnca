package mfacipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestCipherRoundTripUsesVersionedEnvelopeAndRandomNonce(t *testing.T) {
	cipher, err := New(testKey("mfa-kek-v1", 0x11))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = cipher.Close() })

	plaintext := []byte("totp-secret")
	keyID, first, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	_, second, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}
	if keyID != "mfa-kek-v1" {
		t.Fatalf("key ID = %q, want mfa-kek-v1", keyID)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two envelopes are equal; nonce was not random")
	}
	headerSize, embeddedKeyID, ok := parseHeader(first)
	if !ok || headerSize != fixedHeaderSize+len(keyID) || string(embeddedKeyID) != keyID {
		t.Fatalf("envelope header = size:%d key:%q valid:%t", headerSize, embeddedKeyID, ok)
	}
	if !bytes.Equal(first[:4], []byte(envelopeMagic)) || first[4] != Version || first[5] != algorithmAES256GCM {
		t.Fatalf("envelope prefix = %x", first[:fixedHeaderSize])
	}

	decrypted, err := cipher.Decrypt(keyID, first)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestCipherRotationDecryptsPreviousAndEncryptsActive(t *testing.T) {
	oldInput := testKey("mfa-kek-v1", 0x21)
	oldCipher, err := New(oldInput)
	if err != nil {
		t.Fatalf("New(old) error = %v", err)
	}
	t.Cleanup(func() { _ = oldCipher.Close() })
	oldID, oldEnvelope, err := oldCipher.Encrypt([]byte("old-secret"))
	if err != nil {
		t.Fatalf("old Encrypt() error = %v", err)
	}

	newInput := testKey("mfa-kek-v2", 0x22)
	rotated, err := New(newInput, oldInput)
	if err != nil {
		t.Fatalf("New(rotated) error = %v", err)
	}
	t.Cleanup(func() { _ = rotated.Close() })
	clear(oldInput.Material)
	clear(newInput.Material)

	plaintext, err := rotated.Decrypt(oldID, oldEnvelope)
	if err != nil || string(plaintext) != "old-secret" {
		t.Fatalf("Decrypt(previous) = %q, %v", plaintext, err)
	}
	newID, newEnvelope, err := rotated.Encrypt([]byte("new-secret"))
	if err != nil || newID != "mfa-kek-v2" {
		t.Fatalf("Encrypt(active) = %q, %v", newID, err)
	}
	plaintext, err = rotated.Decrypt(newID, newEnvelope)
	if err != nil || string(plaintext) != "new-secret" {
		t.Fatalf("Decrypt(active) = %q, %v", plaintext, err)
	}
	if _, err := oldCipher.Decrypt(newID, newEnvelope); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("old Decrypt(new) error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestCipherRejectsUnknownKeyTamperingAndAADMismatch(t *testing.T) {
	cipher, err := New(testKey("mfa-kek-v2", 0x32), testKey("mfa-kek-v1", 0x31))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = cipher.Close() })
	keyID, envelope, err := cipher.Encrypt([]byte("secret-value"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	unknown := append([]byte(nil), envelope...)
	copy(unknown[fixedHeaderSize:], "mfa-kek-v9")
	if _, err := cipher.Decrypt("mfa-kek-v9", unknown); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("unknown key error = %v, want ErrInvalidEnvelope", err)
	}

	replaced := append([]byte(nil), envelope...)
	copy(replaced[fixedHeaderSize:], "mfa-kek-v1")
	if _, err := cipher.Decrypt("mfa-kek-v1", replaced); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("replaced key error = %v, want ErrInvalidEnvelope", err)
	}

	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 0x80
	if _, err := cipher.Decrypt(keyID, tampered); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("tamper error = %v, want ErrInvalidEnvelope", err)
	}

	wrongAAD := sealWithAAD(t, testKey(keyID, 0x32), []byte("secret-value"), "wrong-domain")
	if _, err := cipher.Decrypt(keyID, wrongAAD); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("wrong AAD error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestNewRejectsInvalidKeys(t *testing.T) {
	valid := testKey("active", 0x41)
	tests := []struct {
		name     string
		active   Key
		previous []Key
	}{
		{name: "empty active ID", active: Key{Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "oversized active ID", active: Key{ID: strings.Repeat("a", maxKeyIDSize+1), Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "space in active ID", active: Key{ID: "active key", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "unicode active ID", active: Key{ID: "active-\xc3\xa9", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "invalid separator", active: Key{ID: "active@key", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "leading dot", active: Key{ID: ".active", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "leading underscore", active: Key{ID: "_active", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "leading colon", active: Key{ID: ":active", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "leading slash", active: Key{ID: "/active", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "leading hyphen", active: Key{ID: "-active", Material: bytes.Repeat([]byte{1}, 32)}},
		{name: "empty active key", active: Key{ID: "active"}},
		{name: "short active key", active: Key{ID: "active", Material: bytes.Repeat([]byte{1}, 31)}},
		{name: "long active key", active: Key{ID: "active", Material: bytes.Repeat([]byte{1}, 33)}},
		{name: "empty previous ID", active: valid, previous: []Key{{Material: bytes.Repeat([]byte{2}, 32)}}},
		{name: "short previous key", active: valid, previous: []Key{{ID: "previous", Material: bytes.Repeat([]byte{2}, 31)}}},
		{name: "duplicate active", active: valid, previous: []Key{valid}},
		{name: "duplicate previous", active: valid, previous: []Key{testKey("previous", 2), testKey("previous", 3)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if cipher, err := New(test.active, test.previous...); !errors.Is(err, ErrInvalidConfig) || cipher != nil {
				t.Fatalf("New() = %#v, %v; want nil, ErrInvalidConfig", cipher, err)
			}
		})
	}
}

func TestCipherCopiesAndZeroesKeyMaterial(t *testing.T) {
	active := testKey("active", 0x51)
	previous := testKey("previous", 0x52)
	cipher, err := New(active, previous)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activeCopy := cipher.keys[active.ID]
	previousCopy := cipher.keys[previous.ID]
	if &active.Material[0] == &activeCopy[0] || &previous.Material[0] == &previousCopy[0] {
		t.Fatal("cipher retained caller-owned key storage")
	}
	clear(active.Material)
	clear(previous.Material)

	keyID, envelope, err := cipher.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt() after caller zeroization error = %v", err)
	}
	if plaintext, err := cipher.Decrypt(keyID, envelope); err != nil || string(plaintext) != "secret" {
		t.Fatalf("Decrypt() after caller zeroization = %q, %v", plaintext, err)
	}

	if err := cipher.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !allZero(activeCopy) || !allZero(previousCopy) {
		t.Fatal("Close() did not zero retained key material")
	}
	if cipher.keys != nil || cipher.activeID != "" || !cipher.closed {
		t.Fatalf("closed cipher retained state: %#v", cipher)
	}
	if err := cipher.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, _, err := cipher.Encrypt([]byte("secret")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Encrypt() after Close error = %v, want ErrUnavailable", err)
	}
	if _, err := cipher.Decrypt(keyID, envelope); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Decrypt() after Close error = %v, want ErrUnavailable", err)
	}
}

func TestCipherRejectsMalformedEnvelopeWithoutLeakingInputs(t *testing.T) {
	cipher, err := New(testKey("active", 0x61))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = cipher.Close() })
	secretKeyID := "not-configured-secret-key-id"
	malformed := [][]byte{
		nil,
		[]byte("MFAE"),
		append([]byte("BAD!"), 1, 1, 0, 1, 'x'),
		append([]byte("MFAE"), 2, 1, 0, 1, 'x'),
		append([]byte("MFAE"), 1, 2, 0, 1, 'x'),
		append([]byte("MFAE"), 1, 1, 0, 0),
		append([]byte("MFAE"), 1, 1, 0, 2, 'x'),
	}
	for _, envelope := range malformed {
		_, err := cipher.Decrypt(secretKeyID, envelope)
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("Decrypt(%x) error = %v, want ErrInvalidEnvelope", envelope, err)
		}
		message := err.Error()
		if strings.Contains(message, secretKeyID) || (len(envelope) > 0 && strings.Contains(message, string(envelope))) {
			t.Fatalf("error leaked input: %q", message)
		}
	}
}

func TestCipherConcurrentUseAndClose(t *testing.T) {
	cipher, err := New(testKey("active", 0x71))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	keyID, envelope, err := cipher.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				_, _, encryptErr := cipher.Encrypt([]byte("secret"))
				if encryptErr != nil && !errors.Is(encryptErr, ErrUnavailable) {
					t.Errorf("Encrypt() error = %v", encryptErr)
				}
				_, decryptErr := cipher.Decrypt(keyID, envelope)
				if decryptErr != nil && !errors.Is(decryptErr, ErrUnavailable) {
					t.Errorf("Decrypt() error = %v", decryptErr)
				}
			}
		}()
	}
	if err := cipher.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	workers.Wait()
}

func testKey(id string, fill byte) Key {
	return Key{ID: id, Material: bytes.Repeat([]byte{fill}, 32)}
}

func sealWithAAD(t *testing.T, key Key, plaintext []byte, domain string) []byte {
	t.Helper()
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	header := makeHeader(key.ID)
	nonce := bytes.Repeat([]byte{0x5a}, aead.NonceSize())
	aad := append([]byte(domain), header...)
	envelope := append(append([]byte(nil), header...), nonce...)
	return aead.Seal(envelope, nonce, plaintext, aad)
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
