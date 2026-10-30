package pluginwebhookcontrol

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type secretBytes interface {
	bytes() []byte
}

func TestSecretValueBytesUsesPointerReceiverAndReturnsCallerOwnedCopy(t *testing.T) {
	if _, ok := any(secretValue{}).(secretBytes); ok {
		t.Fatal("secretValue bytes method accepted a value receiver")
	}
	if _, ok := any(&secretValue{}).(secretBytes); !ok {
		t.Fatal("secretValue bytes method rejected a pointer receiver")
	}
	secret := secretValue{value: [32]byte{0x41, 0x42}}
	result := secret.bytes()
	defer clearBytes(result)
	if len(result) != len(secret.value) {
		t.Fatal("secretValue bytes result length changed")
	}
	result[0] ^= 0xff
	if secret.value[0] != 0x41 {
		t.Fatal("caller-owned result aliased the source secret")
	}
	secret.clear()
	if result[0] == 0 || result[1] != 0x42 {
		t.Fatal("caller-owned result was cleared with the source secret")
	}
}

func TestSecretCipherClearsPartialPlaintextOnFillFailure(t *testing.T) {
	keyring := fixedKeyring{active: WrappingKey{ID: "plugin-webhook-kek-v1", Key: [32]byte{1, 2, 3, 4}}}
	cipherSuite, err := newSecretCipher(keyring, func(target []byte) error {
		copy(target, bytes.Repeat([]byte{0x5a}, len(target)/2))
		return errors.New("simulated partial fill failure")
	})
	if err != nil {
		t.Fatal(err)
	}
	_, plaintext, err := cipherSuite.encryptSecret(t.Context(), uuid.New(), uuid.New(), uuid.New(), 1)
	if !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("partial fill error = %v", err)
	}
	if plaintext != (secretValue{}) {
		t.Fatal("partial fill failure retained plaintext")
	}
}

func TestRuntimeSecretProviderRejectsExpiredAndTamperedRecords(t *testing.T) {
	keyring := fixedKeyring{active: WrappingKey{ID: "plugin-webhook-kek-v1", Key: [32]byte{1, 2, 3, 4}}}
	cipherSuite, err := newSecretCipher(keyring, fixedBytes(0x42))
	if err != nil {
		t.Fatal(err)
	}
	target, subscription, secretID := uuid.New(), uuid.New(), uuid.New()
	encrypted, plaintext, err := cipherSuite.encryptSecret(t.Context(), target, subscription, secretID, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer plaintext.clear()
	record := runtimeSecretRecord{
		Status: "active", Fresh: true, Version: 1, WrappingKeyID: encrypted.WrappingKeyID,
		AADSHA256: encrypted.AADSHA256, Nonce: encrypted.Nonce, Ciphertext: encrypted.Ciphertext,
		SecretSHA256: encrypted.SecretSHA256,
	}
	provider := &RuntimeSecretProvider{cipher: cipherSuite}
	got, err := provider.decryptRecord(context.Background(), target, subscription, secretID, record)
	defer clearBytes(got)
	want := plaintext.bytes()
	defer clearBytes(want)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("valid record match = %t, error = %v", bytes.Equal(got, want), err)
	}

	invalid := []runtimeSecretRecord{record, record, record}
	invalid[0].Fresh = false
	invalid[1].Ciphertext = append([]byte(nil), record.Ciphertext...)
	invalid[1].Ciphertext[0] ^= 0xff
	invalid[2].AADSHA256 = append([]byte(nil), record.AADSHA256...)
	invalid[2].AADSHA256[0] ^= 0xff
	for index, candidate := range invalid {
		secret, err := provider.decryptRecord(context.Background(), target, subscription, secretID, candidate)
		returned := secret != nil
		clearBytes(secret)
		if returned || !errors.Is(err, ErrSecretUnavailable) {
			t.Fatalf("invalid record %d returned secret = %t, error = %v", index, returned, err)
		}
	}

	unavailable, err := newSecretCipher(fixedKeyring{active: WrappingKey{ID: "other", Key: [32]byte{9}}}, fixedBytes(0x11))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := (&RuntimeSecretProvider{cipher: unavailable}).decryptRecord(context.Background(), target, subscription, secretID, record)
	returned := secret != nil
	clearBytes(secret)
	if returned || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("unavailable key returned secret = %t, error = %v", returned, err)
	}
}
