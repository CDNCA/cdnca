package originauthcontrol

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestCredentialAADRejectsRevisionSwap(t *testing.T) {
	keyring, err := newKeyring("active", map[string][]byte{
		"active": bytes.Repeat([]byte{0x61}, 32),
	}, bytes.NewReader(bytes.Repeat([]byte{0x62}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	credentialID := uuid.MustParse("018f9d7e-4a1b-7a2c-8d3e-222222222222")
	envelope, err := keyring.seal([]byte("revision-one"), credentialAAD(credentialID, 1, ProviderS3))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := keyring.open(envelope.keyID, envelope.ciphertext,
		credentialAAD(credentialID, 2, ProviderS3))
	clearBytes(plaintext)
	if !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("revision-swapped credential error = %v", err)
	}
}
