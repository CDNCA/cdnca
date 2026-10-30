package certificateasset

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPrivateKeyKeyringWritesActiveAndReadsLegacyPrevious(t *testing.T) {
	contextValue := keyringEnvelopeContext()
	previousKey := keyringMaterial(0x31)
	legacy := legacyPrivateKeyEnvelope(t, contextValue, "acme-kek-v1", previousKey, []byte("legacy-private-key"))
	keyring, err := NewAESGCMPrivateKeyEnvelopeKeyring(
		PrivateKeyWrappingKey{ID: "acme-kek-v2", Material: keyringMaterial(0x41)},
		PrivateKeyWrappingKey{ID: "acme-kek-v1", Material: previousKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: legacy})
	if err != nil || string(plaintext) != "legacy-private-key" {
		t.Fatalf("previous Unseal() = (%q,%v)", plaintext, err)
	}
	clear(plaintext)
	active, err := keyring.Seal(t.Context(), PrivateKeySealRequest{
		Context: contextValue, PlaintextPKCS8: []byte("active-private-key"),
	})
	if err != nil || active.KeyID != "acme-kek-v2" {
		t.Fatalf("active Seal() key ID = %q, error = %v", active.KeyID, err)
	}
	plaintext, err = keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: active})
	if err != nil || string(plaintext) != "active-private-key" {
		t.Fatalf("active Unseal() = (%q,%v)", plaintext, err)
	}
	clear(plaintext)
}

func TestPrivateKeyKeyringRewrapsPreviousToActive(t *testing.T) {
	contextValue := keyringEnvelopeContext()
	keyring, err := NewAESGCMPrivateKeyEnvelopeKeyring(
		PrivateKeyWrappingKey{ID: "acme-kek-v2", Material: keyringMaterial(0x41)},
		PrivateKeyWrappingKey{ID: "acme-kek-v1", Material: keyringMaterial(0x31)},
	)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyPrivateKeyEnvelope(t, contextValue, "acme-kek-v1", keyringMaterial(0x31), []byte("private-key"))
	rewrapped, err := keyring.Rewrap(t.Context(), PrivateKeyRewrapRequest{
		Context: contextValue, Envelope: legacy, TargetKeyID: "acme-kek-v2",
	})
	if err != nil || rewrapped.KeyID != "acme-kek-v2" || bytes.Equal(rewrapped.Ciphertext, legacy.Ciphertext) {
		t.Fatalf("Rewrap() key ID = %q, ciphertext changed = %t, error = %v",
			rewrapped.KeyID, !bytes.Equal(rewrapped.Ciphertext, legacy.Ciphertext), err)
	}
	plaintext, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: rewrapped})
	if err != nil || string(plaintext) != "private-key" {
		t.Fatalf("rewrapped Unseal() = (%q,%v)", plaintext, err)
	}
	clear(plaintext)
	if _, err := keyring.Rewrap(t.Context(), PrivateKeyRewrapRequest{
		Context: contextValue, Envelope: legacy, TargetKeyID: "acme-kek-v1",
	}); !errors.Is(err, ErrEnvelopeUnavailable) {
		t.Fatalf("rewrap to previous error = %v", err)
	}
}

func TestPrivateKeyKeyringFailsClosed(t *testing.T) {
	valid := PrivateKeyWrappingKey{ID: "acme-kek-v2", Material: keyringMaterial(0x41)}
	tests := []struct {
		name     string
		active   PrivateKeyWrappingKey
		previous []PrivateKeyWrappingKey
	}{
		{name: "missing active ID", active: PrivateKeyWrappingKey{Material: keyringMaterial(0x41)}},
		{name: "missing active material", active: PrivateKeyWrappingKey{ID: "acme-kek-v2"}},
		{name: "bad material length", active: PrivateKeyWrappingKey{ID: "acme-kek-v2", Material: []byte("short")}},
		{name: "missing previous ID", active: valid, previous: []PrivateKeyWrappingKey{{Material: keyringMaterial(0x31)}}},
		{name: "missing previous material", active: valid, previous: []PrivateKeyWrappingKey{{ID: "acme-kek-v1"}}},
		{name: "duplicate ID", active: valid, previous: []PrivateKeyWrappingKey{{ID: valid.ID, Material: keyringMaterial(0x31)}}},
		{name: "too many keys", active: valid, previous: []PrivateKeyWrappingKey{
			{ID: "previous-1", Material: keyringMaterial(1)}, {ID: "previous-2", Material: keyringMaterial(2)},
			{ID: "previous-3", Material: keyringMaterial(3)}, {ID: "previous-4", Material: keyringMaterial(4)},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAESGCMPrivateKeyEnvelopeKeyring(test.active, test.previous...)
			if !errors.Is(err, ErrEnvelopeUnavailable) ||
				test.active.ID != "" && strings.Contains(fmt.Sprint(err), test.active.ID) {
				t.Fatalf("unsafe constructor error = %v", err)
			}
		})
	}
	keyring, err := NewAESGCMPrivateKeyEnvelopeKeyring(valid)
	if err != nil {
		t.Fatal(err)
	}
	contextValue := keyringEnvelopeContext()
	envelope, err := keyring.Seal(t.Context(), PrivateKeySealRequest{Context: contextValue, PlaintextPKCS8: []byte("private-key")})
	if err != nil {
		t.Fatal(err)
	}
	unknown := envelope
	unknown.KeyID = "retired-key"
	if _, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: unknown}); !errors.Is(err, ErrEnvelopeUnavailable) {
		t.Fatalf("unknown key error = %v", err)
	}
	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xff
	if _, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: contextValue, Envelope: tampered}); !errors.Is(err, ErrEnvelopeUnavailable) {
		t.Fatalf("tampered ciphertext error = %v", err)
	}
	otherContext := contextValue
	otherContext.TenantScopeID = uuid.New()
	if _, err := keyring.Unseal(t.Context(), PrivateKeyUnsealRequest{Context: otherContext, Envelope: envelope}); !errors.Is(err, ErrEnvelopeUnavailable) {
		t.Fatalf("cross-tenant context error = %v", err)
	}
}

func TestPrivateKeyKeyringRedactsAndZeroizesTemporaryMaterial(t *testing.T) {
	keyring, err := NewAESGCMPrivateKeyEnvelopeKeyring(PrivateKeyWrappingKey{
		ID: "secret-active-id", Material: keyringMaterial(0x41),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{fmt.Sprint(keyring), fmt.Sprintf("%#v", keyring)} {
		if strings.Contains(rendered, "secret-active-id") || strings.Contains(rendered, "65 65 65") {
			t.Fatalf("rendered keyring leaked key material: %s", rendered)
		}
	}
	source, err := os.ReadFile("private_key_keyring.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"clear(material)", "clear(plaintext)"} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("keyring source lacks zeroization %q", required)
		}
	}
}

func keyringEnvelopeContext() PrivateKeyEnvelopeContext {
	return PrivateKeyEnvelopeContext{
		TenantScopeID: uuid.New(), AssetID: uuid.New(), VersionID: uuid.New(), Version: 1,
		CertificateFingerprintSHA256: sha256.Sum256([]byte("certificate")),
		CertificatePublicKeySHA256:   sha256.Sum256([]byte("public-key")),
		PrivateKeyReference:          "local:certificate-key",
	}
}

func legacyPrivateKeyEnvelope(t *testing.T, contextValue PrivateKeyEnvelopeContext, keyID string, key, plaintext []byte) PrivateKeyEnvelope {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	metadata := json.RawMessage(`{"schema":"cdnca.acme-certificate-envelope.v1","kind":"pkcs8"}`)
	aad, err := legacyPrivateKeyEnvelopeAAD(contextValue, keyID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x11}, aead.NonceSize())
	return PrivateKeyEnvelope{KeyID: keyID, Nonce: nonce, Metadata: metadata, Ciphertext: aead.Seal(nil, nonce, plaintext, aad)}
}

func legacyPrivateKeyEnvelopeAAD(contextValue PrivateKeyEnvelopeContext, keyID string, metadata json.RawMessage) ([]byte, error) {
	canonicalContext, err := contextValue.CanonicalAAD()
	if err != nil {
		return nil, err
	}
	metadataDigest := sha256.Sum256(metadata)
	return json.Marshal(struct {
		Schema         string          `json:"schema"`
		KeyID          string          `json:"key_id"`
		Context        json.RawMessage `json:"context"`
		MetadataSHA256 [32]byte        `json:"metadata_sha256"`
	}{Schema: "cdnca.acme-certificate-envelope-aad.v1", KeyID: keyID, Context: canonicalContext, MetadataSHA256: metadataDigest})
}

func keyringMaterial(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }
