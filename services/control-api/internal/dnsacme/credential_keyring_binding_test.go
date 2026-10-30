package dnsacme

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCredentialKeyringBindsEnvelopeAndBoundsRotation(t *testing.T) {
	previous := CredentialKey{ID: "dns-key-v1", Material: bytes.Repeat([]byte{1}, 32)}
	active := CredentialKey{ID: "dns-key-v2", Material: bytes.Repeat([]byte{2}, 32)}
	binding := CredentialBinding{
		TenantID: uuid.New(), ScopeID: uuid.New(), ProviderID: uuid.New(),
	}
	plaintext := []byte(`{"api_token":"credential-secret"}`)

	oldCipher, err := NewAESGCMCredentialKeyring(previous)
	if err != nil {
		t.Fatal(err)
	}
	oldKeyID, oldEnvelope, err := oldCipher.EncryptCredential(binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := NewAESGCMCredentialKeyring(active, previous)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := rotated.DecryptCredential(binding, oldKeyID, oldEnvelope)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("previous bound decrypt = (%q, %v)", decrypted, err)
	}
	clear(decrypted)

	newKeyID, newEnvelope, err := rotated.EncryptCredential(binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if newKeyID != active.ID {
		t.Fatalf("new key ID = %q, want %q", newKeyID, active.ID)
	}

	wrongBindings := []CredentialBinding{
		{TenantID: uuid.New(), ScopeID: binding.ScopeID, ProviderID: binding.ProviderID},
		{TenantID: binding.TenantID, ScopeID: uuid.New(), ProviderID: binding.ProviderID},
		{TenantID: binding.TenantID, ScopeID: binding.ScopeID, ProviderID: uuid.New()},
	}
	for _, wrong := range wrongBindings {
		if _, err := rotated.DecryptCredential(wrong, newKeyID, newEnvelope); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatalf("cross-authority decrypt error = %v", err)
		}
	}
	if _, err := rotated.DecryptCredential(binding, previous.ID, newEnvelope); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("external/embedded key mismatch error = %v", err)
	}
	retired, err := NewAESGCMCredentialKeyring(active)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retired.DecryptCredential(binding, previous.ID, oldEnvelope); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("retired key error = %v", err)
	}

	tampered := append([]byte(nil), newEnvelope...)
	tampered[len(tampered)-1] ^= 1
	_, err = rotated.DecryptCredential(binding, newKeyID, tampered)
	if !errors.Is(err, ErrCredentialUnavailable) || strings.Contains(err.Error(), active.ID) || strings.Contains(err.Error(), "credential-secret") {
		t.Fatalf("tamper error leaked detail: %v", err)
	}

	if _, err := NewAESGCMCredentialKeyring(active, previous, CredentialKey{
		ID: "dns-key-v0", Material: bytes.Repeat([]byte{3}, 32),
	}); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("unbounded previous keys error = %v", err)
	}
}

func TestCredentialLegacyEnvelopeRequiresExplicitRewrap(t *testing.T) {
	previous := CredentialKey{ID: "dns-key-v1", Material: bytes.Repeat([]byte{1}, 32)}
	active := CredentialKey{ID: "dns-key-v2", Material: bytes.Repeat([]byte{2}, 32)}
	binding := CredentialBinding{
		TenantID: uuid.New(), ScopeID: uuid.New(), ProviderID: uuid.New(),
	}
	legacy, err := NewAESGCMCredentialKeyring(previous)
	if err != nil {
		t.Fatal(err)
	}
	keyID, legacyEnvelope, err := legacy.Encrypt([]byte("legacy-secret"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewAESGCMCredentialKeyring(active, previous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.DecryptCredential(binding, keyID, legacyEnvelope); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("ordinary bound decrypt accepted legacy envelope: %v", err)
	}

	newKeyID, rebound, err := rotated.RewrapCredential(binding, keyID, legacyEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if newKeyID != active.ID {
		t.Fatalf("rewrap key ID = %q, want %q", newKeyID, active.ID)
	}
	plaintext, err := rotated.DecryptCredential(binding, newKeyID, rebound)
	if err != nil || string(plaintext) != "legacy-secret" {
		t.Fatalf("rewrapped decrypt = (%q, %v)", plaintext, err)
	}
}
