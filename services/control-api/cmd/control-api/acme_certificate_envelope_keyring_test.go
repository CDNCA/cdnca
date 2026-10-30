package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/google/uuid"
)

func TestACMECertificateEnvelopeKeyringReadsPreviousAndWritesActive(t *testing.T) {
	previousMaterial := bytes.Repeat([]byte{0x31}, 32)
	previous, err := newACMEPrivateKeyEnveloper("acme-kek-v1", previousMaterial)
	if err != nil {
		t.Fatal(err)
	}
	contextValue := certificateasset.PrivateKeyEnvelopeContext{
		TenantScopeID: uuid.New(), AssetID: uuid.New(), VersionID: uuid.New(), Version: 1,
		CertificateFingerprintSHA256: [32]byte{1}, CertificatePublicKeySHA256: [32]byte{2},
		PrivateKeyReference: "acme:keyring:test",
	}
	legacyEnvelope, err := previous.Seal(t.Context(), certificateasset.PrivateKeySealRequest{
		Context: contextValue, PlaintextPKCS8: []byte("legacy-private-key"),
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(acmePreviousWrappingKeyIDEnv, "acme-kek-v1")
	t.Setenv(acmePreviousWrappingKeyBase64Env, base64.StdEncoding.EncodeToString(previousMaterial))
	keyring, err := newConfiguredACMECertificateEnveloper(config.Config{
		ACMEWrappingKeyID: "acme-kek-v2", ACMEWrappingKey: bytes.Repeat([]byte{0x41}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := keyring.Unseal(t.Context(), certificateasset.PrivateKeyUnsealRequest{
		Context: contextValue, Envelope: legacyEnvelope,
	})
	if err != nil || string(plaintext) != "legacy-private-key" {
		t.Fatalf("previous Unseal() = (%q, %v)", plaintext, err)
	}
	clear(plaintext)

	activeEnvelope, err := keyring.Seal(t.Context(), certificateasset.PrivateKeySealRequest{
		Context: contextValue, PlaintextPKCS8: []byte("active-private-key"),
	})
	if err != nil || activeEnvelope.KeyID != "acme-kek-v2" {
		t.Fatalf("active Seal() key_id = %q, error = %v", activeEnvelope.KeyID, err)
	}
	unknown := legacyEnvelope
	unknown.KeyID = "acme-kek-unknown"
	if _, err := keyring.Unseal(t.Context(), certificateasset.PrivateKeyUnsealRequest{
		Context: contextValue, Envelope: unknown,
	}); !errors.Is(err, certificateasset.ErrEnvelopeUnavailable) {
		t.Fatalf("unknown key error = %v, want fail closed", err)
	}
}

func TestACMECertificateEnvelopeKeyringRejectsInvalidPreviousConfiguration(t *testing.T) {
	tests := []struct {
		name, keyID, encoded string
	}{
		{name: "missing material", keyID: "acme-kek-v1"},
		{name: "missing id", encoded: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))},
		{name: "duplicate id", keyID: "acme-kek-v2", encoded: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(acmePreviousWrappingKeyIDEnv, test.keyID)
			t.Setenv(acmePreviousWrappingKeyBase64Env, test.encoded)
			if _, err := newConfiguredACMECertificateEnveloper(config.Config{
				ACMEWrappingKeyID: "acme-kek-v2", ACMEWrappingKey: bytes.Repeat([]byte{0x41}, 32),
			}); err == nil {
				t.Fatal("invalid previous key configuration was accepted")
			}
		})
	}
}

func TestACMECertificateEnvelopeKeyringIsUsedByProductionRuntime(t *testing.T) {
	source, err := os.ReadFile("acme_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "enveloper, err := newConfiguredACMECertificateEnveloper(cfg)") {
		t.Fatal("ACME runtime does not construct the configured certificate envelope keyring")
	}
	if strings.Contains(text, "enveloper, err := newACMEPrivateKeyEnveloper(cfg.ACMEWrappingKeyID, cfg.ACMEWrappingKey)") {
		t.Fatal("ACME runtime still constructs an active-only certificate enveloper")
	}
}

func TestACMECertificateEnvelopeKeyringClearsTemporaryMaterial(t *testing.T) {
	source, err := os.ReadFile("acme_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("append([]byte(nil), cfg.ACMEWrappingKey...)"),
		[]byte("append([]byte(nil), previousSource[index].Key...)"),
		[]byte("clear(active.Material)"),
		[]byte("clear(previousSource[index].Key)"),
		[]byte("clear(previous[index].Material)"),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("certificate envelope keyring helper lacks material lifecycle %q", required)
		}
	}
}
