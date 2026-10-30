package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

func TestNewConfiguredDNSCredentialCipherRotation(t *testing.T) {
	activeMaterial := bytes.Repeat([]byte{0x41}, 32)
	previousMaterial := bytes.Repeat([]byte{0x31}, 32)
	previous, err := dnsacme.NewAESGCMCredentialCipher("dns-key-v1", previousMaterial)
	if err != nil {
		t.Fatal(err)
	}
	defer previous.Close()
	previousKeyID, previousEnvelope, err := previous.Encrypt([]byte("previous credential"))
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := newConfiguredDNSCredentialCipher(config.Config{
		DNSCredentialKeyID: "dns-key-v2", DNSCredentialKey: activeMaterial,
		DNSCredentialPreviousKeyID: "dns-key-v1", DNSCredentialPreviousKey: previousMaterial,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cipher.Close()

	activeKeyID, _, err := cipher.Encrypt([]byte("active credential"))
	if err != nil || activeKeyID != "dns-key-v2" {
		t.Fatalf("active Encrypt() = (%q,%v), want dns-key-v2", activeKeyID, err)
	}
	plaintext, err := cipher.Decrypt(previousKeyID, previousEnvelope)
	if err != nil || string(plaintext) != "previous credential" {
		t.Fatalf("previous Decrypt() = (%q,%v)", plaintext, err)
	}
	clear(plaintext)
	if _, err := cipher.Decrypt("dns-key-unknown", previousEnvelope); !errors.Is(err, dnsacme.ErrCredentialUnavailable) {
		t.Fatalf("unknown key error = %v, want fail closed", err)
	}
}

func TestNewConfiguredDNSCredentialCipherRejectsDuplicateKeyID(t *testing.T) {
	_, err := newConfiguredDNSCredentialCipher(config.Config{
		DNSCredentialKeyID: "dns-key-v2", DNSCredentialKey: bytes.Repeat([]byte{0x41}, 32),
		DNSCredentialPreviousKeyID: "dns-key-v2", DNSCredentialPreviousKey: bytes.Repeat([]byte{0x31}, 32),
	})
	if !errors.Is(err, dnsacme.ErrCredentialUnavailable) {
		t.Fatalf("duplicate key error = %v, want fail closed", err)
	}
}

func TestNewConfiguredDNSCredentialCipherClearsTemporaryMaterial(t *testing.T) {
	source, err := os.ReadFile("dns_credential_keyring.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("append([]byte(nil), cfg.DNSCredentialKey...)"),
		[]byte("append([]byte(nil), cfg.DNSCredentialPreviousKey...)"),
		[]byte("clear(active.Material)"),
		[]byte("clear(previous[index].Material)"),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("credential keyring helper lacks material lifecycle %q", required)
		}
	}
}
