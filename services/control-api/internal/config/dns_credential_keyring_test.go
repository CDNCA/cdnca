package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadDNSCredentialPreviousKey(t *testing.T) {
	setRequiredConfig(t)
	previous := bytes.Repeat([]byte{0x31}, 32)
	t.Setenv("DNS_CREDENTIAL_KEY_ID", "dns-key-v2")
	t.Setenv("DNS_CREDENTIAL_KEY_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32)))
	t.Setenv("DNS_CREDENTIAL_PREVIOUS_KEY_ID", "dns-key-v1")
	t.Setenv("DNS_CREDENTIAL_PREVIOUS_KEY_BASE64", base64.StdEncoding.EncodeToString(previous))

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNSCredentialPreviousKeyID != "dns-key-v1" || !bytes.Equal(cfg.DNSCredentialPreviousKey, previous) {
		t.Fatalf("previous DNS credential key = (%q, %d bytes)",
			cfg.DNSCredentialPreviousKeyID, len(cfg.DNSCredentialPreviousKey))
	}
}

func TestLoadRejectsInvalidDNSCredentialPreviousKey(t *testing.T) {
	canonical := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	for _, test := range []struct {
		name       string
		activeID   string
		previousID string
		previous   string
	}{
		{name: "missing key", activeID: "dns-key-v2", previousID: "dns-key-v1"},
		{name: "missing key ID", activeID: "dns-key-v2", previous: canonical},
		{name: "duplicate active ID", activeID: "dns-key-v2", previousID: "dns-key-v2", previous: canonical},
		{name: "non canonical base64", activeID: "dns-key-v2", previousID: "dns-key-v1", previous: canonical + "\n"},
		{name: "wrong key length", activeID: "dns-key-v2", previousID: "dns-key-v1",
			previous: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 31))},
		{name: "invalid key ID", activeID: "dns-key-v2", previousID: " dns-key-v1 ", previous: canonical},
	} {
		t.Run(test.name, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("DNS_CREDENTIAL_KEY_ID", test.activeID)
			t.Setenv("DNS_CREDENTIAL_PREVIOUS_KEY_ID", test.previousID)
			t.Setenv("DNS_CREDENTIAL_PREVIOUS_KEY_BASE64", test.previous)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "DNS_CREDENTIAL_PREVIOUS_KEY") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}
