package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestACMERuntimeUsesCompleteDNSCredentialKeyring(t *testing.T) {
	source, err := os.ReadFile("acme_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte("dnsacme.NewAESGCMCredentialKeyring(")) {
		t.Fatal("ACME runtime does not construct the configured DNS credential keyring")
	}

	cfg := validACMERuntimeConfig()
	cfg.DNSCredentialPreviousKeyID = cfg.DNSCredentialKeyID
	cfg.DNSCredentialPreviousKey = bytes.Repeat([]byte{0x52}, 32)

	_, err = openConfiguredACMERuntimeComponentsWithProviders(
		t.Context(), cfg, new(pgxpool.Pool), acmeRuntimeProviders{},
	)
	if err == nil || err.Error() != "configure ACME DNS credential cipher" {
		t.Fatalf("duplicate complete keyring startup error = %v", err)
	}
}
