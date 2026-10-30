package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBuildEdgeSignerTrustRuntimeConfiguration(t *testing.T) {
	pool, err := pgxpool.New(t.Context(), "postgres://unused@127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	clearRoot := func() {
		for _, name := range []string{"OFFLINE_ROOT_KEY_ID", "OFFLINE_ROOT_GENERATION", "OFFLINE_ROOT_PUBLIC_KEY_BASE64"} {
			t.Setenv("SIGNER_REVOCATION_CONSUMER_"+name, "")
		}
	}
	setRoot := func() {
		t.Setenv("SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_KEY_ID", "cdnca-offline-root")
		t.Setenv("SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_GENERATION", "1")
		t.Setenv("SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_PUBLIC_KEY_BASE64", base64.RawURLEncoding.EncodeToString(
			ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)))
	}
	t.Setenv(edgeSignerTrustURLEnv, "")
	t.Setenv(edgeSignerTrustIntervalEnv, "")
	t.Setenv(edgeSignerTrustDownloads, "")

	clearRoot()
	t.Setenv(edgeSignerTrustEnabledEnv, "")
	if runtime, err := buildEdgeSignerTrustRuntime(pool, "https://auth.example.com", nil, nil); runtime != nil || err != nil {
		t.Fatalf("no pin = %v, %v", runtime, err)
	}
	t.Setenv(edgeSignerTrustEnabledEnv, "true")
	if _, err := buildEdgeSignerTrustRuntime(pool, "https://auth.example.com", nil, nil); err == nil {
		t.Fatal("enabled without a pin accepted")
	}
	t.Setenv(edgeSignerTrustEnabledEnv, "yes")
	if _, err := buildEdgeSignerTrustRuntime(pool, "https://auth.example.com", nil, nil); err == nil {
		t.Fatal("invalid flag accepted")
	}

	setRoot()
	t.Setenv(edgeSignerTrustEnabledEnv, "")
	if runtime, err := buildEdgeSignerTrustRuntime(pool, "https://auth.example.com", nil, nil); runtime == nil || err != nil {
		t.Fatalf("pin configured = %v, %v", runtime, err)
	} else if runtime.distributor != nil || len(runtime.workers()) != 1 {
		t.Fatal("distributor started without the edge publication signer and edge NATS")
	}
	t.Setenv(edgeSignerTrustEnabledEnv, "false")
	if runtime, err := buildEdgeSignerTrustRuntime(pool, "https://auth.example.com", nil, nil); runtime != nil || err != nil {
		t.Fatalf("explicitly off = %v, %v", runtime, err)
	}
	t.Setenv(edgeSignerTrustEnabledEnv, "")
	if _, err := buildEdgeSignerTrustRuntime(pool, "http://auth.example.com", nil, nil); err == nil ||
		!strings.Contains(err.Error(), "https") {
		t.Fatalf("plain licensing origin error = %v", err)
	}
	t.Setenv(edgeSignerTrustDownloads, "relative/dir")
	if _, err := buildEdgeSignerTrustRuntime(pool, "https://auth.example.com", nil, nil); err == nil {
		t.Fatal("relative downloads directory accepted")
	}
	t.Setenv(edgeSignerTrustDownloads, "")
	t.Setenv(edgeSignerTrustIntervalEnv, "10s")
	if _, err := buildEdgeSignerTrustRuntime(pool, "https://auth.example.com", nil, nil); err == nil {
		t.Fatal("interval below 1m accepted")
	}
}
