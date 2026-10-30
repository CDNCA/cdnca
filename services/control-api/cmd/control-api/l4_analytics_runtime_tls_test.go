package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/nats-io/nats.go"
)

func TestL4AnalyticsNATSOptionsBindTLSAndRuntimeCredentials(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsServer.Close)
	caFile := filepath.Join(t.TempDir(), "root-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", caFile)
	cfg := config.Config{AnalyticsIngest: config.AnalyticsIngestConfig{
		NATSURL: "tls://analytics-nats.internal:4222", NATSUsername: "runtime", NATSPassword: "protected",
		ConnectTimeout: time.Second, SupervisorBackoffMin: time.Second,
	}}
	settings := nats.GetDefaultOptions()
	for _, option := range l4AnalyticsNATSOptions(cfg, 2*time.Second) {
		if err := option(&settings); err != nil {
			t.Fatal(err)
		}
	}
	if !settings.TLSHandshakeFirst || settings.TLSConfig == nil || settings.RootCAsCB == nil ||
		settings.User != "runtime" || settings.Password != "protected" {
		t.Fatalf("L4 TLS NATS options are not fully bound: %+v", settings)
	}

	cfg.AnalyticsIngest.NATSURL = "nats://127.0.0.1:4222"
	settings = nats.GetDefaultOptions()
	for _, option := range l4AnalyticsNATSOptions(cfg, 2*time.Second) {
		if err := option(&settings); err != nil {
			t.Fatal(err)
		}
	}
	if settings.TLSHandshakeFirst || settings.TLSConfig != nil || settings.RootCAsCB != nil {
		t.Fatal("loopback plaintext L4 NATS unexpectedly enables TLS")
	}
}
