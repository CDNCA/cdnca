package main

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/nats-io/nats.go"
)

func TestAnalyticsConnectionsRuntimeConfigUsesExactTwoTokenSubject(t *testing.T) {
	t.Setenv("ANALYTICS_CONNECTIONS_NATS_URL", "nats://127.0.0.1:4222")
	t.Setenv("ANALYTICS_CONNECTIONS_SUBJECT", "")
	runtimeConfig := analyticsConnectionsRuntimeConfig(config.Config{
		AnalyticsIngest: config.AnalyticsIngestConfig{Enabled: true, ClickHouseURL: "https://clickhouse.example.test", ClickHouseDatabase: "analytics"},
	})
	if runtimeConfig.Subject != analyticsconnections.ConnectionsSubjectPrefix+".*.*" {
		t.Fatalf("default subject = %q", runtimeConfig.Subject)
	}
	if err := analyticsconnections.ValidateRuntimeConfig(runtimeConfig); err != nil {
		t.Fatalf("default config: %v", err)
	}

	t.Setenv("ANALYTICS_CONNECTIONS_SUBJECT", analyticsconnections.ConnectionsSubjectPrefix+".*")
	runtimeConfig = analyticsConnectionsRuntimeConfig(config.Config{
		AnalyticsIngest: config.AnalyticsIngestConfig{Enabled: true, ClickHouseURL: "https://clickhouse.example.test", ClickHouseDatabase: "analytics"},
	})
	if err := analyticsconnections.ValidateRuntimeConfig(runtimeConfig); !errors.Is(err, analyticsconnections.ErrInvalidConfiguration) {
		t.Fatalf("one-token subject override error = %v", err)
	}
}

func TestAnalyticsConnectionsNATSOptionsBindTLSAndCredentials(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsServer.Close)
	caFile := filepath.Join(t.TempDir(), "root-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", caFile)
	t.Setenv("ANALYTICS_CONNECTIONS_NATS_USER", "connections-runtime")
	t.Setenv("ANALYTICS_CONNECTIONS_NATS_PASSWORD", "connections-password")
	config := analyticsconnections.RuntimeConfig{
		NATSURL: "tls://analytics-nats.internal:4222", ConnectTimeout: time.Second,
		OperationTimeout: 2 * time.Second,
	}
	options, err := analyticsConnectionsNATSOptions(config)
	if err != nil {
		t.Fatal(err)
	}
	settings := nats.GetDefaultOptions()
	for _, option := range options {
		if err := option(&settings); err != nil {
			t.Fatal(err)
		}
	}
	if !settings.TLSHandshakeFirst || settings.User != "connections-runtime" ||
		settings.Password != "connections-password" || settings.TLSConfig == nil || settings.RootCAsCB == nil {
		t.Fatalf("TLS NATS options are not fully bound: %+v", settings)
	}

	config.NATSURL = "nats://127.0.0.1:4222"
	options, err = analyticsConnectionsNATSOptions(config)
	if err != nil {
		t.Fatal(err)
	}
	settings = nats.GetDefaultOptions()
	for _, option := range options {
		if err := option(&settings); err != nil {
			t.Fatal(err)
		}
	}
	if settings.TLSHandshakeFirst || settings.TLSConfig != nil || settings.RootCAsCB != nil {
		t.Fatal("loopback plaintext NATS unexpectedly enables TLS")
	}

	t.Setenv("ANALYTICS_CONNECTIONS_NATS_PASSWORD", "secret-do-not-log")
	t.Setenv("ANALYTICS_CONNECTIONS_NATS_USER", "")
	_, err = analyticsConnectionsNATSOptions(config)
	if err == nil || strings.Contains(err.Error(), "secret-do-not-log") {
		t.Fatalf("unpaired credential error = %v", err)
	}
}
