package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/nats-io/nats.go"
)

func TestAnalyticsConnectionsWriterUsesIngestIdentity(t *testing.T) {
	t.Setenv("ANALYTICS_CONNECTIONS_NATS_URL", "nats://127.0.0.1:4222")
	t.Setenv("ANALYTICS_CONNECTIONS_OPERATION_TIMEOUT", "1234ms")
	var reads, writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "ingest-user" || password != "ingest-test-only" || r.URL.Query().Get("database") != "ingest_database" {
			http.Error(w, "wrong writer identity", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case strings.HasPrefix(string(body), "SELECT ") && strings.Contains(string(body), "FROM connections_ingest_receipts_v1 FINAL"):
			reads.Add(1)
		case strings.HasPrefix(string(body), "INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow\n"):
			writes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	cfg := config.Config{
		ClickHouseURL: "http://127.0.0.1:1", ClickHouseDatabase: "query_database",
		ClickHouseUsername: "query-user", ClickHousePassword: "query-test-only",
		AnalyticsIngest: config.AnalyticsIngestConfig{
			Enabled: true, ClickHouseURL: server.URL, ClickHouseDatabase: "ingest_database",
			ClickHouseUsername: "ingest-user", ClickHousePassword: "ingest-test-only",
		},
	}
	runtimeConfig := analyticsConnectionsRuntimeConfig(cfg)
	if runtimeConfig.Endpoint != cfg.AnalyticsIngest.ClickHouseURL || runtimeConfig.Database != cfg.AnalyticsIngest.ClickHouseDatabase ||
		runtimeConfig.Username != cfg.AnalyticsIngest.ClickHouseUsername || runtimeConfig.Password != cfg.AnalyticsIngest.ClickHousePassword {
		t.Fatal("connections writer did not bind the independent ingest identity")
	}
	// DLQ also reads this helper, but consumes only OperationTimeout. It must
	// remain independent of the presence or identity of a ClickHouse writer.
	if runtimeConfig.OperationTimeout != 1234*time.Millisecond || analyticsConnectionsRuntimeConfig(config.Config{}).OperationTimeout != runtimeConfig.OperationTimeout {
		t.Fatal("connections DLQ operation timeout changed with writer configuration")
	}
	writer, err := analyticsconnections.NewClickHouseWriter(analyticsconnections.ClickHouseConfig{
		Endpoint: runtimeConfig.Endpoint, Database: runtimeConfig.Database,
		Username: runtimeConfig.Username, Password: runtimeConfig.Password,
		ConnectTimeout: runtimeConfig.ConnectTimeout, OperationTimeout: runtimeConfig.OperationTimeout,
		MaxResponseBytes: runtimeConfig.MaxResponseBytes,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	receipt := analyticsconnections.Receipt{
		SchemaVersion: 1, ReceiptID: "fixture-receipt", BatchID: "fixture-batch", EventID: "fixture-event",
		TenantID: "11111111-1111-1111-1111-111111111111", InstallationID: "fixture-installation",
		SiteID: "22222222-2222-2222-2222-222222222222", NodeID: "33333333-3333-3333-3333-333333333333",
		PackageSubscriptionID: "44444444-4444-4444-4444-444444444444", Domain: "fixture.example.test", ListenPort: 443,
		OccurredAt: now, Connections: 1, SourceWatermark: 1, FinalizedThrough: now.Add(time.Minute),
		Stream: "CONNECTIONS_INGEST_V1", Durable: "control_api_connections", StreamSequence: 1, ConsumerSequence: 1,
		PubAck:        analyticsconnections.PubAck{Stream: "CONNECTIONS_INGEST_V1", Sequence: 1},
		PayloadSHA256: sha256.Sum256([]byte("fixture-payload")), CanonicalEventSHA256: sha256.Sum256([]byte("fixture-event")),
		EvidenceSHA256: sha256.Sum256([]byte("fixture-evidence")), State: analyticsconnections.StateReceived,
	}
	receipt.ClickHouseToken = analyticsconnections.ClickHouseInsertToken(receipt)
	if err := writer.Prepare(context.Background(), receipt); err != nil {
		t.Fatalf("writer prepare with ingest identity: %v", err)
	}
	if reads.Load() != 1 || writes.Load() != 1 {
		t.Fatalf("writer HTTP operations: reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestOpenAnalyticsConnectionsRequiresIngestWriter(t *testing.T) {
	t.Setenv("ANALYTICS_CONNECTIONS_RUNTIME_ENABLED", "true")
	t.Setenv("ANALYTICS_CONNECTIONS_NATS_URL", "nats://127.0.0.1:4222")
	base := config.Config{
		ClickHouseURL: "http://127.0.0.1:8123", ClickHouseDatabase: "query_database",
		ClickHouseUsername: "query-user", ClickHousePassword: "query-test-only",
		AnalyticsIngest: config.AnalyticsIngestConfig{
			Enabled: true, ClickHouseURL: "http://127.0.0.1:8123", ClickHouseDatabase: "ingest_database",
			ClickHouseUsername: "ingest-user", ClickHousePassword: "ingest-test-only",
		},
	}
	for _, item := range []struct {
		name   string
		change func(*config.AnalyticsIngestConfig)
	}{
		{"disabled", func(c *config.AnalyticsIngestConfig) { c.Enabled = false }},
		{"missing endpoint", func(c *config.AnalyticsIngestConfig) { c.ClickHouseURL = "" }},
		{"missing database", func(c *config.AnalyticsIngestConfig) { c.ClickHouseDatabase = "" }},
		{"missing username", func(c *config.AnalyticsIngestConfig) { c.ClickHouseUsername = "" }},
		{"missing password", func(c *config.AnalyticsIngestConfig) { c.ClickHousePassword = "" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			cfg := base
			item.change(&cfg.AnalyticsIngest)
			connected := false
			runtime, err := openAnalyticsConnectionsRuntime(context.Background(), cfg, func(string, ...nats.Option) (*nats.Conn, error) {
				connected = true
				return nil, errors.New("connector must not be reached")
			})
			if err == nil || runtime != nil || connected {
				t.Fatalf("incomplete ingest writer reached runtime: err=%v connected=%t", err, connected)
			}
			if strings.Contains(err.Error(), "query-test-only") || strings.Contains(err.Error(), "ingest-test-only") {
				t.Fatal("writer rejection exposed credentials")
			}
		})
	}
	connected := false
	connectionFailure := errors.New("fixture connection boundary")
	runtime, err := openAnalyticsConnectionsRuntime(context.Background(), base, func(string, ...nats.Option) (*nats.Conn, error) {
		connected = true
		return nil, connectionFailure
	})
	if !errors.Is(err, connectionFailure) || runtime != nil || !connected {
		t.Fatal("complete ingest writer did not reach the connector boundary")
	}
	t.Setenv("ANALYTICS_CONNECTIONS_RUNTIME_ENABLED", "false")
	runtime, err = openAnalyticsConnectionsRuntime(nil, config.Config{}, nil)
	if err != nil || runtime != nil {
		t.Fatal("disabled connections runtime acquired dependencies")
	}
}
