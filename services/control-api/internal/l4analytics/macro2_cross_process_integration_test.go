package l4analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	gateway "github.com/cdnca/cdnca/services/agent-gateway"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var macro2Identifier = regexp.MustCompile(`^[a-z0-9_]+$`)

type macro2L4RuntimeConfig struct {
	Identifier         string
	RuntimeNATSURL     string
	PublisherNATSURL   string
	ClickHouseURL      string
	ClickHouseUsername string
	ClickHousePassword string
	Stream             string
	Durable            string
	OperationTimeout   time.Duration
}

func macro2L4RuntimeConfigFromEnv(getenv func(string) string) (macro2L4RuntimeConfig, error) {
	if getenv == nil {
		return macro2L4RuntimeConfig{}, errors.New("macro2 integration environment is incomplete")
	}
	prefix := strings.TrimSpace(getenv("CDNCA_MACRO2_PREFIX"))
	config := macro2L4RuntimeConfig{
		RuntimeNATSURL:     strings.TrimSpace(getenv("CDNCA_TEST_NATS_URL")),
		PublisherNATSURL:   strings.TrimSpace(getenv("CDNCA_TEST_NATS_PUBLISHER_URL")),
		ClickHouseURL:      strings.TrimSpace(getenv("TEST_CLICKHOUSE_URL")),
		ClickHouseUsername: strings.TrimSpace(getenv("TEST_CLICKHOUSE_USERNAME")),
		ClickHousePassword: getenv("TEST_CLICKHOUSE_PASSWORD"),
		Stream:             strings.TrimSpace(getenv("CDNCA_MACRO2_L4_STREAM")),
		Durable:            strings.TrimSpace(getenv("CDNCA_MACRO2_L4_DURABLE")),
		OperationTimeout:   5 * time.Second,
	}
	if prefix == "" || config.RuntimeNATSURL == "" || config.PublisherNATSURL == "" || config.ClickHouseURL == "" ||
		config.ClickHouseUsername == "" || config.ClickHousePassword == "" || config.Stream == "" || config.Durable == "" {
		return macro2L4RuntimeConfig{}, errors.New("macro2 integration environment is incomplete")
	}
	if config.Stream != L4IngestStream || config.Durable != L4IngestDurable {
		return macro2L4RuntimeConfig{}, errors.New("macro2 L4 resources must use the preprovisioned production names")
	}
	config.Identifier = strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(prefix))
	if !macro2Identifier.MatchString(config.Identifier) {
		return macro2L4RuntimeConfig{}, errors.New("macro2 prefix is not a safe identifier")
	}
	return config, nil
}

func TestMacro2L4GatewayNATSClickHouseTenantReplayAndTTL(t *testing.T) {
	if os.Getenv("CDNCA_MACRO2_L4_INTEGRATION") != "1" {
		t.Skip("set CDNCA_MACRO2_L4_INTEGRATION=1")
	}
	runtimeConfig, err := macro2L4RuntimeConfigFromEnv(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	identifier := runtimeConfig.Identifier
	database := "task_" + identifier + "_l4"
	client := &http.Client{Timeout: 10 * time.Second}
	clickHouseURL := runtimeConfig.ClickHouseURL
	clickHouseUsername := runtimeConfig.ClickHouseUsername
	clickHousePassword := runtimeConfig.ClickHousePassword
	macro2ClickHouseExec(t, client, clickHouseURL, "", "DROP DATABASE IF EXISTS "+database+" SYNC")
	macro2ClickHouseExec(t, client, clickHouseURL, "", "CREATE DATABASE "+database)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		macro2ClickHouseExecContext(t, cleanupCtx, client, clickHouseURL, "", "DROP DATABASE IF EXISTS "+database+" SYNC")
	})
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate L4 integration test")
	}
	migration, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "..", "infra", "clickhouse", "migrations", "011_l4_session_facts.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	macro2ClickHouseExec(t, client, clickHouseURL, database, string(migration))

	runtimeConnection, err := nats.Connect(runtimeConfig.RuntimeNATSURL, nats.Name("cdnca-macro2-l4-runtime"), nats.Timeout(5*time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtimeConnection.Close)
	config := NATSIngestConfig{
		Stream: runtimeConfig.Stream, Subject: L4IngestSubject,
		Durable: runtimeConfig.Durable, OperationTimeout: runtimeConfig.OperationTimeout,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := EnsureL4JetStream(ctx, runtimeConnection, config); err != nil {
		t.Fatal(err)
	}
	source, err := NewClickHouseSource(ClickHouseConfig{
		Endpoint: clickHouseURL, Database: database, QueryTimeout: 5 * time.Second,
		Username: clickHouseUsername, Password: clickHousePassword,
		MaxResponseBytes: 1 << 20, HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewClickHouseFactWriter(source)
	if err != nil {
		t.Fatal(err)
	}
	ingestor, err := NewNATSIngestor(runtimeConnection, writer, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ingestor.Close() })
	runCtx, stop := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	go func() { runErr <- ingestor.Run(runCtx) }()

	now := time.Now().UTC().Truncate(time.Millisecond)
	tenantID := "10000000-0000-4000-8000-000000000201"
	otherTenantID := "10000000-0000-4000-8000-000000000202"
	siteID := "20000000-0000-4000-8000-000000000201"
	nodeID := "30000000-0000-4000-8000-000000000201"
	configID := "40000000-0000-4000-8000-000000000201"
	streamID := "50000000-0000-4000-8000-000000000201"
	listenerID := "60000000-0000-4000-8000-000000000201"
	currentEventID := "macro2-l4-current"
	expiredEventID := "macro2-l4-expired"
	envelope := &agentv1.L4SessionEnvelopeV1{
		SchemaVersion: 1, ProducedAt: timestamppb.New(now), TenantId: tenantID, NodeId: nodeID,
		SiteId: siteID, ConfigVersionId: configID, SourceWatermark: 2,
		FinalizedThrough: timestamppb.New(now.Add(-time.Minute)), EvidenceSha256: bytes.Repeat([]byte{3}, sha256.Size),
		Events: []*agentv1.L4SessionEventV1{
			macro2L4Event(expiredEventID, tenantID, nodeID, siteID, streamID, listenerID, configID, now.Add(-31*24*time.Hour), 1),
			macro2L4Event(currentEventID, tenantID, nodeID, siteID, streamID, listenerID, configID, now.Add(-time.Minute), 2),
		},
	}
	envelope.MessageId = macro2L4MessageID(t, envelope)
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	publisherConfig := gateway.DefaultNATSTelemetryPublisherConfig()
	publisherConfig.L4Stream = config.Stream
	publisherConfig.OperationTimeout = 3 * time.Second
	publisherConnection, err := nats.Connect(runtimeConfig.PublisherNATSURL, nats.Name("cdnca-macro2-l4-publisher"), nats.Timeout(5*time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisherConnection.Close)
	publisher, err := gateway.NewNATSTelemetryPublisher(publisherConnection, publisherConfig)
	if err != nil {
		t.Fatal(err)
	}
	publication := gateway.TelemetryPublication{
		Kind:   agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1,
		NodeID: nodeID, TenantID: tenantID, SiteID: siteID, ConfigVersionID: configID,
		InstallationID: "macro2-installation", MessageID: envelope.MessageId, Payload: payload,
	}
	first, err := publisher.Publish(ctx, publication)
	if err != nil || first.Stream != config.Stream || first.Sequence == 0 || first.Duplicate {
		t.Fatalf("first L4 publish=%+v err=%v", first, err)
	}
	duplicate, err := publisher.Publish(ctx, publication)
	if err != nil || !duplicate.Duplicate || duplicate.Stream != first.Stream || duplicate.Sequence != first.Sequence {
		t.Fatalf("duplicate L4 publish=%+v first=%+v err=%v", duplicate, first, err)
	}
	macro2Eventually(t, 45*time.Second, func() bool {
		select {
		case err := <-runErr:
			t.Fatalf("L4 ingestor stopped before receipt: %v", err)
		default:
		}
		return macro2ClickHouseCount(t, client, clickHouseURL, database,
			"SELECT count() FROM l4_session_facts_v1 WHERE tenant_id=toUUID('"+tenantID+"') AND event_id='"+currentEventID+"'") == 1
	})
	filter := Filter{From: now.Add(-time.Hour), To: now.Add(time.Minute), Timezone: "UTC", Limit: 10}
	page, err := source.Read(ctx, Scope{TenantID: tenantID}, filter)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Sessions != 1 || page.Rows[0].BytesUp != 300 || page.Rows[0].BytesDown != 1200 || page.Rows[0].ListenPort != 18080 {
		t.Fatalf("tenant L4 page=%+v err=%v", page, err)
	}
	// A tenant without L4 facts reads an empty page (204b90190), never the other tenant's rows.
	if other, otherErr := source.Read(ctx, Scope{TenantID: otherTenantID}, filter); otherErr != nil || len(other.Rows) != 0 {
		t.Fatalf("cross-tenant L4 read=%+v err=%v", other, otherErr)
	}
	macro2ClickHouseExec(t, client, clickHouseURL, database, "OPTIMIZE TABLE l4_session_facts_v1 FINAL")
	macro2Eventually(t, 20*time.Second, func() bool {
		return macro2ClickHouseCount(t, client, clickHouseURL, database,
			"SELECT count() FROM l4_session_facts_v1 WHERE event_id='"+expiredEventID+"'") == 0
	})
	if got := macro2ClickHouseCount(t, client, clickHouseURL, database,
		"SELECT count() FROM l4_session_facts_v1 WHERE event_id='"+currentEventID+"'"); got != 1 {
		t.Fatalf("current L4 fact count=%d want=1", got)
	}
	stop()
	if err := <-runErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func macro2L4Event(eventID, tenantID, nodeID, siteID, streamID, listenerID, configID string, finalized time.Time, watermark uint64) *agentv1.L4SessionEventV1 {
	taskID := "macro2-task"
	return &agentv1.L4SessionEventV1{
		Event: &commonv1.EventMetadata{EventId: eventID, OccurredTime: timestamppb.New(finalized),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", TaskId: &taskID},
		TenantId: tenantID, NodeId: nodeID, SiteId: siteID, StreamId: streamID, ListenerId: listenerID,
		ConfigVersionId: configID, ConfigRevision: 7, Protocol: "tcp", ListenPort: 18080,
		SessionId: strconv.FormatUint(watermark, 10), StartedAt: timestamppb.New(finalized.Add(-time.Second)),
		FinalizedAt: timestamppb.New(finalized), BytesUp: 300, BytesDown: 1200, StatusCode: 200,
		EvidenceSha256: bytes.Repeat([]byte{2}, sha256.Size), CanonicalEventSha256: bytes.Repeat([]byte{1}, sha256.Size),
	}
}

func macro2L4MessageID(t *testing.T, envelope *agentv1.L4SessionEnvelopeV1) string {
	t.Helper()
	clone := proto.Clone(envelope).(*agentv1.L4SessionEnvelopeV1)
	clone.MessageId = ""
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte("cdnca.l4.session.publication.v1\x00"), payload...))
	return "l4msg_" + hex.EncodeToString(digest[:])
}

func macro2ClickHouseExec(t *testing.T, client *http.Client, endpoint, database, query string) []byte {
	t.Helper()
	return macro2ClickHouseExecContext(t, t.Context(), client, endpoint, database, query)
}

func macro2ClickHouseExecContext(t *testing.T, ctx context.Context, client *http.Client, endpoint, database, query string) []byte {
	t.Helper()
	target, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	values := target.Query()
	if database != "" {
		values.Set("database", database)
	}
	target.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(query))
	if err != nil {
		t.Fatal(err)
	}
	if username := strings.TrimSpace(os.Getenv("TEST_CLICKHOUSE_USERNAME")); username != "" {
		request.SetBasicAuth(username, os.Getenv("TEST_CLICKHOUSE_PASSWORD"))
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("ClickHouse status=%d", response.StatusCode)
	}
	return body
}

func macro2ClickHouseCount(t *testing.T, client *http.Client, endpoint, database, query string) uint64 {
	t.Helper()
	body := macro2ClickHouseExec(t, client, endpoint, database, query+" FORMAT TSVRaw")
	value, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		t.Fatal(fmt.Errorf("parse ClickHouse count: %w", err))
	}
	return value
}

func macro2Eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for macro2 dependency state")
}

func TestMacro2L4RuntimeConfigRequiresFixedPreprovisionedResources(t *testing.T) {
	base := map[string]string{
		"CDNCA_MACRO2_PREFIX":           "l402_isolated",
		"CDNCA_TEST_NATS_URL":           "nats://runtime.invalid:4222",
		"CDNCA_TEST_NATS_PUBLISHER_URL": "nats://publisher.invalid:4222",
		"TEST_CLICKHOUSE_URL":           "http://clickhouse.invalid:8123",
		"TEST_CLICKHOUSE_USERNAME":      "macro2",
		"TEST_CLICKHOUSE_PASSWORD":      "macro2-secret",
		"CDNCA_MACRO2_L4_STREAM":        L4IngestStream,
		"CDNCA_MACRO2_L4_DURABLE":       L4IngestDurable,
	}
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	config, err := macro2L4RuntimeConfigFromEnv(getenv(base))
	if err != nil || config.Identifier != "l402_isolated" || config.Stream != L4IngestStream || config.Durable != L4IngestDurable || config.OperationTimeout != 5*time.Second {
		t.Fatalf("fixed runtime config=%+v err=%v", config, err)
	}
	for name, value := range map[string]string{
		"CDNCA_MACRO2_L4_STREAM":  "L402_ISOLATED_L4",
		"CDNCA_MACRO2_L4_DURABLE": "l402_isolated_l4",
	} {
		values := make(map[string]string, len(base))
		for key, baseValue := range base {
			values[key] = baseValue
		}
		values[name] = value
		if _, err := macro2L4RuntimeConfigFromEnv(getenv(values)); err == nil {
			t.Fatalf("dynamic resource %s was accepted", name)
		}
	}
	for name := range map[string]struct{}{
		"TEST_CLICKHOUSE_USERNAME": {},
		"TEST_CLICKHOUSE_PASSWORD": {},
	} {
		values := make(map[string]string, len(base))
		for key, baseValue := range base {
			values[key] = baseValue
		}
		delete(values, name)
		if _, err := macro2L4RuntimeConfigFromEnv(getenv(values)); err == nil {
			t.Fatalf("missing ClickHouse credential %s was accepted", name)
		}
	}
}
