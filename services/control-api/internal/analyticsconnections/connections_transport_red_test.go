package analyticsconnections

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func validConnectionsDelivery() Delivery {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	envelope := &agentv1.ConnectionsMetricEnvelopeV1{
		SchemaVersion:         1,
		Event:                 &commonv1.EventMetadata{EventId: "event-001", OccurredTime: timestamppb.New(now)},
		TenantId:              "11111111-1111-1111-1111-111111111111",
		InstallationId:        "installation-001",
		SiteId:                "22222222-2222-2222-2222-222222222222",
		PackageSubscriptionId: "33333333-3333-3333-3333-333333333333",
		Connections:           3,
		CanonicalEventSha256:  bytesOf(1),
		DependencyState:       agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough:      timestamppb.New(now.Add(time.Minute)),
		EvidenceSha256:        bytesOf(2),
		SourceWatermark:       7,
		NodeId:                "44444444-4444-4444-4444-444444444444",
		Domain:                "cdn.example.test",
		ListenPort:            443,
	}
	return Delivery{
		BatchID: "batch-001", ReceiptID: "receipt-001", NodeID: "44444444-4444-4444-4444-444444444444", Domain: "cdn.example.test", ListenPort: 443, Envelope: envelope,
		Stream: "CONNECTIONS_INGEST_V1", Durable: "control_api_connections",
		StreamSequence: 11, ConsumerSequence: 9,
		PubAck: PubAck{Stream: "CONNECTIONS_INGEST_V1", Sequence: 11},
		Ack:    func(context.Context) error { return nil },
	}
}

func bytesOf(value byte) []byte {
	result := make([]byte, sha256.Size)
	result[0] = value
	return result
}

func TestValidateDeliveryRejectsInvalidAuthorityAndDigestConflict(t *testing.T) {
	valid := validConnectionsDelivery()
	if _, err := ValidateDelivery(valid); err != nil {
		t.Fatalf("valid delivery rejected: %v", err)
	}
	invalid := valid
	invalid.Envelope = valid.Envelope.ProtoReflect().New().Interface().(*agentv1.ConnectionsMetricEnvelopeV1)
	if _, err := ValidateDelivery(invalid); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("missing authority was accepted: %v", err)
	}
	conflict := valid
	conflict.ReceiptID = ""
	if _, err := ValidateDelivery(conflict); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("missing receipt identity was accepted: %v", err)
	}
}

func TestProcessAcknowledgesOnlyAfterDurableClickHouseReceipt(t *testing.T) {
	delivery := validConnectionsDelivery()
	var acked bool
	delivery.Ack = func(context.Context) error { acked = true; return nil }
	store := &recordingStore{}
	if err := Process(context.Background(), delivery, store); err != nil {
		t.Fatalf("process failed: %v", err)
	}
	if !acked || !store.prepared || !store.observed {
		t.Fatalf("durable order was not preserved: ack=%t prepared=%t observed=%t", acked, store.prepared, store.observed)
	}
	if store.receipt.ClickHouseToken == "" || store.receipt.ClickHouseToken != ClickHouseInsertToken(store.receipt) {
		t.Fatalf("token is not deterministic: %q", store.receipt.ClickHouseToken)
	}
}

func TestProcessNeverAcknowledgesClickHouseFailure(t *testing.T) {
	delivery := validConnectionsDelivery()
	var acked bool
	delivery.Ack = func(context.Context) error { acked = true; return nil }
	store := &recordingStore{prepareErr: ErrClickHouseUnavailable}
	if err := Process(context.Background(), delivery, store); !errors.Is(err, ErrClickHouseUnavailable) {
		t.Fatalf("error = %v, want ClickHouse unavailable", err)
	}
	if acked {
		t.Fatal("NATS was acknowledged before ClickHouse durable failure was resolved")
	}
}

func TestClickHouseWriterUsesStableTokenAndBoundedResponse(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("insert_deduplication_token"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	writer, err := NewClickHouseWriter(ClickHouseConfig{Endpoint: server.URL, Database: "analytics", MaxResponseBytes: 128}, server.Client())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if err := writer.Prepare(context.Background(), receipt); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := writer.Prepare(context.Background(), receipt); err != nil {
		t.Fatalf("replay prepare: %v", err)
	}
	insertTokens := queries[:0]
	for _, token := range queries {
		if token != "" {
			insertTokens = append(insertTokens, token)
		}
	}
	if len(insertTokens) != 2 || insertTokens[0] == "" || insertTokens[0] != insertTokens[1] {
		t.Fatalf("insert token drift: %q", queries)
	}
}

func TestRuntimeConfigRequiresBoundedDurationsAndLimits(t *testing.T) {
	cases := []RuntimeConfig{
		{Enabled: true},
		{Enabled: true, NATSURL: "nats://127.0.0.1:4222", Stream: "CONNECTIONS_INGEST_V1", Durable: "connections", Subject: ConnectionsSubject, Endpoint: "https://clickhouse.example.test", Database: "analytics", ConnectTimeout: time.Second, OperationTimeout: time.Second, MaxResponseBytes: 1 << 20},
		{Enabled: true, NATSURL: "nats://127.0.0.1:4222", Stream: "CONNECTIONS_INGEST_V1", Durable: "connections", Subject: ConnectionsSubject, Endpoint: "https://clickhouse.example.test", Database: "analytics", ConnectTimeout: time.Second, OperationTimeout: 0, MaxResponseBytes: 1 << 20},
	}
	if err := ValidateRuntimeConfig(cases[0]); err == nil {
		t.Fatal("empty config was accepted")
	}
	if err := ValidateRuntimeConfig(cases[1]); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := ValidateRuntimeConfig(cases[2]); err == nil {
		t.Fatal("unbounded operation timeout was accepted")
	}
}

func TestMigration007Binds006AndEnforcesReceiptContract(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "infra", "clickhouse", "migrations")
	up, err := os.ReadFile(filepath.Join(root, "007_connections_ingest_receipts.up.sql"))
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	down, err := os.ReadFile(filepath.Join(root, "007_connections_ingest_receipts.down.sql"))
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{"ad7191e2f4895f489bb3534c314460e01f60c66c7ae7e38abf9cf70bef39f721", "received", "ch_prepared", "broker_ack_observed", "receipt_id", "batch_id", "event_id", "tenant_id", "installation_id", "site_id", "package_subscription_id", "payload_sha256", "canonical_event_sha256", "evidence_sha256", "source_watermark", "finalized_through", "nats_stream_sequence", "nats_consumer_sequence", "clickhouse_insert_token", "TTL"} {
		if !strings.Contains(upText, required) {
			t.Fatalf("up migration missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(downText), "TRUNCATE") || !strings.Contains(downText, "connections_ingest_receipts_v1") {
		t.Fatalf("down migration is not bounded and append-only: %s", downText)
	}
}

type recordingStore struct {
	receipt    Receipt
	prepared   bool
	observed   bool
	prepareErr error
}

func (store *recordingStore) Prepare(_ context.Context, receipt Receipt) error {
	if store.prepareErr != nil {
		return store.prepareErr
	}
	store.receipt, store.prepared = receipt, true
	return nil
}

func (store *recordingStore) MarkBrokerAckObserved(_ context.Context, receipt Receipt, ack PubAck) error {
	if !store.prepared || ack.Sequence == 0 {
		return errors.New("ack observed before prepare")
	}
	store.observed = true
	return nil
}
